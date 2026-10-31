"""Bounded rclone adapter. Bearer URLs stay in memory and the encrypted Vault."""
import copy
from datetime import datetime, timezone
import json
import os
import re
import selectors
import signal
import subprocess
import time
from urllib.parse import parse_qsl, quote, urlsplit

import vault

MAX_EXPIRES = 604800
MAX_LINK = 8192


def duration(text):
    match = re.fullmatch(r'([1-9][0-9]{0,6})(s|m|h|d|w)?', text or '')
    if not match: raise vault.VaultError('Use a whole-second duration such as 3600s, 6d or 1w')
    seconds = int(match[1]) * {None:1,'s':1,'m':60,'h':3600,'d':86400,'w':604800}[match[2]]
    if not 1 <= seconds <= MAX_EXPIRES: raise vault.VaultError('Temporary links must last 1–604800 seconds (at most 7 days)')
    return seconds


def remote_path(text):
    match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_-]{0,63}):([A-Za-z0-9._/-]{1,4096})', text or '')
    if not match: raise vault.VaultError('Use a named rclone remote:bucket[/prefix], without options, queries or local paths')
    name, path = match.groups();path = path.rstrip('/')
    if not path or any(p in ('', '.', '..') for p in path.split('/')):
        raise vault.VaultError('Unsafe remote path')
    return name, path


def validate_options(source, remote, expires, publish=False, vault_remote=None):
    vault.source_id(source);remote_name, path = remote_path(remote);duration(expires)
    if publish and not vault_remote: raise vault.VaultError('--publish requires an explicit --vault-remote in a publicly readable Vault location')
    if vault_remote:
        public_name, public_path = remote_path(vault_remote)
        if not public_path.endswith('.enc') or '/' not in public_path:
            raise vault.VaultError('--vault-remote must name the complete encrypted Vault object')
        if (public_name, public_path.split('/')[0]) == (remote_name, path.split('/')[0]):
            raise vault.VaultError('Private video bucket and public Vault publication must be separate destinations')


def run_rclone(arguments, timeout=45, stdout_limit=65536, stderr_limit=16384):
    """Drain bounded pipes, never log rclone diagnostics, kill the process group on failure."""
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('RCLONE_RC') or key in ('RCLONE_LOG_FILE','RCLONE_LOG_LEVEL','RCLONE_DUMP','RCLONE_USE_SYSLOG','RCLONE_SYSLOG_FACILITY'):
            env.pop(key, None)
    args = ['rclone', '--log-level', 'ERROR', '--log-file', '', '--rc=false', '--retries', '1', '--low-level-retries', '1',
            '--contimeout', '10s', '--timeout', '30s', *arguments]
    proc = None
    try:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, start_new_session=True)
        chunks, counts = [], {'out':0,'err':0}
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for pipe, label in ((proc.stdout,'out'),(proc.stderr,'err')):
                os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,label)
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0: raise vault.VaultError('rclone timed out; check the configured remote and network')
                for event, _ in selector.select(min(left,0.2)):
                    label=event.data;limit=stdout_limit if label=='out' else stderr_limit
                    data=os.read(event.fileobj.fileno(),min(16384,limit-counts[label]+1))
                    if not data: selector.unregister(event.fileobj);continue
                    counts[label]+=len(data)
                    if counts[label]>limit: raise vault.VaultError('rclone output exceeded its safety limit')
                    if label=='out': chunks.append(data)
            try: code=proc.wait(timeout=max(0.01,deadline-time.monotonic()))
            except subprocess.TimeoutExpired: raise vault.VaultError('rclone timed out') from None
        if code: raise vault.VaultError('rclone failed; verify its configuration/permissions without enabling sensitive debug logs')
        try: return b''.join(chunks).decode('utf-8',errors='strict')
        except UnicodeError: raise vault.VaultError('rclone returned invalid output encoding') from None
    except OSError: raise vault.VaultError('Unable to run rclone; install a supported version and check the remote') from None
    finally:
        if proc:
            try: os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: raise vault.VaultError('rclone cleanup timed out after termination') from None
            proc.stdout.close();proc.stderr.close()


def backend(remote):
    name, _ = remote_path(remote)
    output=run_rclone(['version'],stdout_limit=16384)
    match=re.match(r'rclone v([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][^\s]+)?(?:\s|$)',output)
    if not match or not (1,60,1) <= tuple(map(int,match.groups())) < (2,0,0):
        raise vault.VaultError('Use rclone 1.60.1 or newer in the supported 1.x series')
    candidates=[]
    for line in run_rclone(['listremotes','--long']).splitlines():
        item=re.fullmatch(r'([^\s:]+):\s+([a-z0-9]+)',line.strip())
        if item and item[1]==name: candidates.append(item[2])
    if len(candidates)!=1 or candidates[0] not in ('s3','b2'):
        raise vault.VaultError('Only directly configured S3 or B2 Native remotes with expiring download links are supported')
    return candidates[0]


def query(text):
    try:
        pairs=parse_qsl(text,keep_blank_values=True,strict_parsing=True,max_num_fields=64)
        if len({k for k,v in pairs})!=len(pairs): raise ValueError()
        return dict(pairs)
    except ValueError: raise vault.VaultError('Invalid or duplicate authorization parameters') from None


def validate_link(text, kind, remote, object_key, seconds, before, after):
    """Validate protocol/target/expiry without rewriting a single signed URL byte."""
    if not isinstance(text,str) or not text or len(text)>MAX_LINK or not text.isascii():
        raise vault.VaultError('Empty, excessive or malformed temporary URL')
    if re.search(r'%(?![0-9A-Fa-f]{2})',text) or quote(text,safe=":/?[]@!$&'()*+,;=%-._~")!=text:
        raise vault.VaultError('Non-canonical temporary URL encoding')
    vault.validate_url(text);url=urlsplit(text)
    if url.scheme!='https' or '#' in text: raise vault.VaultError('Generated temporary URLs must use HTTPS without fragments')
    _, root=remote_path(remote);bucket,_,prefix=root.partition('/')
    target=(prefix+'/' if prefix else '')+object_key
    params=query(url.query)
    if kind=='s3':
        if not (url.path=='/'+bucket+'/'+target or (url.path=='/'+target and url.hostname.startswith(bucket+'.'))):
            raise vault.VaultError('S3 link does not target the requested bucket/object')
        required={'X-Amz-Algorithm','X-Amz-Credential','X-Amz-Date','X-Amz-Expires','X-Amz-SignedHeaders','X-Amz-Signature'}
        if (not required <= params.keys() or params['X-Amz-Algorithm']!='AWS4-HMAC-SHA256' or
                params['X-Amz-SignedHeaders']!='host' or params['X-Amz-Expires']!=str(seconds) or
                not re.fullmatch(r'[a-f0-9]{64}',params['X-Amz-Signature']) or 'Authorization' in params or
                not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z',params['X-Amz-Date'])):
            raise vault.VaultError('Expected a time-limited SigV4 GET URL signing only the host header')
        credential=params['X-Amz-Credential'].split('/')
        if (len(credential)!=5 or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}',credential[0]) or
                credential[1]!=params['X-Amz-Date'][:8] or not re.fullmatch(r'[A-Za-z0-9-]{1,64}',credential[2]) or
                credential[3:]!=['s3','aws4_request']):
            raise vault.VaultError('Invalid SigV4 credential scope')
        try: issued=int(datetime.strptime(params['X-Amz-Date'],'%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc).timestamp())
        except ValueError: raise vault.VaultError('Invalid SigV4 issue time') from None
        if not before-5 <= issued <= after+5: raise vault.VaultError('Unexpected SigV4 issue time; check the NAS clock')
        expires=issued+seconds
    elif kind=='b2':
        if url.path!='/file/'+bucket+'/'+target or set(params)!={'Authorization'} or not re.fullmatch(r'[A-Za-z0-9._~=/+-]{16,4096}',params.get('Authorization','')):
            raise vault.VaultError('Expected a B2 Native token scoped by rclone to the complete object name')
        # The known backend's explicit duration is sent to B2. The opaque token has no readable exp.
        expires=int(before)+seconds
    else: raise vault.VaultError('Unsupported expiry backend')
    if expires<=after: raise vault.VaultError('Generated authorization already expired before batch completion')
    return {'type':'presigned','url':text,'expiresAt':expires}


def record_size(item):
    return len(json.dumps(vault.ordered_record(item),ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8'))


def sign_vault(opened, source, remote, expires='6d', dry_run=False):
    validate_options(source,remote,expires);seconds=duration(expires);kind=backend(remote)
    files=copy.deepcopy(opened.data['files']);objects=[f for f in files if 'objectKey' in f]
    report={'source':source,'backend':kind,'objects':len(objects),'legacy_skipped':len(files)-len(objects),
            'signed':0,'dry_run':dry_run,'published':False,'requested_seconds':seconds}
    # Estimate typical/max URL growth before requesting any link; actual bytes are tracked below.
    report['estimated_directory_bytes']=len(vault.encode_data(opened.data))+len(objects)*(2048+96)
    report['maximum_url_bytes']=MAX_LINK
    report['directory_limit_bytes']=vault.MAX_DATA
    report['estimate_may_exceed_limit']=report['estimated_directory_bytes']>vault.MAX_DATA
    if dry_run:
        report['files']=[{k:f[k] for k in ('id','name')} for f in objects]
        return None, report
    if not objects: return None, report
    preview={'version':3,'revision':opened.meta.revision+1,'files':files}
    size=len(vault.encode_data(preview))
    origin=None;deadlines=[]
    for item in objects:
        try:
            previous=record_size(item);before=time.time()
            arguments=['link','--expire',f'{seconds}s']
            if kind=='b2': arguments+=['--b2-download-auth-duration',f'{seconds}s']
            output=run_rclone([*arguments,'--',remote.rstrip('/')+'/'+item['objectKey']],stdout_limit=MAX_LINK+2)
            after=time.time()
            # A single URL line only, not arbitrary debug output with a link at the end.
            text=output.removesuffix('\n').removesuffix('\r')
            grant=validate_link(text,kind,remote,item['objectKey'],seconds,before,after)
            url=urlsplit(text);current_origin=(url.scheme,url.netloc)
            if origin is not None and origin!=current_origin: raise vault.VaultError('Signer changed origin within this source batch')
            origin=current_origin
            access=item.setdefault('access',{});access[source]=grant
            if len(access)>32: raise vault.VaultError('Too many access sources')
            size+=record_size(item)-previous
            if size>vault.MAX_DATA: raise vault.VaultError('Signed directory exceeds the unchanged 4 MiB Vault limit')
            deadlines.append(grant['expiresAt'])
        except (ValueError,OSError) as error:
            reason=str(error) if isinstance(error,vault.VaultError) else 'rclone or URL validation failure'
            raise vault.VaultError(f'Signing failed for object {item["id"]}; no Vault update was committed. {reason}') from None
    if min(deadlines)<=time.time(): raise vault.VaultError('Some authorizations expired during signing; use a longer duration and retry')
    raw=vault.update(opened,files)  # Exact final schema/canonical/size check and authenticated re-open.
    report.update(signed=len(objects),expiresAtMin=min(deadlines),expiresAtMax=max(deadlines),directory_bytes=size)
    return raw,report
