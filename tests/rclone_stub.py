"""Test-only rclone protocol emulator: synthetic credentials, no cloud access."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def main():
    state=Path(os.environ['SECURES3_TEST_RCLONE_STATE']);config=json.loads(state.read_text())
    args=sys.argv[1:];command=next((a for a in args if a in ('version','listremotes','link','copyto')),None)
    unsafe=any(k.startswith('RCLONE_RC') or k in ('RCLONE_LOG_FILE','RCLONE_LOG_LEVEL','RCLONE_DUMP','RCLONE_USE_SYSLOG') for k in os.environ)
    with state.with_suffix('.calls').open('a') as f:f.write(json.dumps({'command':command,'args':args,'unsafe_debug_env':unsafe})+'\n')
    if command=='version':print('rclone v1.60.1');return
    if command=='listremotes':
        for name,kind in config.get('remotes',{'r2':'s3','b2':'b2','public':'s3','unsupported':'webdav'}).items():print(name+':    '+kind)
        return
    if command=='copyto':
        if config.get('upload_fail'):print('TEST_ONLY_SENSITIVE_DIAGNOSTIC',file=sys.stderr);sys.exit(1)
        return
    if command!='link':sys.exit(1)
    target=args[-1];name,path=target.split(':',1);file_id=path.rsplit('/',1)[-1][:-4]
    mode=config.get('mode','')
    if config.get('failure_id') and file_id!=config['failure_id']:mode=''
    if mode=='sleep':time.sleep(5)
    if mode=='stdout_flood':sys.stdout.write('x'*1000000);return
    if mode=='stderr_flood':sys.stderr.write('x'*1000000);return
    now=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    seconds=args[args.index('--expire')+1][:-1]
    if name=='b2':
        url='https://b2.example.invalid/file/'+path+'?Authorization=TEST_ONLY_OBJECT_'+file_id
    else:
        params={'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Credential':'TESTONLY/'+now[:8]+'/auto/s3/aws4_request',
                'X-Amz-Date':now,'X-Amz-Expires':seconds,'X-Amz-SignedHeaders':'host',
                'X-Amz-Signature':hashlib.sha256(file_id.encode()).hexdigest()}
        url='https://r2.example.invalid/'+path+'?'+urlencode(params)
    if mode=='http':url=url.replace('https:','http:')
    if mode=='wrong_object':url=url.replace(file_id+'.enc','0'*32+'.enc')
    if mode=='wrong_bucket':url=url.replace('private-bucket','other-bucket')
    if mode=='wrong_origin':url=url.replace('r2.example.invalid',file_id+'.example.invalid')
    if mode=='permanent':url=url.split('?')[0]
    if mode=='long':url+='&padding='+'x'*9000
    if mode=='fragment':url+='#secret'
    if mode=='duplicate':url+='&X-Amz-Expires='+seconds
    if mode=='bad_encoding':url+='&x=%zz'
    if mode in ('ttl','signed_range','stale_date'):
        u=urlsplit(url);q=dict(parse_qsl(u.query));
        if mode=='ttl':q['X-Amz-Expires']='9999999999'
        if mode=='signed_range':q['X-Amz-SignedHeaders']='host;range'
        if mode=='stale_date':q['X-Amz-Date']='20000101T000000Z'
        url=urlunsplit((u.scheme,u.netloc,u.path,urlencode(q),''))
    if mode=='multiline':print('Unexpected debug output')
    print(url)
    if mode=='fail':print('TEST_ONLY_SENSITIVE_DIAGNOSTIC '+url,file=sys.stderr);sys.exit(1)


if __name__=='__main__':main()
