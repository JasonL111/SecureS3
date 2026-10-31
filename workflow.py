"""Reusable V4 orchestration. No passwords or bearer URLs are written to app state."""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, HTTPSHandler
import ssl

import batch
import presign
import vault

ROOT = Path(__file__).resolve().parent
HEX = re.compile(r'[a-f0-9]{64}')


class UserError(vault.VaultError):
    pass


def absolute(value):
    if not isinstance(value,str) or not value or len(value)>4096 or re.search(r'[\x00-\x1f\x7f]',value):
        raise UserError('本地路径无效。')
    return str(Path(os.path.abspath(os.path.expanduser(value))))


def public_url(value):
    vault.validate_url(value)
    u=urlsplit(value)
    if u.scheme!='https' or u.query or '#' in value:
        raise UserError('请填写稳定的 HTTPS 地址，不要填写临时授权链接或查询参数。')
    return value


def config_home():
    base=os.environ.get('XDG_CONFIG_HOME') or str(Path.home()/'.config')
    if not os.path.isabs(base): raise UserError('XDG_CONFIG_HOME 必须是绝对路径。')
    return Path(base)/'secures3'


def data_home():
    base=os.environ.get('XDG_DATA_HOME') or str(Path.home()/'.local/share')
    if not os.path.isabs(base): raise UserError('XDG_DATA_HOME 必须是绝对路径。')
    return Path(base)/'secures3'


def validate_settings(s):
    fields={'version','data_dir','vault_file','vault_id','batches','active_batch','sources','active_source',
            'vault_remote','vault_url','site_url','expires','repo_dir','deployment_linked','deploy_branch','approved_local_paths'}
    if not isinstance(s,dict) or set(s)!=fields or type(s['version']) is not int or s['version']!=1:
        raise UserError('设置文件不完整或版本不支持；已保留原文件，不会重新初始化保险库。')
    for key in ('data_dir','vault_file'):
        if absolute(s[key])!=s[key]: raise UserError('设置中的路径必须是规范绝对路径。')
    if s['repo_dir'] and absolute(s['repo_dir'])!=s['repo_dir']: raise UserError('源码路径无效。')
    if not re.fullmatch(r'[a-f0-9]{32}',s['vault_id']): raise UserError('保险库标识无效。')
    if not isinstance(s['batches'],list) or not 1<=len(s['batches'])<=64: raise UserError('视频文件夹配置无效。')
    if type(s['active_batch']) is not int or not 0<=s['active_batch']<len(s['batches']): raise UserError('当前文件夹无效。')
    inputs=set()
    for b in s['batches']:
        if not isinstance(b,dict) or set(b)!={'input_dir','output_dir','private_dir'}: raise UserError('工作目录配置无效。')
        paths=[Path(absolute(b[k])) for k in ('input_dir','output_dir','private_dir')]
        if any(str(p)!=b[k] for p,k in zip(paths,('input_dir','output_dir','private_dir'))): raise UserError('工作路径无效。')
        if any(a==c or a in c.parents or c in a.parents for a,c in ((paths[0],paths[1]),(paths[0],paths[2]),(paths[1],paths[2]))):
            raise UserError('视频、加密输出和私有资料目录不能互相包含。')
        if b['input_dir'] in inputs: raise UserError('重复的视频文件夹配置。')
        inputs.add(b['input_dir'])
    if not isinstance(s['sources'],list) or not 1<=len(s['sources'])<=32: raise UserError('存储设置无效。')
    ids=set()
    for source in s['sources']:
        if not isinstance(source,dict) or set(source)!={'id','name','remote'}: raise UserError('存储来源字段无效。')
        vault.source_id(source['id']);presign.remote_path(source['remote'])
        if source['id'] in ids or not isinstance(source['name'],str) or not 1<=len(source['name'].encode())<=128 or re.search(r'[\x00-\x1f\x7f]',source['name']):
            raise UserError('存储来源名称或标识无效。')
        ids.add(source['id'])
        presign.validate_options(source['id'],source['remote'],s['expires'],True,s['vault_remote'])
    if s['active_source'] not in ids: raise UserError('当前存储来源无效。')
    public_url(s['vault_url']);public_url(s['site_url']);presign.duration(s['expires'])
    if type(s['deployment_linked']) is not bool or not isinstance(s['deploy_branch'],str): raise UserError('网站部署配置无效。')
    if s['deployment_linked'] and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9._/-]{0,200}',s['deploy_branch']): raise UserError('部署分支无效。')
    if not isinstance(s['approved_local_paths'],list) or len(s['approved_local_paths'])>128: raise UserError('本地路径授权无效。')
    for path in s['approved_local_paths']:
        if absolute(path)!=path: raise UserError('本地路径授权无效。')
    return s


def empty_state():
    return {'version':1,'local':{},'uploads':{},'objects':{},'library_hash':'','library_ids':[],
            'grant_until':{},'uploaded':None,'published':None,'private_checked':[],
            'web_hash':'','web_confirmed':'','config_commit':''}


class LocalStore:
    def __init__(self,directory=None): self.path=Path(absolute(str(directory or config_home())))
    @contextmanager
    def session(self):
        with batch.directory(self.path,create=True,private=True) as fd:
            lock=os.open('.app.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=fd)
            try:
                info=os.fstat(lock)
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1: raise UserError('本地锁文件不安全。')
                try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError: raise UserError('另一个视频保险箱窗口正在运行，请先关闭它。') from None
                yield self
            finally: os.close(lock)
    def read(self,name,limit=65536):
        with batch.directory(self.path,private=True) as fd:return batch.read_json(fd,name,limit)
    def write(self,name,data,limit=65536):
        raw=batch.json_bytes(data)
        if len(raw)>limit: raise UserError('本地配置或恢复记录超过安全上限。')
        with vault.VaultFile(self.path/name) as store:
            try: old=batch.read_bytes(store.fd,name,limit)
            except FileNotFoundError: old=None
            if old is not None: store._write(name+'.bak',old)
            store._write(name,raw)
    def settings(self):return validate_settings(self.read('settings.json'))
    def save_settings(self,s):self.write('settings.json',validate_settings(s))
    def state(self):
        try:s=self.read('state.json',batch.MAX_MANIFEST)
        except FileNotFoundError:return empty_state()
        if not isinstance(s,dict) or set(s)!=set(empty_state()) or s['version']!=1: raise UserError('恢复记录不完整；已停止，未覆盖已有资料。')
        for field in ('local','uploads','objects','grant_until'):
            if not isinstance(s[field],dict) or len(s[field])>vault.MAX_FILES: raise UserError('恢复记录超限或无效。')
        for field in ('library_hash','web_hash','web_confirmed'):
            if s[field] and not HEX.fullmatch(s[field]): raise UserError('恢复指纹无效。')
        if not isinstance(s['library_ids'],list) or len(s['library_ids'])>vault.MAX_FILES or any(not isinstance(i,str) or not re.fullmatch(r'[a-f0-9]{32}',i) for i in s['library_ids']): raise UserError('恢复编号无效。')
        if not isinstance(s['private_checked'],list) or len(s['private_checked'])>32: raise UserError('存储检查记录无效。')
        for remote in s['private_checked']:presign.remote_path(remote)
        for remote,receipts in s['uploads'].items():
            presign.remote_path(remote)
            if not isinstance(receipts,dict) or len(receipts)>vault.MAX_FILES: raise UserError('上传恢复记录无效。')
            for i,digest in receipts.items():vault.object_key(i);_digest(digest)
        for i,receipt in s['local'].items():
            vault.object_key(i)
            if not isinstance(receipt,dict) or set(receipt)!={'source','cipher','key','sha256','private_dir'}:raise UserError('本地校验记录无效。')
            _digest(receipt['sha256']);absolute(receipt['private_dir'])
            for k in ('source','cipher','key'):
                if k=='source' and receipt[k] is None:continue
                _stamp(receipt[k])
        for i,obj in s['objects'].items():
            vault.object_key(i)
            if not isinstance(obj,dict) or set(obj)!={'path','sha256','stamp'}:raise UserError('迁移恢复记录无效。')
            absolute(obj['path']);_digest(obj['sha256']);_stamp(obj['stamp'])
        for source,until in s['grant_until'].items():
            vault.source_id(source)
            if type(until) is not int or not 0<=until<=vault.MAX_ACCESS_TIME:raise UserError('观看期限记录无效。')
        for key in ('uploaded','published'):
            if s[key] is not None:
                if not isinstance(s[key],dict) or set(s[key])!={'sha256','remote','url'}:raise UserError('发布恢复记录无效。')
                _digest(s[key]['sha256']);presign.remote_path(s[key]['remote']);public_url(s[key]['url'])
        if s['config_commit'] and not re.fullmatch(r'[a-f0-9]{40,64}',s['config_commit']):raise UserError('网站提交记录无效。')
        return s
    def save_state(self,s):self.write('state.json',s,batch.MAX_MANIFEST)


def _digest(value):
    if not isinstance(value,str) or not HEX.fullmatch(value):raise UserError('本地指纹无效。')


def _stamp(value):
    if not isinstance(value,dict) or set(value)!={'dev','ino','size','mtime_ns','ctime_ns'} or any(type(v) is not int for v in value.values()):raise UserError('本地文件状态无效。')


def file_stamp(path):
    path=Path(path)
    with batch.directory(path.parent) as fd,batch.read_file(fd,path.name) as f:return batch.stamp(os.fstat(f.fileno()))


def read_vault(path):
    with vault.VaultFile(path) as store:return store.read()


def sha(raw):return hashlib.sha256(raw).hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def fetch(url,limit,headers=None,partial=False):
    vault.validate_url(url)
    if urlsplit(url).scheme!='https':raise UserError('连接检查只允许 HTTPS，不会关闭 TLS 验证。')
    request=Request(url,headers={'Cache-Control':'no-cache',**(headers or {})},method='GET')
    opener=build_opener(NoRedirect(),HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request,timeout=20) as response:
            status=response.status;response_headers=dict(response.headers.items());body=response.read(limit+1)
            if len(body)>limit and not partial:raise UserError('远端响应超过预期大小，已停止读取。')
            body=body[:limit]
            return status,{k.lower():v for k,v in response_headers.items()},body
    except HTTPError as error:
        code=error.code;error.close();return code,{},b''
    except (URLError,OSError,ValueError):raise UserError('网络或 TLS 检查未完成；请核对地址、网络和证书，验证未被关闭。') from None


def unsigned_url(url):
    u=urlsplit(url);return urlunsplit((u.scheme,u.netloc,u.path,'',''))


def object_remote(remote,identifier):return remote.rstrip('/')+'/'+vault.object_key(identifier)


def remote_digest(remote):
    output=presign.run_rclone(['hashsum','sha256','--download','--',remote],timeout=86400,stdout_limit=16384)
    match=re.fullmatch(r'([a-fA-F0-9]{64})\s+[^\r\n]+\r?\n?',output)
    if not match:raise UserError('未能校验远端文件内容；不会把只看大小当成上传完成。')
    return match[1].lower()


def upload_object(path,remote,digest):
    try:
        metadata=presign.run_rclone(['lsjson','--stat','--',remote],stdout_limit=16384)
        info=json.loads(metadata)
        if not isinstance(info,dict) or type(info.get('IsDir')) is not bool:raise UserError('无法确认目标对象状态，已拒绝覆盖。')
        if info['IsDir']:
            # S3 reports an absent file as an empty virtual directory. A nonempty prefix is a conflict.
            children=presign.run_rclone(['lsf','--max-depth','1','--',remote],stdout_limit=16384)
            if children.strip():raise UserError('目标对象路径已被其他目录内容占用，已拒绝覆盖。')
            exists=False
        else:exists=True
    except presign.RcloneFailure as error:
        if error.returncode not in (3,4):raise
        exists=False
    if exists:
        if remote_digest(remote)!=digest:raise UserError('远端已有不同或未完成的同名对象，已拒绝覆盖；本地资料保留，请检查该目标。')
        return False
    presign.run_rclone(['copyto','--immutable','--ignore-existing','--s3-no-check-bucket','--',str(path),remote],timeout=86400)
    if remote_digest(remote)!=digest:raise UserError('上传后的内容校验失败，本地资料保留，未登记为完成。')
    return True


class Library:
    def __init__(self,settings,local,emit=print):
        self.s=validate_settings(settings);self.local=local;self.state=local.state();self.emit=emit
        for identifier,obj in self.state['objects'].items():
            if obj['path'] not in {str(Path(b['output_dir'])/vault.object_key(identifier)) for b in self.s['batches']}:
                raise UserError('迁移恢复记录不能引用受管对象目录之外的文件。')
    @property
    def source(self):return next(x for x in self.s['sources'] if x['id']==self.s['active_source'])
    def save(self):self.local.save_state(self.state)
    def records(self):
        result=[];pending=[]
        for slot in self.s['batches']:
            private=Path(slot['private_dir'])
            if not private.exists():continue
            with batch.directory(private,private=True) as fd:
                try:
                    layout=batch.binding(fd)
                    if layout!={'version':1,'input_dir':slot['input_dir'],'output_dir':slot['output_dir']}:raise UserError('已有工作目录的绑定不同，未重建或覆盖资料。')
                    data=batch.manifest(fd)
                except FileNotFoundError:
                    if any((private/n).exists() for n in ('keys','manifest.json.bak','.pending.json')):
                        raise UserError('已有工作资料不完整，请保留文件并在高级选项中检查/恢复。') from None
                    pending.append(slot);continue
                if (private/'.pending.json').exists():pending.append(slot)
                result.extend((slot,item) for item in data['files'])
        if len(result)>vault.MAX_FILES:raise UserError('本地视频记录过多。')
        if len({item['id'] for slot,item in result})!=len(result):raise UserError('不同工作目录存在重复编号，已停止。')
        return result,pending
    def stamps(self,slot,item):
        source=Path(slot['input_dir'])/item['name']
        try: source_info=file_stamp(source)
        except FileNotFoundError:source_info=None
        if source_info is not None and source_info!={k:item['source'][k] for k in ('dev','ino','size','mtime_ns','ctime_ns')}:
            raise UserError('源视频已修改：'+item['name']+'。原副本保留；请把新版本放到新名称或新文件夹后添加。')
        return {'source':source_info,'cipher':file_stamp(Path(slot['output_dir'])/item['object_key']),
                'key':file_stamp(Path(slot['private_dir'])/item['key_file']),'sha256':item['cipher_sha256'],'private_dir':slot['private_dir']}
    def trusted(self,slot,item,stamps=None):
        current=stamps or self.stamps(slot,item);old=self.state['local'].get(item['id'])
        return bool(old and all(old[k]==current[k] for k in ('cipher','key','sha256','private_dir')) and
                    (current['source'] is None or old['source']==current['source']))
    def plan(self):
        slot=self.s['batches'][self.s['active_batch']]
        with batch.directory(slot['input_dir']): names=batch.scan(Path(slot['input_dir']),True)
        entries,pending=self.records();known={i['name'] for b,i in entries if b==slot};new=[n for n in names if n not in known]
        unverified=0
        for b,item in entries:
            if not self.trusted(b,item):unverified+=1
        size=sum(file_stamp(Path(slot['input_dir'])/n)['size'] for n in new)
        return {'new':new,'bytes':size,'known':len(entries),'entries':entries,'pending':pending,'unverified':unverified}
    def ready_without_work(self,plan):
        if plan['new'] or plan['pending'] or plan['unverified']:return False
        remote=self.source['remote'];receipts=self.state['uploads'].get(remote,{})
        if any(receipts.get(i['id'])!=i['cipher_sha256'] or i['id'] not in self.state['library_ids'] for b,i in plan['entries']):return False
        digest=sha(read_vault(self.s['vault_file']));target=self.publication(digest)
        return self.state['library_hash']==digest and self.state['published']==target and self.state['grant_until'].get(self.source['id'],0)>=time.time()+self.threshold()
    def verify_local(self,entries,force=False):
        for slot,item in entries:
            before=self.stamps(slot,item)
            if not force and self.trusted(slot,item,before):continue
            with batch.directory(slot['private_dir'],private=True) as private,batch.directory(slot['output_dir']) as output:
                batch.verify_record(item,private,output)
                if before['source'] is not None:
                    with batch.directory(slot['input_dir']) as source:
                        if batch.fingerprint(source,item['name'])!=item['source']:raise UserError('源视频与已加密副本不一致，已停止。')
            after=self.stamps(slot,item)
            if after!=before:raise UserError('校验时文件发生变化，未记录成功。')
            self.state['local'][item['id']]=after;self.save()
    def remember(self,raw,opened):
        self.state['library_hash']=sha(raw);self.state['library_ids']=[f['id'] for f in opened.data['files']]
        objects=[f for f in opened.data['files'] if 'objectKey' in f]
        self.state['grant_until']={source['id']:min((f.get('access',{}).get(source['id'],{}).get('expiresAt',0) for f in objects),default=vault.MAX_ACCESS_TIME) for source in self.s['sources']}
        self.save()
    def threshold(self):return min(3600,presign.duration(self.s['expires'])//4)
    def publication(self,digest):return {'sha256':digest,'remote':self.s['vault_remote'],'url':self.s['vault_url']}
    def private_check(self,opened):
        remote=self.source['remote']
        if remote in self.state['private_checked']:return
        first=next((f for f in opened.data['files'] if 'objectKey' in f and self.source['id'] in f.get('access',{})),None)
        if first is None:return
        try: status,headers,body=fetch(unsigned_url(first['access'][self.source['id']]['url']),49,{'Range':'bytes=0-47'},True)
        except UserError:
            self.emit('未验证：无法确认匿名读取已关闭；请在设置 → 检查连接中核实。');return
        if status in (200,206):raise UserError('视频存储允许匿名读取，已停止发布。请保持视频 Bucket 私有；本程序不会修改权限。')
        if status in (401,403):self.state['private_checked'].append(remote);self.save()
        else:self.emit('未验证：匿名请求未返回明确的拒绝状态，请核实私有设置。')
    def publish(self,raw,opened):
        target=self.publication(sha(raw))
        if self.state['published']==target:return False
        self.private_check(opened)
        if self.state['uploaded']!=target:
            try:vault.copy_remote(self.s['vault_file'],self.s['vault_remote'],is_vault=True)
            except (ValueError,OSError):raise UserError('视频库已在 NAS 本地安全更新，但远端发布失败。重新选择“开始观看”可只重试发布，不会重复签名。') from None
            self.state['uploaded']=target;self.save()
        status,headers,body=fetch(self.s['vault_url'],vault.MAX_FILE)
        if status!=200:raise UserError('已上传，但公开地址暂时不可读取；未确认发布成功。再次开始观看只重试未完成阶段。')
        if sha(body)!=target['sha256']:raise UserError('公开地址返回了旧版本或不同内容，可能有缓存；本地新版保留，未误报发布完成。')
        self.state['published']=target;self.save();return True
    def watch(self,opened,raw,store,adding=False):
        objects=[f for f in opened.data['files'] if 'objectKey' in f]
        need=any(f.get('access',{}).get(self.source['id'],{}).get('expiresAt',0)<time.time()+self.threshold() for f in objects)
        if need:
            self.emit('正在准备观看权限…')
            replacement,report=presign.sign_vault(opened,self.source['id'],self.source['remote'],self.s['expires'])
            if replacement is not None:
                store.commit(replacement,previous=raw);raw=replacement;opened=vault.open_with_kek(raw,opened.kek)
        self.remember(raw,opened)
        self.emit('[5/5] 正在发布视频库…' if adding else '正在确认视频库发布…');self.publish(raw,opened)
        return raw,opened,need
    def add(self,opened,raw,store,plan=None):
        plan=plan or self.plan();slot=self.s['batches'][self.s['active_batch']]
        self.emit('[1/5] 正在加密新视频…')
        if plan['new'] or plan['pending']:
            targets=[slot,*[b for b in plan['pending'] if b!=slot]]
            for b in targets:
                names=plan['new'] if b==slot else []
                result=batch.batch_encrypt(b['input_dir'],b['output_dir'],b['private_dir'],True,only_names=names)
                if result['errors']:raise UserError('部分加密未完成；已完成的加密文件和密钥保留，再次添加即可安全继续。')
        entries,pending=self.records();self.verify_local(entries)
        self.emit('[2/5] 正在上传到私人存储…');remote=self.source['remote'];receipts=self.state['uploads'].setdefault(remote,{})
        if any(receipts.get(item['id'])!=item['cipher_sha256'] for b,item in entries) or any(receipts.get(i)!=o['sha256'] for i,o in self.state['objects'].items()):
            name,path=presign.remote_path(remote);bucket=path.split('/')[0]
            try:presign.run_rclone(['lsf','--max-depth','1','--files-only','--',name+':'+bucket],stdout_limit=1048576)
            except (ValueError,OSError):raise UserError('无法验证已存在的私人存储，未尝试创建 Bucket 或上传。请检查位置与只读列举权限。') from None
        completed=0;total=len(entries)+len(self.state['objects'])
        for b,item in entries:
            if receipts.get(item['id'])==item['cipher_sha256']:completed+=1;continue
            try:
                with batch.directory(b['private_dir'],private=True) as private,batch.directory(b['output_dir']) as output:batch.verify_record(item,private,output)
                upload_object(Path(b['output_dir'])/item['object_key'],object_remote(remote,item['id']),item['cipher_sha256'])
            except (ValueError,OSError):raise UserError(f'上传未完成：{total} 个视频中已确认 {completed} 个。本地文件和密钥保留，重新选择“添加视频”即可继续。') from None
            receipts[item['id']]=item['cipher_sha256'];self.save();completed+=1
        by_id={f['id']:f for f in opened.data['files']}
        for identifier,obj in self.state['objects'].items():
            if identifier not in by_id:continue
            if receipts.get(identifier)!=obj['sha256'] or file_stamp(obj['path'])!=obj['stamp']:
                info=vault.verify_video(obj['path'],by_id[identifier]['key'],details=True)
                if info['id']!=identifier or info['cipher_sha256']!=obj['sha256']:raise UserError('迁移副本已变化，未上传。')
                obj['stamp']=file_stamp(obj['path']);self.save()
            if receipts.get(identifier)!=obj['sha256']:
                upload_object(obj['path'],object_remote(remote,identifier),obj['sha256']);receipts[identifier]=obj['sha256'];self.save()
        self.emit('[3/5] 正在更新视频库…')
        candidate=raw;current=opened
        for b,item in entries:
            prior=next((f for f in opened.data['files'] if f['id']==item['id']),None)
            if prior:
                with batch.directory(b['private_dir'],private=True) as fd:key=batch.key_text(fd,item['key_file'])
                expected={'id':item['id'],'name':item['name'],'objectKey':item['object_key'],'key':key}
                if {k:v for k,v in prior.items() if k!='access'}!=expected:raise UserError('本地资料与已有视频库记录冲突，已保留原库并停止。')
        for b in self.s['batches']:
            identifiers={item['id'] for other,item in entries if other==b and item['id'] not in {f['id'] for f in current.data['files']}}
            if not identifiers:continue
            replacement=batch.batch_add(current,Path(b['private_dir'])/'manifest.json',only_ids=identifiers)
            if replacement is not None:candidate=replacement;current=vault.open_with_kek(candidate,opened.kek)
        if candidate!=raw:store.commit(candidate,previous=raw);raw=candidate;opened=current
        self.remember(raw,opened)
        self.emit('[4/5] 正在准备临时观看权限…')
        raw,opened,signed=self.watch(opened,raw,store,adding=True)
        return raw,opened,len(plan['new'])


def web_data(s):
    return {'vaultUrl':s['vault_url'],'vaultId':s['vault_id'],
            'storageSources':[{'id':v['id'],'name':v['name'],'type':'presigned'} for v in sorted(s['sources'],key=lambda x:x['id']!=s['active_source'])]}


def web_bytes(s):return ('globalThis.SECURES3_CONFIG = Object.freeze('+json.dumps(web_data(s),ensure_ascii=False,separators=(',',':'))+');\n').encode()


def git(repo,args,check=True,limit=131072):
    try:
        env=os.environ.copy()
        for key in ('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_PREFIX'):env.pop(key,None)
        code,text=presign.run_process(['git','-C',str(repo),*args],45,limit,16384,env)
    except (ValueError,OSError):raise UserError('Git 操作未完成，未显示任何凭据；请检查仓库或网络。') from None
    if check and code:raise UserError('Git 操作未完成，未自动覆盖或强制推送。')
    return code,text.encode()


def repository(path):
    p=Path(path);p=p if p.is_dir() else p.parent
    while not p.exists() and p!=p.parent:p=p.parent
    code,out=git(p,['rev-parse','--show-toplevel'],False)
    return Path(out.decode().strip()) if code==0 else None


def sensitive_tracked(repo):
    _,data=git(repo,['ls-files','-z'])
    result=[]
    for path in data.decode().split('\0'):
        if not path:continue
        name=Path(path).name.lower()
        if (name.endswith(('.key','.key.bak','.enc','.enc.bak','.pem','.p12')) or
                name in ('rclone.conf','.rclone.conf','manifest.json','manifest.json.bak','.batch.json','.pending.json','settings.json','settings.json.bak','state.json','state.json.bak') or
                name.startswith(('.env','rclone.conf.','.rclone.conf.'))):result.append(path)
    return result


def private_path_risk(path):
    repo=repository(path)
    if repo is None:return None
    try:relative=Path(path).relative_to(repo).as_posix()
    except ValueError:raise UserError('私有路径无法安全定位。') from None
    _,tracked=git(repo,['ls-files','-z','--',relative])
    if tracked:raise UserError('私有路径已被 Git 追踪，已停止。若历史中有真实 Secret，请撤销/轮换，而不只是删除文件。')
    probe=relative if Path(path).suffix else relative.rstrip('/')+'/.secures3-private-probe'
    code,_=git(repo,['check-ignore','-q','--',probe],False)
    if code:raise UserError('私有路径位于源码仓库且未完整排除，请改用仓库外的目录。')
    return str(repo)


ASSETS=('index.html','style.css','app.js','download.js','config.js','protocol.js','sw.js','vault.js','vault-crypto.js','vault-kdf.js','_headers','client.json',
        'vendor/argon2.umd.min.js','vendor/LICENSE.hash-wasm','vendor/PROVENANCE.json')


def generate_site(s,local):
    data=web_bytes(s);destination=Path(s['data_dir'])/'website'
    with batch.directory(destination,create=True) as output:
        repo=repository(ROOT)
        for name in ASSETS:
            if name=='config.js':content=data
            elif repo and (repo/'.git').exists():
                code,content=git(repo,['show','HEAD:web/'+name],False,2097152)
                if code:
                    source=ROOT/'web'/name
                    with batch.directory(source.parent) as fd:content=batch.read_bytes(fd,source.name,2097152)
            else:
                source=ROOT/'web'/name
                with batch.directory(source.parent) as fd:content=batch.read_bytes(fd,source.name,2097152)
            path=destination/name
            with batch.directory(path.parent,create=True),vault.VaultFile(path) as store:store._write(path.name,content)
    with vault.VaultFile(local.path/'web-config.js') as store:store._write('web-config.js',data)
    return destination


def config_target(s,state,write=False):
    if not s['deployment_linked'] or not s['repo_dir']:raise UserError('未确认当前仓库与网站自动部署关联；已生成独立网站文件，未覆盖源码。')
    repo=Path(s['repo_dir']);target=repo/'web/config.js'
    if sensitive_tracked(repo):raise UserError('仓库追踪了可能的私有资料，已禁止自动提交。请核实历史泄露并撤销/轮换真实 Secret。')
    _,branch=git(repo,['branch','--show-current'])
    if branch.decode().strip()!=s['deploy_branch']:raise UserError('当前分支不是已确认的网站部署分支，未覆盖或推送。')
    _,status=git(repo,['status','--porcelain=v1','-z'])
    changed=[x[3:] for x in status.decode().split('\0') if x]
    if any(p!='web/config.js' for p in changed):raise UserError('源码中有其他修改或冲突，未覆盖网站配置，也不会自动推送。')
    if changed:
        with batch.directory(target.parent) as fd:current=batch.read_bytes(fd,target.name,65536)
        if sha(current)!=state['web_hash']:raise UserError('网站配置有非本工具的修改，已保留，未覆盖或推送。')
    if target.is_symlink() or target.parent.is_symlink() or repository(target)!=repo:raise UserError('网站配置路径不安全。')
    with batch.directory(target.parent) as fd:previous=batch.read_bytes(fd,target.name,65536)
    if re.search(rb'(?:access[_-]?key|secret[_-]?key|password|api[_-]?key)\s*[:=]\s*[\'\"][^\'\"]+',previous,re.I):
        raise UserError('旧网站配置可能含敏感字段，已禁止自动发布；若是真实 Secret，请撤销/轮换并检查历史。')
    if write:
        with vault.VaultFile(target) as store:store._write(target.name,web_bytes(s))
        state['web_hash']=sha(web_bytes(s))
    return repo,target


def push_config(s,local,state):
    repo,target=config_target(s,state)
    git(repo,['fetch','origin',s['deploy_branch']])
    _,upstream=git(repo,['rev-parse','--abbrev-ref','--symbolic-full-name','@{upstream}'])
    if upstream.decode().strip()!='origin/'+s['deploy_branch']:raise UserError('无法确认部署分支的远端关联，未自动推送。')
    _,ahead=git(repo,['rev-list','@{upstream}..HEAD'])
    commits=ahead.decode().split()
    if commits and commits!=[state['config_commit']]:raise UserError('本地有其他尚未推送的提交，不能只凭文件白名单推送整段历史。')
    for commit in commits:
        _,paths=git(repo,['diff-tree','--no-commit-id','--name-only','-r',commit])
        _,content=git(repo,['show',commit+':web/config.js'],limit=65536)
        match=re.fullmatch(rb'\s*globalThis\.SECURES3_CONFIG\s*=\s*Object\.freeze\((\{.*\})\);?\s*',content,re.S)
        if paths.decode().splitlines()!=['web/config.js'] or not match:
            raise UserError('待推送历史不只是受控网站配置，已停止。')
        parsed=json.loads(match[1]);public_url(parsed.get('vaultUrl',''))
        if set(parsed)!={'vaultUrl','vaultId','storageSources'} or not re.fullmatch(r'[a-f0-9]{32}',parsed.get('vaultId','')):
            raise UserError('待推送历史配置无法验证，已停止。')
        for source in parsed['storageSources']:
            if set(source)!={'id','name','type'} or source['type']!='presigned':raise UserError('待推送历史配置无法验证，已停止。')
            vault.source_id(source['id'])
    _,staged=git(repo,['diff','--cached','--name-only','-z'])
    if any(p!='web/config.js' for p in staged.decode().split('\0') if p):raise UserError('暂存区有其他文件，未提交。')
    with batch.directory(target.parent) as fd:current=batch.read_bytes(fd,target.name,65536)
    if current!=web_bytes(s):raise UserError('待提交配置与已验证设置不同，已停止。')
    _,diff=git(repo,['diff','HEAD','--','web/config.js'])
    if diff:
        git(repo,['add','--','web/config.js']);git(repo,['commit','--only','-m','Update public SecureS3 website configuration','--','web/config.js'])
        _,head=git(repo,['rev-parse','HEAD']);state['config_commit']=head.decode().strip();local.save_state(state)
    _,remaining=git(repo,['rev-list','@{upstream}..HEAD'])
    if remaining.decode().split() not in ([],[state['config_commit']]):raise UserError('提交期间出现其他本地历史，已停止推送。')
    git(repo,['push','origin','HEAD:refs/heads/'+s['deploy_branch']])
    state['config_commit']='';local.save_state(state)


def checks(s,opened,raw):
    result=[]
    source=next(x for x in s['sources'] if x['id']==s['active_source'])
    try:presign.backend(source['remote']);result.append(('通过','存储工具和已保存来源正常'))
    except (ValueError,OSError):result.append(('未验证','存储工具或来源未就绪'))
    first=next((f for f in opened.data['files'] if 'objectKey' in f and f.get('access',{}).get(source['id'],{}).get('expiresAt',0)>time.time()),None)
    if first:
        grant=first['access'][source['id']];url=grant['url'];origin=urlunsplit((*urlsplit(s['site_url'])[:2],'','',''))
        try:
            code,h,body=fetch(url,48,{'Range':'bytes=0-47','Origin':origin})
            valid=code==206 and re.fullmatch(r'bytes 0-47/[0-9]+',h.get('content-range','')) and len(body)==48 and body[:8]==b'ES3VID01' and body[24:40].hex()==first['id']
            result.append(('通过' if valid else '失败','临时 GET 与精确 Range 视频头读取（完整 AEAD 仍由播放器验证）'))
            expose={x.strip().lower() for x in h.get('access-control-expose-headers','').split(',')}
            cors=h.get('access-control-allow-origin') in ('*',origin) and ('content-range' in expose or '*' in expose)
            result.append(('通过' if cors else '未验证','浏览器跨域权限；不满足时请复制下方 CORS 示例'))
        except (ValueError,OSError):result.extend([('未验证','临时 GET / Range'),('未验证','浏览器跨域权限')])
        try:
            code,h,body=fetch(unsigned_url(url),49,{'Range':'bytes=0-47'},True)
            result.append(('通过' if code in (401,403) else '失败' if code in (200,206) else '未验证','私人视频拒绝匿名读取'))
        except (ValueError,OSError):result.append(('未验证','私人视频拒绝匿名读取'))
    else:result.extend([('未验证','没有尚有效的单视频权限；先选择开始观看'),('未验证','私人存储匿名拒绝 / Range / CORS')])
    try:
        code,h,body=fetch(s['vault_url'],vault.MAX_FILE)
        match=code==200 and sha(body)==sha(raw)
        result.append(('通过' if match else '失败','公开视频库可读且与 NAS 最新版本一致'))
        result.append(('通过' if 'no-store' in h.get('cache-control','').lower() else '未验证','视频库缓存策略'))
    except (ValueError,OSError):result.append(('未验证','公开视频库 / 最新版本 / 缓存'))
    try:
        base=s['site_url'].rstrip('/')+'/'
        code,h,body=fetch(base+'client.json',8192)
        meta=json.loads(body) if code==200 else {}
        result.append(('通过' if 3 in meta.get('vaultSchemas',[]) else '未验证','网页声明兼容当前视频库格式（仍需浏览器验收）'))
        code,h,body=fetch(base+'config.js',65536)
        match=re.fullmatch(r'\s*globalThis\.SECURES3_CONFIG\s*=\s*Object\.freeze\((\{.*\})\);?\s*',body.decode(),re.S)
        result.append(('通过' if code==200 and match and json.loads(match[1])==web_data(s) else '未验证','网站已使用当前非敏感配置'))
    except (ValueError,OSError,UnicodeError):result.append(('未验证','网页部署版本与配置'))
    return result


def website_ready(s,local,state):
    # A confirmation belongs to the exact site as well as its public configuration.
    digest=sha(s['site_url'].encode()+b'\0'+web_bytes(s))
    if state['web_confirmed']==digest:return True
    try:
        base=s['site_url'].rstrip('/')+'/'
        code,headers,body=fetch(base+'client.json',8192)
        if code!=200 or 3 not in json.loads(body).get('vaultSchemas',[]):return False
        code,headers,body=fetch(base+'config.js',65536)
        match=re.fullmatch(r'\s*globalThis\.SECURES3_CONFIG\s*=\s*Object\.freeze\((\{.*\})\);?\s*',body.decode(),re.S)
        if code!=200 or not match or json.loads(match[1])!=web_data(s):return False
        state['web_confirmed']=digest;local.save_state(state);return True
    except (ValueError,OSError,UnicodeError):return False
