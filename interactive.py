"""Chinese terminal application for SecureS3; advanced CLI stays in vault.py."""
from contextlib import contextmanager
import copy
from datetime import datetime
import getpass
import json
import os
from pathlib import Path
import re
import sys
import warnings
import webbrowser

import batch
import presign
import vault
import workflow as w


def ask(label,default=''):
    answer=input(label+(f' [{default}]' if default else '')+'：').strip()
    return answer or default


def confirm(label,default=False):
    answer=input(label+(' [Y/n]：' if default else ' [y/N]：')).strip().lower()
    return default if not answer else answer in ('y','yes','是')


def password(new=False):
    if not sys.stdin.isatty():raise w.UserError('需要交互式终端；通过 SSH 时请使用 ssh -t，密码不能通过管道输入。')
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        try:
            value=getpass.getpass('设置主密码：' if new else '请输入主密码：')
            if new and value!=getpass.getpass('再次输入主密码：'):raise w.UserError('两次密码不同，未创建保险库。')
        except getpass.GetPassWarning:raise w.UserError('终端不能安全隐藏密码，已停止。') from None
    try:vault.password_bytes(value,new=new)
    except ValueError:raise w.UserError('新主密码至少 12 个字符，最多 1024 个 UTF-8 字节；密码不自动去空格或规范化。') from None
    return value


def choose(items,label='请选择',default=1):
    for index,text in enumerate(items,1):print(f'{index}. {text}')
    answer=ask(label,str(default))
    if not answer.isdigit() or not 1<=int(answer)<=len(items):raise w.UserError('请选择列表中的编号。')
    return int(answer)-1


def existing_materials(local):
    roots=list(dict.fromkeys([Path.cwd(),w.ROOT,w.data_home()]))
    vaults=[];slots=[];hints=[]
    for root in roots:
        for name in ('vault.enc','private-vault/vault.enc','private/vault.enc'):
            path=root/name
            if path.is_file() and not path.is_symlink() and path not in vaults:vaults.append(path)
            if path.with_name(path.name+'.bak').exists():hints.append(path.with_name(path.name+'.bak'))
        directories=[root/'private',root/'work/private']
        if (root/'batches').is_dir() and not (root/'batches').is_symlink():
            children=list((root/'batches').iterdir())
            if len(children)>64:raise w.UserError('已有工作目录过多，请先核对设置，不会自动初始化。')
            directories.extend(p/'private' for p in children if p.is_dir() and not p.is_symlink())
        for path in directories:
            if not path.is_dir() or path.is_symlink():continue
            try:
                with batch.directory(path,private=True) as fd:
                    binding=batch.binding(fd);batch.manifest(fd)
                slot={'input_dir':binding['input_dir'],'output_dir':binding['output_dir'],'private_dir':str(path.absolute())}
                if slot not in slots:slots.append(slot)
            except (ValueError,OSError):hints.append(path)
    return vaults,slots,hints


def web_hint():
    try:
        text=(w.ROOT/'web/config.js').read_text()
        found=re.search(r'\bvaultUrl\s*:\s*([\'\"])(https://[^\'\"\s]+)\1',text)
        if found:return w.public_url(found[2])
        found=re.search(r'Object\.freeze\((\{.*\})\)',text,re.S)
        if found:
            value=json.loads(found[1]).get('vaultUrl','')
            if value:return w.public_url(value)
    except (ValueError,OSError):pass
    return ''


def new_slot(data,folder):
    base=Path(data)/'batches'/w.sha(folder.encode())[:16]
    return {'input_dir':folder,'output_dir':str(base/'encrypted'),'private_dir':str(base/'private')}


class App:
    def __init__(self,local):self.local=local;self.s=None;self.pending=None
    def path_guards(self,s):
        paths=[str(self.local.path),s['data_dir'],s['vault_file']]
        paths += [b[k] for b in s['batches'] for k in ('output_dir','private_dir')]
        for path in paths:
            repo=w.private_path_risk(path)
            if repo and path not in s['approved_local_paths']:
                print('注意：私有资料位于 Git 仓库中。默认建议放在仓库外；已检查未追踪且被排除，不能仅依赖 .gitignore。')
                if not confirm('仍明确选择保留这个私有路径 '+path+'？'):raise w.UserError('已取消，请改用仓库外目录。')
                s['approved_local_paths'].append(path)
        if s['repo_dir']:
            found=w.sensitive_tracked(s['repo_dir'])
            if found:
                print('警告：源码追踪了可能的私有文件：'+', '.join(found[:8]))
                print('若含真实 Secret，请撤销/轮换并检查历史，而不只是删除文件；自动网站提交将被禁止。')
    def source_select(self,remotes=None):
        remotes=remotes or presign.available_remotes()
        supported=[(n,k) for n,k in remotes.items() if k in ('s3','b2')]
        if not supported:raise w.UserError('未发现可用存储。请先在 rclone 配置 S3 或 B2 存储；不要把云端 Secret 交给网页。')
        labels=[('Backblaze B2' if k=='b2' else 'S3 兼容存储')+'（'+n+'）' for n,k in supported]
        if len(supported)==1:index=0;print('检测到可用存储：'+labels[0]+'，已作为默认来源。')
        else:
            print('视频准备存放在哪里？');index=choose(labels)
        name,kind=supported[index]
        bucket=ask('视频的私人 Bucket 名称（已存在，不会自动创建）')
        remote=name+':'+bucket;presign.remote_path(remote)
        print('请在存储平台关闭视频 Bucket 的匿名读取，并设置允许播放器网站访问的 CORS。程序不会修改权限。')
        if not confirm('已确认视频存储应保持私有？'):raise w.UserError('已取消，未修改任何云端权限。')
        identifier=re.sub(r'[^a-z0-9_-]','',name.lower())[:20]
        if not identifier or not identifier[0].isalpha():identifier='s'+identifier
        identifier=identifier+'-'+w.sha(remote.encode())[:6]
        return {'id':identifier,'name':labels[index],'remote':remote}
    def setup(self):
        print('\nSecureS3 视频保险箱\n\n欢迎首次使用！\n正在检查运行环境…')
        vault.derive('SecureS3 runtime check',bytes(16));print('✓ Python 加密组件正常')
        remotes=presign.available_remotes();print('✓ 检测到 rclone 和已有存储配置')
        found,slots,hints=existing_materials(self.local)
        selected=None
        if found:
            print('检测到已有保险库，将验证后复用，不重新生成密钥。')
            selected=found[0] if len(found)==1 else found[choose([str(p) for p in found],'选择已有保险库')]
        else:
            value=ask('如果已有保险库，可填写文件路径；首次使用直接回车')
            if value:
                selected=Path(w.absolute(value))
                if not selected.is_file():raise w.UserError('指定的已有保险库不存在；未重新初始化。')
            elif hints and not confirm('发现旧工作资料或备份。建议先恢复旧库，仍明确创建一个新保险库？'):
                raise w.UserError('已停止创建，请保留旧资料并选择已有保险库或备份。')
        source=self.source_select(remotes)
        remote=ask('加密视频库的公开发布位置（例如 public:public-bucket/vault.enc）')
        presign.validate_options(source['id'],source['remote'],'6d',True,remote)
        url=w.public_url(ask('视频库的稳定 HTTPS 访问地址',web_hint()))
        site=w.public_url(ask('播放器网站的 HTTPS 地址'))
        default=slots[0]['input_dir'] if slots else str(Path('/nas/videos') if Path('/nas/videos').is_dir() else Path.cwd()/'videos')
        folder=w.absolute(ask('你的视频文件夹在哪里',default))
        with batch.directory(folder):pass
        data=w.absolute(str(w.data_home()))
        if slots:print('检测到已有加密工作资料，将复用并首次核验；不会重新加密已完成的视频。')
        active=next((i for i,b in enumerate(slots) if b['input_dir']==folder),None)
        if active is None:slots.append(new_slot(data,folder));active=len(slots)-1
        repo=w.repository(Path.cwd()) or w.repository(w.ROOT)
        linked=False;branch=''
        if repo:
            _,branch_data=w.git(repo,['branch','--show-current']);branch=branch_data.decode().strip()
            code,origin=w.git(repo,['remote','get-url','origin'],False)
            github=bool(re.fullmatch(rb'(?:https://github\.com/|git@github\.com:)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?\n?',origin))
            _,dirty=w.git(repo,['status','--porcelain=v1','-z'])
            print('检测到源码仓库；GitHub 公开性未验证，按公开仓库保护。')
            if github and not dirty and branch:
                linked=confirm('这个仓库的当前分支已连接网站自动部署？')
            elif dirty:print('源码已有其他修改，不会覆盖配置或自动推送；会生成独立网站目录。')
        target=w.absolute(str(selected or Path(data)/'vault.enc'))
        self.s={'version':1,'data_dir':data,'vault_file':target,'vault_id':'0'*32,'batches':slots,'active_batch':active,
                'sources':[source],'active_source':source['id'],'vault_remote':remote,'vault_url':url,'site_url':site,'expires':'6d',
                'repo_dir':str(repo) if repo else '','deployment_linked':linked,'deploy_branch':branch,'approved_local_paths':[]}
        w.validate_settings(self.s);self.path_guards(self.s)
        with batch.directory(Path(target).parent,create=True,private=selected is None):pass
        with vault.VaultFile(target) as store:
            if selected:
                raw=store.read();opened=vault.unlock(raw,password())
            else:
                # No fallback from a missing/corrupt existing file to creation.
                secret=password(True)
                try:raw=vault.create(secret);opened=vault.unlock(raw,secret);store.commit(raw)
                finally:secret=None
        self.s['vault_id']=opened.meta.vault_id.hex();self.pending=opened
        self.local.save_settings(self.s);print('✓ 设置已保存，下次无需重复填写位置。')
        self.configure_website()
        if confirm('现在添加视频？',True):
            try:self.add()
            except (ValueError,OSError,vault.InvalidTag) as error:
                self.pending=None;print('操作未完成：'+safe(error)+'\n设置及已完成阶段已保留，可在菜单中继续。')
        else:self.pending=None
    @contextmanager
    def unlocked(self):
        with vault.VaultFile(self.s['vault_file']) as store:
            raw=store.read()
            pending=self.pending;self.pending=None
            opened=vault.open_with_kek(raw,pending.kek) if pending else vault.unlock(raw,password())
            if opened.meta.vault_id.hex()!=self.s['vault_id']:raise w.UserError('保险库身份与保存的设置不同，未继续操作。')
            yield store,raw,opened
    def configure_website(self):
        destination=w.generate_site(self.s,self.local);state=self.local.state()
        print('网站文件已自动生成：'+str(destination))
        try:
            w.config_target(self.s,state,write=True);self.local.save_state(state)
            print('网站配置已更新，仅包含公开地址和存储显示信息。')
            if confirm('是否只提交此次非敏感配置，并推送到 GitHub 触发已关联的网站部署？'):
                w.push_config(self.s,self.local,state);print('✓ 已推送配置；网站是否完成部署仍需检查连接验证。')
            else:print('未提交或推送网站配置。')
        except (ValueError,OSError) as error:
            print('未自动发布网站：'+safe(error))
            print('可将上面生成的 website 目录上传到静态托管平台，无需手写配置；不要上传私有工作目录。')
    def finish(self,library,count=None):
        if w.website_ready(self.s,self.local,library.state):
            print('✓ 全部完成！' if count is not None else '✓ 已准备好，视频库已发布。')
        else:print('✓ 视频库已发布并校验；网站部署/配置尚未验证，请在设置中检查连接或发布生成的网站目录。')
        if count:print(f'本次新增 {count} 个视频。')
        print('打开：\n'+self.s['site_url'])
        if not any(os.environ.get(k) for k in ('SSH_CONNECTION','SSH_TTY','SSH_CLIENT')) and (os.name=='nt' or sys.platform=='darwin' or os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
            if confirm('在此设备打开网站？'):webbrowser.open(self.s['site_url'],new=2)
    def add(self):
        library=w.Library(self.s,self.local);plan=library.plan()
        print(f'\n正在扫描视频文件夹…\n已有视频：{plan["known"]}\n新增视频：{len(plan["new"])}\n新增总大小：{plan["bytes"]/1024**3:.2f} GiB')
        if not plan['new'] and not plan['known'] and not plan['pending']:
            self.pending=None;print('没有发现新视频。请选择包含 MP4 的文件夹。');return
        if library.ready_without_work(plan):
            self.pending=None;print('没有发现新视频。\n你的视频库已经是最新状态。');print('打开：\n'+self.s['site_url']);return
        label=f'是否添加这 {len(plan["new"])} 个视频并上传、准备观看和发布？' if plan['new'] else '发现首次核验或待完成步骤，是否安全继续？'
        if not confirm(label,True):self.pending=None;return
        with self.unlocked() as (store,raw,opened):
            raw,opened,count=library.add(opened,raw,store,plan)
        self.finish(library,count)
    def watch(self):
        print('\n准备打开视频保险箱…')
        library=w.Library(self.s,self.local)
        with self.unlocked() as (store,raw,opened):
            print('正在检查观看权限…');library.watch(opened,raw,store)
        self.finish(library)
    def save_change(self,candidate):
        w.validate_settings(candidate)
        print('将保存以下设置变化（已有视频、密钥和云对象均不会删除）：')
        if candidate['batches']!=self.s['batches'] or candidate['active_batch']!=self.s['active_batch']:
            print('  视频文件夹：'+candidate['batches'][candidate['active_batch']]['input_dir'])
        if candidate['sources']!=self.s['sources'] or candidate['active_source']!=self.s['active_source']:
            print('  当前存储：'+next(s['name'] for s in candidate['sources'] if s['id']==candidate['active_source']))
        for key,label in (('vault_file','保险库文件'),('vault_remote','公开发布位置'),('vault_url','公开视频库地址'),('site_url','网站地址'),('expires','观看期限'),('deployment_linked','网站自动部署关联')):
            if candidate[key]!=self.s[key]:print('  '+label+'：'+str(candidate[key]))
        if not confirm('确认保存？'):return False
        self.path_guards(candidate);self.local.save_settings(candidate);self.s=candidate;self.pending=None;return True
    def settings(self):
        while True:
            print('\n设置\n1. 视频文件夹\n2. 存储位置\n3. 视频库发布位置\n4. 默认观看期限\n5. 网站配置\n6. 检查连接\n7. 高级选项\n\n0. 返回')
            choice=ask('请选择','0');candidate=copy.deepcopy(self.s)
            if choice=='0':return
            try:
                if choice=='1':
                    old=self.s['batches'][self.s['active_batch']];folder=w.absolute(ask('新视频文件夹',old['input_dir']))
                    with batch.directory(folder):pass
                    index=next((i for i,b in enumerate(candidate['batches']) if b['input_dir']==folder),None)
                    if index is None:candidate['batches'].append(new_slot(candidate['data_dir'],folder));index=len(candidate['batches'])-1
                    candidate['active_batch']=index
                    print('旧工作目录与库中视频保留；新文件夹使用独立工作资料，不重新加密旧视频。')
                    self.save_change(candidate)
                elif choice=='2':
                    source=self.source_select();existing=next((s for s in candidate['sources'] if s['remote']==source['remote']),None)
                    if existing:source=existing
                    else:candidate['sources'].append(source)
                    candidate['active_source']=source['id']
                    print('不会自动删除或搬走旧副本。“添加视频”可复制已登记密文到新来源；“开始观看”只准备权限，不搬运视频。')
                    if self.save_change(candidate):self.configure_website()
                elif choice=='3':
                    candidate['vault_remote']=ask('新公开发布位置',self.s['vault_remote'])
                    candidate['vault_url']=w.public_url(ask('新公开视频库 HTTPS 地址',self.s['vault_url']))
                    if self.save_change(candidate):self.configure_website()
                elif choice=='4':
                    days=ask('观看权限保留多少天（1–7）',str(max(1,presign.duration(self.s['expires'])//86400)))
                    if not days.isdigit() or not 1<=int(days)<=7:raise w.UserError('请选择 1 到 7 天。')
                    candidate['expires']=days+'d';self.save_change(candidate)
                elif choice=='5':
                    candidate['site_url']=w.public_url(ask('网站 HTTPS 地址',self.s['site_url']))
                    repo=w.repository(Path.cwd()) or w.repository(w.ROOT)
                    if repo:
                        _,branch=w.git(repo,['branch','--show-current']);candidate['repo_dir']=str(repo);candidate['deploy_branch']=branch.decode().strip()
                        candidate['deployment_linked']=confirm('确认这个仓库当前分支已关联网站自动部署？')
                    if self.save_change(candidate):self.configure_website()
                elif choice=='6':self.connections()
                elif choice=='7':self.advanced()
                else:print('请选择菜单中的编号。')
            except (ValueError,OSError,vault.InvalidTag) as error:print('操作未完成：'+safe(error))
    def connections(self):
        print('将对已保存的存储、公开视频库和网站发送只读检查；不会修改权限、CORS 或关闭 TLS 验证。')
        if not confirm('开始检查？',True):return
        with self.unlocked() as (store,raw,opened):
            result=w.checks(self.s,opened,raw)
        for status,label in result:print(('✓ ' if status=='通过' else '✗ ' if status=='失败' else '· ')+status+'：'+label)
        if any('跨域' in label and status!='通过' for status,label in result):
            u=w.urlsplit(self.s['site_url']);origin=u.scheme+'://'+u.netloc
            print('可复制的 CORS 配置（请在存储平台设置，CORS 不是身份认证）：')
            print(json.dumps([{'AllowedOrigins':[origin],'AllowedMethods':['GET'],'AllowedHeaders':['Range'],
                              'ExposeHeaders':['Content-Range','Content-Length','Accept-Ranges','Content-Type','Content-Encoding'],'MaxAgeSeconds':3600}],ensure_ascii=False))
    def advanced(self):
        while True:
            print('\n高级选项\n1. 更换主密码\n2. 查看视频\n3. 安全迁移旧视频\n4. 备份保险库\n5. 从备份恢复到新文件\n6. 完整校验本地视频\n7. 查看高级命令帮助\n\n0. 返回')
            choice=ask('请选择','0')
            if choice=='0':return
            try:
                if choice=='1':
                    with self.unlocked() as (store,raw,opened):
                        secret=password(True)
                        try:changed=vault.change_password(opened,secret);newer=vault.unlock(changed,secret);store.commit(changed,previous=raw)
                        finally:secret=None
                        print('✓ 主密码已更换；已有视频和文件密钥不变。旧密码加旧备份仍能恢复旧能力，密码更改不能撤销已泄露的密钥。')
                        if confirm('现在发布新的视频库？',True):
                            library=w.Library(self.s,self.local);library.remember(changed,newer);library.publish(changed,newer)
                elif choice=='2':
                    with self.unlocked() as (store,raw,opened):
                        print(f'共有 {len(opened.data["files"])} 个视频：')
                        for item in opened.data['files']:print(item['id']+'  '+item['name'])
                elif choice=='3':
                    with self.unlocked() as (store,raw,opened):
                        choices=opened.data['files']
                        if not choices:raise w.UserError('视频库为空，尚无旧视频可迁移。')
                        item=choices[choose([f['name'] for f in choices],'选择视频')]
                        cipher=w.absolute(ask('已有加密视频文件的本地路径'))
                        output=self.s['batches'][self.s['active_batch']]['output_dir']
                        print('将验证并复制同一密文，不改密钥，不删除旧文件或旧云对象。')
                        if not confirm('确认迁移？'):continue
                        replacement=batch.migrate(opened,item['id'],cipher,output)
                        if replacement is not None:store.commit(replacement,previous=raw);raw=replacement;opened=vault.open_with_kek(raw,opened.kek)
                        record=next(f for f in opened.data['files'] if f['key']==item['key']);path=Path(output)/record['objectKey']
                        info=vault.verify_video(path,record['key'],details=True);library=w.Library(self.s,self.local)
                        library.state['objects'][record['id']]={'path':str(path),'sha256':info['cipher_sha256'],'stamp':w.file_stamp(path)};library.remember(raw,opened)
                        if confirm('现在上传此视频并准备观看？',True):
                            remote=library.source['remote'];w.upload_object(path,w.object_remote(remote,record['id']),info['cipher_sha256'])
                            library.state['uploads'].setdefault(remote,{})[record['id']]=info['cipher_sha256'];library.save()
                            library.watch(opened,raw,store)
                    print('✓ 迁移步骤已完成，旧路径由你确认新副本可用后再决定是否清理。')
                elif choice=='4':
                    with self.unlocked() as (store,raw,opened):
                        default=Path(self.s['data_dir'])/'backups'/('vault-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'.enc')
                        target=Path(w.absolute(ask('备份保存位置',str(default))))
                        if w.private_path_risk(target):raise w.UserError('备份请放在源码仓库之外。')
                        with batch.directory(target.parent,create=True,private=True),vault.VaultFile(target) as dest:dest.commit(raw)
                    print('✓ 已验证并保存加密备份；没有导出任何明文密钥。')
                elif choice=='5':self.restore()
                elif choice=='6':
                    if not confirm('完整校验会读取本地全部已登记视频，可能耗时较长，继续？'):continue
                    with self.unlocked() as (store,raw,opened):
                        library=w.Library(self.s,self.local);entries,pending=library.records();library.verify_local(entries,True)
                    print('✓ 已完整认证本地已登记副本；不等于真实云副本或浏览器已通过验收。')
                elif choice=='7':print('高级命令仍可直接运行：\npython vault.py --help\npython vault.py presign --help\n详细格式、迁移和安全限制请看 README 与 V3_PRIVATE.md。')
                else:print('请选择菜单中的编号。')
            except (ValueError,OSError,vault.InvalidTag) as error:print('操作未完成：'+safe(error))
    def restore(self):
        source=Path(w.absolute(ask('备份文件路径',self.s['vault_file']+'.bak')))
        backup=w.read_vault(source);opened=vault.unlock(backup,password())
        if opened.meta.vault_id.hex()!=self.s['vault_id']:raise w.UserError('备份属于不同保险库，未替换当前设置。')
        print(f'备份包含 {len(opened.data["files"])} 个视频。可能缺少较新的记录；恢复到新文件，当前库和备份都不覆盖。')
        if not confirm('确认恢复这个经过验证的备份？'):return
        revision=opened.meta.revision
        try:
            current=vault.parse(w.read_vault(self.s['vault_file']))
            if current.vault_id==opened.meta.vault_id:revision=max(revision,current.revision)
        except (ValueError,OSError):print('当前文件无法读取，最新版本未验证；请核对可信备份。')
        if revision>=vault.MAX_REVISION:raise w.UserError('版本已用尽，无法安全恢复。')
        meta=vault.replace(opened.meta,revision=revision+1,data_revision=revision+1,wrap_nonce=vault.nonce(opened.meta.wrap_nonce),data_nonce=vault.nonce(opened.meta.data_nonce))
        data={**opened.data,'revision':revision+1};raw=vault.seal(meta,data,opened.key,opened.kek)
        target=Path(self.s['data_dir'])/('vault-restored-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'.enc')
        with batch.directory(target.parent,create=True,private=True),vault.VaultFile(target) as store:store.commit(raw)
        candidate=copy.deepcopy(self.s);candidate['vault_file']=str(target)
        if self.save_change(candidate):print('✓ 已切换至恢复文件；使用备份时的主密码，选择开始观看可更新授权并发布。')
    def menu(self):
        while True:
            print('\n╭──────────────────────────────╮\n│       SecureS3 视频保险箱     │\n╰──────────────────────────────╯\n\n1. 添加视频\n2. 开始观看\n3. 设置\n\n0. 退出')
            choice=ask('请选择','1')
            if choice=='0':return
            try:
                if choice=='1':self.add()
                elif choice=='2':self.watch()
                elif choice=='3':self.pending=None;self.settings()
                else:print('请选择菜单中的编号。')
            except (ValueError,OSError,vault.InvalidTag) as error:self.pending=None;print('操作未完成：'+safe(error)+'\n已完成的阶段结果安全保留，可重新选择相同功能重试。')


def safe(error):
    if isinstance(error,w.UserError):return str(error)
    return '本地资料、存储或网络检查未完成。没有显示敏感诊断；请检查连接或使用高级完整校验，现有资料未被删除。'


def run():
    if not sys.stdin.isatty():
        print('请在交互式终端运行 python vault.py；SSH 可使用 ssh -t。不会从管道读取主密码。',file=sys.stderr);return 1
    try:
        local=w.LocalStore()
        with local.session():
            app=App(local)
            try:app.s=local.settings();app.path_guards(app.s)
            except FileNotFoundError:app.setup()
            if app.s is not None:
                if not Path(app.s['vault_file']).is_file():print('保存的保险库文件不存在；不会重新初始化。请在设置 → 高级从备份恢复，或检查挂载。')
                app.menu()
        return 0
    except (EOFError,KeyboardInterrupt):print('\n已退出，已完成阶段和原始资料均保留。');return 0
    except (ValueError,OSError,vault.InvalidTag) as error:print('未完成启动：'+safe(error),file=sys.stderr);return 1
    except Exception as error:
        print('发生未预期错误，已停止；现有资料保留，未显示可能含凭据的内部诊断。错误类型：'+type(error).__name__,file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(run())
