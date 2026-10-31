"""Real rclone + verified TLS object store + real terminal process; no real cloud account."""
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import pty
import re
import select
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT=Path(__file__).resolve().parents[1]
PASSWORD='Public V4 terminal password 密码'  # Non-production test vector.


class Store:
    def __init__(self,root):
        self.root=Path(root);self.objects={};self.operations=[];self.fail_video=False;self.fail_public=False
        self.fail_sign=False;self.public_private=False;self.stale_public=None;self.cors=True;self.fail_video_after=None
        self.home=self.root/'config/secures3';self.data=self.root/'data/secures3'
        self.videos=self.root/'videos';self.videos.mkdir();self.cwd=self.root/'work';self.cwd.mkdir()
        for i in range(2):(self.videos/f'电影 {i}.mp4').write_bytes(bytes([i+1])*1024)
        now=datetime.now(timezone.utc);key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SecureS3 V4 test CA')])
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).sign(key,hashes.SHA256()))
        ca=self.root/'ca.pem';ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        tls_key=self.root/'tls.key';tls_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));tls_key.chmod(0o600)
        fixture=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def answer(self,code,body=b'',headers=None):
                self.send_response(code)
                for k,v in (headers or {}).items():self.send_header(k,v)
                if not any(k.lower()=='content-length' for k in (headers or {})):self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                if self.command!='HEAD':
                    try:self.wfile.write(body)
                    except (BrokenPipeError,ConnectionResetError):pass
            def location(self):
                u=urlsplit(self.path);path=u.path
                # Record operation/target only. Never persist query credentials or auth headers.
                fixture.operations.append((self.command,path))
                return u,path
            def allowed(self,u,path):
                if path.startswith('/public-bucket/') or path.startswith('/site/'):return True
                if fixture.public_private:return True
                return self.headers.get('Authorization','').startswith('AWS4-HMAC-SHA256') or bool(parse_qs(u.query).get('X-Amz-Signature'))
            def do_HEAD(self):
                u,path=self.location()
                if not self.allowed(u,path) or (fixture.fail_sign and path.startswith('/private-bucket/')):self.answer(403);return
                if path not in fixture.objects:self.answer(404);return
                body=fixture.objects[path];self.answer(200,b'',{'Content-Length':str(len(body)),'ETag':'"'+hashlib.md5(body).hexdigest()+'"','Last-Modified':'Sat, 31 Oct 2026 00:00:00 GMT'})
            def do_PUT(self):
                u,path=self.location()
                private_count=sum(p.startswith('/private-bucket/') for p in fixture.objects)
                stop_video=fixture.fail_video or (fixture.fail_video_after is not None and private_count>=fixture.fail_video_after)
                if (stop_video and path.startswith('/private-bucket/')) or (fixture.fail_public and path.startswith('/public-bucket/')):
                    self.answer(403);return
                body=self.rfile.read(int(self.headers.get('Content-Length','0')))
                fixture.objects[path]=body;self.answer(200,b'',{'ETag':'"'+hashlib.md5(body).hexdigest()+'"'})
            def do_GET(self):
                u,path=self.location()
                if path.startswith('/site/'):
                    name=path[len('/site/'):]
                    if name=='config.js':file=fixture.home/'web-config.js'
                    elif name=='client.json':file=ROOT/'web/client.json'
                    else:file=ROOT/'web/index.html'
                    if not file.is_file():self.answer(404);return
                    self.answer(200,file.read_bytes(),{'Content-Type':'application/json' if name.endswith('.json') else 'text/javascript'});return
                if not self.allowed(u,path):self.answer(403);return
                if path in ('/private-bucket','/private-bucket/','/public-bucket','/public-bucket/'):
                    bucket=path.strip('/');prefix=parse_qs(u.query).get('prefix',[''])[0]
                    entries=[]
                    for target,data in fixture.objects.items():
                        if target.startswith('/'+bucket+'/'):
                            name=target[len(bucket)+2:]
                            if name.startswith(prefix):entries.append(f'<Contents><Key>{name}</Key><LastModified>2026-10-31T00:00:00.000Z</LastModified><ETag>"{hashlib.md5(data).hexdigest()}"</ETag><Size>{len(data)}</Size><StorageClass>STANDARD</StorageClass></Contents>')
                    body=('<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>'+bucket+'</Name><Prefix>'+prefix+'</Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>'+''.join(entries)+'</ListBucketResult>').encode()
                    self.answer(200,body,{'Content-Type':'application/xml'});return
                if path not in fixture.objects:self.answer(404);return
                body=fixture.stale_public if path.startswith('/public-bucket/') and fixture.stale_public is not None else fixture.objects[path]
                headers={'Content-Type':'application/octet-stream','ETag':'"'+hashlib.md5(body).hexdigest()+'"','Cache-Control':'no-store'}
                if fixture.cors:headers.update({'Access-Control-Allow-Origin':'*','Access-Control-Expose-Headers':'Content-Range,Content-Length,Accept-Ranges','Accept-Ranges':'bytes'})
                value=self.headers.get('Range')
                if value:
                    match=re.fullmatch(r'bytes=(\d+)-(\d+)',value)
                    if not match:self.answer(416);return
                    start,end=map(int,match.groups());end=min(end,len(body)-1)
                    headers['Content-Range']=f'bytes {start}-{end}/{len(body)}';self.answer(206,body[start:end+1],headers)
                else:self.answer(200,body,headers)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.url='https://127.0.0.1:'+str(self.server.server_port)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(ca,tls_key)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        config=self.root/'rclone.conf'
        config.write_text('[v4test]\ntype = s3\nprovider = Cloudflare\nregion = auto\naccess_key_id = TESTONLY\nsecret_access_key = NONPRODUCTIONTESTSECRET\nforce_path_style = true\nno_check_bucket = true\nenv_auth = false\nendpoint = '+self.url+'\n')
        config.chmod(0o600)
        self.env={**os.environ,'XDG_CONFIG_HOME':str(self.root/'config'),'XDG_DATA_HOME':str(self.root/'data'),
                  'RCLONE_CONFIG':str(config),'RCLONE_CA_CERT':str(ca),'SSL_CERT_FILE':str(ca),'SSH_CONNECTION':'v4-test',
                  'RCLONE_CONFIG_V4TEST_ENDPOINT':self.url,'RCLONE_CONFIG_V4TEST_ACCESS_KEY_ID':'TESTONLY',
                  'RCLONE_CONFIG_V4TEST_SECRET_ACCESS_KEY':'NONPRODUCTIONTESTSECRET','RCLONE_CONFIG_V4TEST_ENV_AUTH':'false'}
    def close(self):self.server.shutdown();self.server.server_close()
    def cli(self):return Terminal(self.env,self.cwd)


class Terminal:
    def __init__(self,env,cwd):
        self.master,slave=pty.openpty();self.data=b'';self.cursor=0
        self.process=subprocess.Popen([sys.executable,str(ROOT/'vault.py')],cwd=cwd,env=env,stdin=slave,stdout=slave,stderr=slave)
        os.close(slave)
    def expect(self,text,timeout=40):
        target=text.encode();deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            index=self.data.find(target,self.cursor)
            if index>=0:self.cursor=index+len(target);return
            if select.select([self.master],[],[],0.1)[0]:
                try:chunk=os.read(self.master,65536)
                except OSError:break
                if not chunk:break
                self.data+=chunk
            if self.process.poll() is not None:break
        raise AssertionError('Terminal did not show '+text+'\n'+self.data[-4000:].decode(errors='replace'))
    def send(self,value=''):os.write(self.master,(value+'\n').encode())
    def setup(self,store,add=True,storage_choice=None):
        self.expect('如果已有保险库');self.send()
        if storage_choice is not None:
            self.expect('视频准备存放在哪里');self.expect('请选择 [1]');self.send(storage_choice)
        self.expect('视频的私人 Bucket');self.send('private-bucket')
        self.expect('已确认视频存储');self.send('y')
        self.expect('公开发布位置');self.send('v4test:public-bucket/vault.enc')
        self.expect('稳定 HTTPS');self.send(store.url+'/public-bucket/vault.enc')
        self.expect('播放器网站');self.send(store.url+'/site/')
        self.expect('你的视频文件夹');self.send(str(store.videos))
        self.expect('设置主密码');self.send(PASSWORD);self.expect('再次输入主密码');self.send(PASSWORD)
        self.expect('现在添加视频');self.send('y' if add else 'n')
        if add:self.expect('是否添加这');self.send('y')
    def menu(self):self.expect('请选择 [1]')
    def close(self):
        if self.process.poll() is None:self.process.kill();self.process.wait()
        os.close(self.master)
