"""Installed rclone against a verified local TLS S3/B2 API, never real accounts."""
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import shutil
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import presign
import vault
from test_presign import PASSWORD, records


@unittest.skipUnless(shutil.which('rclone'),'Installed rclone is required for backend behavior checks')
class RcloneBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.operations=[];cls.private_bucket=True
        now=datetime.now(timezone.utc);key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SecureS3 local test CA')])
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
              .sign(key,hashes.SHA256()))
        cls.ca=cls.root/'ca.pem';cls.ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keyfile=cls.root/'server.key';keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));keyfile.chmod(0o600)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self,data):
                body=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_HEAD(self):
                cls.operations.append(('HEAD',self.path,None))
                self.send_response(200);self.send_header('Content-Length','64');self.send_header('Last-Modified','Thu, 01 Oct 2026 00:00:00 GMT')
                self.send_header('ETag','"'+'0'*32+'"');self.send_header('Content-Type','application/octet-stream');self.end_headers()
            def do_GET(self):
                operation=self.path.rsplit('/',1)[-1];cls.operations.append(('GET',operation,None))
                if operation=='b2_authorize_account':
                    self.reply({'accountId':'test-account','authorizationToken':'TEST_ONLY_ACCOUNT_TOKEN','apiUrl':cls.endpoint,'downloadUrl':cls.endpoint,
                                'recommendedPartSize':100000000,'absoluteMinimumPartSize':5000000,
                                'allowed':{'bucketId':None,'bucketName':None,'namePrefix':None,'capabilities':['listBuckets','listFiles','readFiles','shareFiles']}})
                else:self.send_error(404)
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'));request=json.loads(self.rfile.read(length));operation=self.path.rsplit('/',1)[-1]
                # Store only non-secret target/scope information, not auth headers/tokens.
                cls.operations.append(('POST',operation,{k:request[k] for k in ('fileNamePrefix','validDurationInSeconds','startFileName') if k in request}))
                if operation=='b2_list_buckets':self.reply({'buckets':[{'bucketId':'test-bucket-id','bucketName':'private-bucket','bucketType':'allPrivate' if cls.private_bucket else 'allPublic'}]})
                elif operation in ('b2_list_file_names','b2_list_file_versions'):
                    filename=request.get('startFileName') or request.get('prefix') or 'objects/'+'0'*32+'.enc'
                    self.reply({'files':[{'fileId':'test-file-id','fileName':filename,'accountId':'test-account','bucketId':'test-bucket-id',
                                         'action':'upload','contentLength':64,'size':64,'contentSha1':'0'*40,'contentType':'application/octet-stream',
                                         'fileInfo':{},'uploadTimestamp':1790000000000}],'nextFileName':None,'nextFileId':None})
                elif operation=='b2_get_download_authorization':
                    token='TEST_ONLY_OBJECT_'+hashlib.sha256(request['fileNamePrefix'].encode()).hexdigest()
                    self.reply({'bucketId':'test-bucket-id','fileNamePrefix':request['fileNamePrefix'],'authorizationToken':token})
                else:self.send_error(404)
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.endpoint='https://127.0.0.1:'+str(cls.server.server_port)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cls.ca,keyfile)
        cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()
        config=cls.root/'rclone.conf'
        config.write_text('[secures3tests3]\ntype = s3\nprovider = Cloudflare\naccess_key_id = TESTONLY\nsecret_access_key = NONPRODUCTIONTESTSECRET\nregion = auto\nforce_path_style = true\nno_check_bucket = true\nendpoint = '+cls.endpoint+'\n\n[secures3testb2]\ntype = b2\naccount = test-account\nkey = NONPRODUCTIONTESTSECRET\nendpoint = '+cls.endpoint+'\n')
        config.chmod(0o600);cls.environment=patch.dict(os.environ,{'RCLONE_CONFIG':str(config),'RCLONE_CA_CERT':str(cls.ca),
            'RCLONE_CONFIG_SECURES3TESTS3_ENDPOINT':cls.endpoint,'RCLONE_CONFIG_SECURES3TESTS3_ACCESS_KEY_ID':'TESTONLY',
            'RCLONE_CONFIG_SECURES3TESTS3_SECRET_ACCESS_KEY':'NONPRODUCTIONTESTSECRET','RCLONE_CONFIG_SECURES3TESTS3_ENV_AUTH':'false',
            'RCLONE_CONFIG_SECURES3TESTB2_ENDPOINT':cls.endpoint,'RCLONE_CONFIG_SECURES3TESTB2_ACCOUNT':'test-account',
            'RCLONE_CONFIG_SECURES3TESTB2_KEY':'NONPRODUCTIONTESTSECRET'})
        cls.environment.start();cls.empty=vault.create(PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.environment.stop();cls.server.shutdown();cls.server.server_close();cls.temp.cleanup()

    def setUp(self):type(self).operations=[];type(self).private_bucket=True

    def opened(self):return vault.unlock(vault.update(vault.unlock(self.empty,PASSWORD),records(2)),PASSWORD)

    def test_actual_s3_sigv4_target_expiry_and_range_unsigned(self):
        self.assertEqual(presign.backend('secures3tests3:private-bucket'),'s3')
        raw,report=presign.sign_vault(self.opened(),'r2','secures3tests3:private-bucket','6d')
        self.assertEqual(report['signed'],2)
        data=vault.unlock(raw,PASSWORD).data
        for item in data['files']:
            grant=item['access']['r2'];self.assertTrue(grant['url'].startswith(self.endpoint+'/private-bucket/'+item['objectKey']))
            self.assertIn('X-Amz-Expires=518400',grant['url']);self.assertIn('X-Amz-SignedHeaders=host',grant['url'])
        self.assertTrue(any(m=='HEAD' for m,p,d in self.operations),'NAS rclone checks object metadata before signing GET')

    def test_actual_b2_native_duration_and_full_object_prefix_scope(self):
        self.assertEqual(presign.backend('secures3testb2:private-bucket'),'b2')
        raw,report=presign.sign_vault(self.opened(),'b2','secures3testb2:private-bucket/archive','2h')
        self.assertEqual(report['signed'],2)
        grants=[d for m,p,d in self.operations if p=='b2_get_download_authorization']
        self.assertEqual([d['fileNamePrefix'] for d in grants],['archive/'+f['objectKey'] for f in records(2)])
        self.assertTrue(all(d['validDurationInSeconds']==7200 for d in grants))
        for item in vault.unlock(raw,PASSWORD).data['files']:
            self.assertTrue(item['access']['b2']['url'].startswith(self.endpoint+'/file/private-bucket/archive/'+item['objectKey']+'?Authorization='))

    def test_actual_b2_public_permanent_link_is_rejected(self):
        type(self).private_bucket=False
        with self.assertRaises(vault.VaultError):presign.sign_vault(self.opened(),'b2','secures3testb2:private-bucket','6d')


if __name__=='__main__':unittest.main()
