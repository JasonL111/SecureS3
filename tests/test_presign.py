"""Presign CLI transaction, subprocess bounds and V3 directory regression."""
import base64
import copy
import io
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import presign
import vault
import batch

PASSWORD='Public V3 test password 密码'  # Non-production test vector.


def records(count):
    return [{'id':f'{i+1:032x}','name':f'Movies/电影 {i}.mp4','objectKey':vault.object_key(f'{i+1:032x}'),
             'key':base64.urlsafe_b64encode(i.to_bytes(32,'big')).decode().rstrip('=')} for i in range(count)]


class PresignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.empty=vault.create(PASSWORD)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.path=self.root/'vault.enc';self.state=self.root/'stub.json';self.state.write_text('{}');self.state.chmod(0o600)
        binary=self.root/'rclone';binary.write_text('#!'+sys.executable+'\nimport runpy\nrunpy.run_path('+repr(str(ROOT/'tests/rclone_stub.py'))+',run_name="__main__")\n');binary.chmod(0o700)
        self.environment=patch.dict(os.environ,{'PATH':str(self.root)+os.pathsep+os.environ['PATH'],'SECURES3_TEST_RCLONE_STATE':str(self.state)})
        self.environment.start();self.addCleanup(self.environment.stop)
        self.files=records(10);self.raw=vault.update(vault.unlock(self.empty,PASSWORD),self.files);self.path.write_bytes(self.raw)

    def config(self,**kwargs):self.state.write_text(json.dumps(kwargs))
    def calls(self):return [json.loads(line) for line in self.state.with_suffix('.calls').read_text().splitlines()]
    def cli(self,*extra):
        args=['presign','--vault',str(self.path),'--source','r2','--remote','r2:private-bucket','--expires','6d',*extra]
        with patch('vault.prompt',return_value=PASSWORD) as prompt,patch('sys.stdout',io.StringIO()) as out:
            vault.main(args)
        self.assertEqual(prompt.call_count,1);return json.loads(out.getvalue())

    def test_10_objects_atomic_backup_identity_and_password_rotation(self):
        before=vault.unlock(self.raw,PASSWORD);report=self.cli()
        current=self.path.read_bytes();after=vault.unlock(current,PASSWORD)
        self.assertEqual(after.key,before.key);self.assertEqual(after.meta.vault_id,before.meta.vault_id)
        self.assertEqual(after.data['version'],3);self.assertEqual(report['signed'],10);self.assertFalse(report['published'])
        self.assertEqual(self.path.with_name('vault.enc.bak').read_bytes(),self.raw)
        self.assertEqual([{k:v for k,v in f.items() if k!='access'} for f in after.data['files']],self.files)
        self.assertNotIn('X-Amz',json.dumps(report));self.assertNotIn('https://',json.dumps(report))
        links=[c['args'] for c in self.calls() if c['command']=='link'];self.assertEqual(len(links),10)
        self.assertTrue(all(a[-2]=='--' and a[-1]=='r2:private-bucket/'+f['objectKey'] for a,f in zip(links,self.files)))
        changed=vault.change_password(after,'Another public V3 password')
        self.assertEqual(changed[vault.BODY_OFFSET:],current[vault.BODY_OFFSET:])
        self.assertEqual(vault.unlock(changed,'Another public V3 password').data,after.data)

    def test_actual_cli_terminal_prompts_once_and_does_not_echo_secrets(self):
        master,slave=pty.openpty()
        proc=subprocess.Popen([sys.executable,'vault.py','presign','--vault',str(self.path),'--source','r2','--remote','r2:private-bucket','--expires','6d'],
                              cwd=ROOT,stdin=slave,stdout=slave,stderr=slave)
        os.close(slave);captured=b'';sent=False;deadline=time.monotonic()+30
        try:
            while time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]:
                    try:chunk=os.read(master,16384)
                    except OSError:break
                    if not chunk:break
                    captured+=chunk
                    if not sent and b'Master password:' in captured:
                        os.write(master,(PASSWORD+'\n').encode());sent=True
                if proc.poll() is not None and not select.select([master],[],[],0)[0]:break
            self.assertEqual(proc.wait(timeout=5),0,captured.decode(errors='replace'))
            self.assertEqual(captured.count(b'Master password:'),1);self.assertNotIn(PASSWORD.encode(),captured)
            self.assertNotIn(b'X-Amz-Signature',captured);self.assertTrue(all(f['key'].encode() not in captured for f in self.files))
            self.assertEqual(vault.unlock(self.path.read_bytes(),PASSWORD).data['version'],3)
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
            os.close(master)

    def test_500_objects_and_repeated_signing_do_not_duplicate(self):
        self.files=records(500);self.raw=vault.update(vault.unlock(self.empty,PASSWORD),self.files);self.path.write_bytes(self.raw)
        report=self.cli();self.assertEqual(report['signed'],500)
        print('500 synthetic signed objects, directory bytes:',report['directory_bytes'])
        opened=vault.unlock(self.path.read_bytes(),PASSWORD);self.assertLess(report['directory_bytes'],vault.MAX_DATA)
        self.assertEqual(len(opened.data['files']),500)
        # Repeat a smaller but fully authenticated catalog, checking the same long-term identity.
        self.path.write_bytes(vault.update(opened,opened.data['files'][:10]));self.cli()
        again=vault.unlock(self.path.read_bytes(),PASSWORD)
        self.assertEqual(len(again.data['files']),10);self.assertEqual([f['id'] for f in again.data['files']],[f['id'] for f in self.files[:10]])

    def test_multiple_sources_preserve_previous_grants_and_legacy_url(self):
        extra={'id':'ff'*16,'name':'legacy','url':'https://public.example.invalid/old.enc','key':base64.urlsafe_b64encode(bytes([254])*32).decode().rstrip('=')}
        self.raw=vault.update(vault.unlock(self.raw,PASSWORD),[*self.files,extra]);self.path.write_bytes(self.raw)
        first=self.cli();r2=copy.deepcopy(vault.unlock(self.path.read_bytes(),PASSWORD).data)
        with patch('vault.prompt',return_value=PASSWORD),patch('sys.stdout',io.StringIO()):
            vault.main(['presign','--vault',str(self.path),'--source','b2','--remote','b2:private-bucket','--expires','6d'])
        data=vault.unlock(self.path.read_bytes(),PASSWORD).data
        self.assertEqual(data['files'][-1],extra);self.assertEqual(first['legacy_skipped'],1)
        for old,new in zip(r2['files'][:-1],data['files'][:-1]):
            self.assertEqual(new['access']['r2'],old['access']['r2']);self.assertIn('b2',new['access'])
        native=[c['args'] for c in self.calls() if c['command']=='link' and c['args'][-1].startswith('b2:')]
        self.assertTrue(all(a[a.index('--b2-download-auth-duration')+1]=='518400s' for a in native))

    def test_dry_run_generates_no_links_and_does_not_publish(self):
        report=self.cli('--dry-run','--publish','--vault-remote','public:public-bucket/vault.enc')
        self.assertTrue(report['dry_run']);self.assertEqual(report['signed'],0);self.assertEqual(len(report['files']),10)
        self.assertEqual(self.path.read_bytes(),self.raw);self.assertFalse(self.path.with_name('vault.enc.bak').exists())
        self.assertEqual([c['command'] for c in self.calls()],['version','listremotes'])

    def test_batch_reimport_and_idempotent_migration_preserve_access(self):
        source=self.root/'videos';source.mkdir();(source/'movie.mp4').write_bytes(b'original test bytes')
        output,private=self.root/'encrypted',self.root/'private'
        with patch('sys.stderr',io.StringIO()):batch.batch_encrypt(source,output,private)
        original=batch.batch_add(vault.unlock(self.empty,PASSWORD),private/'manifest.json')
        signed,_=presign.sign_vault(vault.unlock(original,PASSWORD),'r2','r2:private-bucket')
        opened=vault.unlock(signed,PASSWORD);item=opened.data['files'][0]
        self.assertIsNone(batch.batch_add(opened,private/'manifest.json'))
        self.assertIsNone(batch.migrate(opened,item['id'],output/item['objectKey'],output))

    def test_287th_failure_preserves_old_vault_and_no_partial_upload_or_url_log(self):
        self.files=records(500);self.raw=vault.update(vault.unlock(self.empty,PASSWORD),self.files);self.path.write_bytes(self.raw)
        self.config(mode='fail',failure_id=self.files[286]['id'])
        with patch('sys.stderr',io.StringIO()) as err,self.assertRaises(SystemExit):
            self.cli('--publish','--vault-remote','public:public-bucket/vault.enc')
        self.assertEqual(self.path.read_bytes(),self.raw);self.assertFalse(self.path.with_name('vault.enc.bak').exists())
        self.assertNotIn('copyto',[c['command'] for c in self.calls()]);self.assertNotIn('X-Amz',err.getvalue())
        self.assertNotIn('TEST_ONLY_SENSITIVE',err.getvalue());self.assertIn(self.files[286]['id'],err.getvalue())

    def test_publish_failure_keeps_new_vault_and_upload_retry_does_not_sign(self):
        self.config(upload_fail=True)
        with patch('sys.stderr',io.StringIO()) as err,self.assertRaises(SystemExit):self.cli('--publish','--vault-remote','public:public-bucket/vault.enc')
        updated=self.path.read_bytes();self.assertNotEqual(updated,self.raw);self.assertIn('Retry vault.py upload',err.getvalue())
        self.config();count=len([c for c in self.calls() if c['command']=='link'])
        with patch('vault.prompt',return_value=PASSWORD),patch('sys.stdout',io.StringIO()):
            vault.main(['upload','--vault',str(self.path),'--remote','public:public-bucket/vault.enc'])
        self.assertEqual(len([c for c in self.calls() if c['command']=='link']),count);self.assertEqual(self.path.read_bytes(),updated)
        report=self.cli('--publish','--vault-remote','public:public-bucket/vault.enc');self.assertTrue(report['published'])

    def test_untrusted_link_shapes_are_rejected_without_secret_diagnostics(self):
        for mode in ('http','wrong_object','wrong_bucket','permanent','long','fragment','duplicate','bad_encoding','ttl','signed_range','stale_date','multiline','wrong_origin'):
            self.config(mode=mode);self.path.write_bytes(self.raw)
            with self.subTest(mode=mode),patch('sys.stderr',io.StringIO()) as err,self.assertRaises(SystemExit):self.cli()
            self.assertEqual(self.path.read_bytes(),self.raw);self.assertNotIn('https://',err.getvalue());self.assertNotIn('X-Amz',err.getvalue())

    def test_wrong_remote_source_expiry_and_publication_destination_rejected(self):
        for source,remote,expires,publish,destination in [
            ('r2','--evil','6d',False,None),('1bad','r2:private-bucket','6d',False,None),('r2','r2:bucket/../x','6d',False,None),
            ('r2','r2:bucket','8d',False,None),('r2','r2:bucket','0s',False,None),('r2','r2:bucket','6d',True,None),
            ('r2','r2:bucket','6d',True,'r2:bucket/vault.enc')]:
            with self.subTest(remote=remote),self.assertRaises(vault.VaultError):presign.validate_options(source,remote,expires,publish,destination)
        for remote in ('missing:bucket','unsupported:bucket'):
            with self.assertRaises(vault.VaultError):presign.sign_vault(vault.unlock(self.raw,PASSWORD),'r2',remote)
        with self.assertRaises(vault.VaultError):presign.duration('6d;touch x')

    def test_real_4_mib_limit_rejects_growth_before_commit(self):
        files=records(10);revision=2
        data={'version':2,'revision':revision,'files':files}
        # Fill with legitimate long legacy URLs; their keys are unique and no secrets are real.
        while True:
            i=len(files);key=base64.urlsafe_b64encode((10000+i).to_bytes(32,'big')).decode().rstrip('=')
            item={'id':f'{10000+i:032x}','name':'legacy','url':'https://example.invalid/'+str(i)+'/'+'x'*8100,'key':key}
            trial={**data,'files':[*files,item]}
            try:raw=vault.encode_data(trial)
            except vault.VaultError:break
            files.append(item)
        used=len(vault.encode_data(data));remaining=vault.MAX_DATA-200-used
        extra={'id':'fe'*16,'name':'padding','url':'https://example.invalid/pad/',
               'key':base64.urlsafe_b64encode(bytes([253])*32).decode().rstrip('=')}
        cost=presign.record_size(extra)+1
        if remaining>=cost:
            extra['url']+='x'*(remaining-cost);files.append(extra)
        elif remaining>0:files[-1]['name']+='x'*remaining
        self.assertLessEqual(len(files[-1]['url']),8192)
        self.raw=vault.update(vault.unlock(self.empty,PASSWORD),files);self.path.write_bytes(self.raw)
        with patch('sys.stderr',io.StringIO()) as err,self.assertRaises(SystemExit):self.cli()
        self.assertIn('4 MiB',err.getvalue());self.assertEqual(self.path.read_bytes(),self.raw)

    def test_bounded_process_timeout_flood_and_debug_env(self):
        for mode in ('stdout_flood','stderr_flood','sleep'):
            self.config(mode=mode)
            with self.subTest(mode=mode),self.assertRaises(vault.VaultError):
                presign.run_rclone(['link','--expire','60s','--','r2:private-bucket/'+self.files[0]['objectKey']],timeout=0.3,stdout_limit=1024,stderr_limit=1024)
        leak=self.root/'forbidden-debug.log';self.config()
        with patch.dict(os.environ,{'RCLONE_LOG_FILE':str(leak),'RCLONE_DUMP':'auth','RCLONE_RC':'true'}):self.cli()
        self.assertFalse(leak.exists());self.assertTrue(all('--rc=false' in c['args'] for c in self.calls()))
        self.assertTrue(all(not c['unsafe_debug_env'] for c in self.calls()))


if __name__=='__main__':unittest.main()
