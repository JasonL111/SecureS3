"""Opaque-object batch, recovery and hostile private-manifest regression tests."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import batch
import encrypt
import vault

PASSWORD = 'Public batch test password 密码'  # Public test vector.


class BatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.empty = vault.create(PASSWORD)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.source = self.root/'videos';self.source.mkdir()
        self.output = self.root/'encrypted';self.private = self.root/'private'
        self.path = self.root/'vault.enc';self.path.write_bytes(self.empty)

    def source_file(self, name='movie.mp4', data=b'original video bytes'):
        path=self.source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);return path

    def run_batch(self, **kwargs):
        with patch('sys.stderr',io.StringIO()):
            return batch.batch_encrypt(self.source,self.output,self.private,**kwargs)

    def manifest(self): return json.loads((self.private/'manifest.json').read_text())

    def write_manifest(self, data): (self.private/'manifest.json').write_text(json.dumps(data),encoding='utf-8')

    def test_names_header_randomness_keys_and_private_manifest(self):
        for name in ['Movies/Avatar.mp4','Series/Avatar.mp4','旅行 空格/片段🎬.MP4','empty.mp4']:
            self.source_file(name,b'' if name=='empty.mp4' else os.urandom(511))
        self.source_file('ignored.txt')
        result=self.run_batch(recursive=True);self.assertEqual(result['encrypted'],4);self.assertEqual(result['errors'],0)
        manifest=self.manifest();self.assertEqual(manifest['version'],2)
        keys=set();ids=set()
        for item in manifest['files']:
            self.assertEqual(item['object_key'],f"objects/{item['id']}.enc")
            cipher=self.output/item['object_key'];key=(self.private/item['key_file']).read_text().strip()
            self.assertEqual(vault.verify_video(cipher,key),item['id'])
            self.assertEqual(cipher.read_bytes()[24:40].hex(),item['id']);ids.add(item['id']);keys.add(key)
            self.assertNotIn(key,json.dumps(manifest));self.assertNotIn('://',json.dumps(manifest))
            self.assertEqual(stat.S_IMODE((self.private/item['key_file']).stat().st_mode),0o600)
            self.assertEqual(hashlib.sha256((self.source/item['name']).read_bytes()).hexdigest(),item['source']['sha256'])
        self.assertEqual(len(ids),4);self.assertEqual(len(keys),4)
        public=[p.relative_to(self.output).as_posix() for p in self.output.rglob('*') if p.is_file()]
        self.assertEqual(sorted(public),sorted(i['object_key'] for i in manifest['files']))
        self.assertEqual(stat.S_IMODE((self.private/'manifest.json').stat().st_mode),0o600)

    def test_dry_run_nonrecursive_and_verified_resume(self):
        self.source_file();self.source_file('nested/movie.mp4')
        dry=self.run_batch(recursive=True,dry_run=True)
        self.assertEqual(dry['scanned'],2);self.assertFalse(self.output.exists());self.assertFalse(self.private.exists())
        self.assertEqual(self.run_batch()['encrypted'],1)
        previous=(self.private/'manifest.json').read_bytes()
        self.assertEqual(self.run_batch()['skipped'],1)
        self.assertEqual((self.private/'manifest.json').read_bytes(),previous)
        self.assertEqual(self.run_batch(recursive=True)['encrypted'],1)
        self.assertNotEqual(*[f['id'] for f in self.manifest()['files']])

    def test_changed_source_never_overwrites_completed_record(self):
        src=self.source_file();self.run_batch();previous=(self.private/'manifest.json').read_bytes()
        src.write_bytes(b'changed original')
        result=self.run_batch();self.assertEqual(result['errors'],1);self.assertEqual(result['skipped'],0)
        self.assertEqual((self.private/'manifest.json').read_bytes(),previous)
        self.assertEqual(src.read_bytes(),b'changed original')
        src.unlink();self.assertEqual(self.run_batch()['errors'],1)
        self.assertEqual((self.private/'manifest.json').read_bytes(),previous)

    def test_reencrypt_same_video_generates_new_id_and_key(self):
        self.source_file();self.run_batch();first=self.manifest()['files'][0]
        other_private=self.root/'private2';other_output=self.root/'encrypted2'
        with patch('sys.stderr',io.StringIO()):batch.batch_encrypt(self.source,other_output,other_private)
        second=json.loads((other_private/'manifest.json').read_text())['files'][0]
        self.assertNotEqual(first['id'],second['id'])
        self.assertNotEqual((self.private/first['key_file']).read_bytes(),(other_private/second['key_file']).read_bytes())

    def test_tamper_truncation_and_wrong_key_cannot_be_skipped_or_imported(self):
        self.source_file(data=os.urandom(encrypt.CHUNK+13));self.run_batch()
        item=self.manifest()['files'][0];cipher=self.output/item['object_key'];original=cipher.read_bytes()
        for raw in (b'',original[:47],original[:-1],original[:60]+bytes([original[60]^1])+original[61:]):
            cipher.write_bytes(raw)
            self.assertEqual(self.run_batch()['errors'],1)
            with self.assertRaises((ValueError,vault.InvalidTag)):
                batch.batch_add(vault.unlock(self.empty,PASSWORD),self.private/'manifest.json')
        cipher.write_bytes(original)
        (self.private/item['key_file']).write_text(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))
        self.assertEqual(self.run_batch()['errors'],1)

    def test_valid_pre_epoch_source_timestamp_can_be_archived_and_resumed(self):
        src=self.source_file();os.utime(src,ns=(-1000000000,-1000000000))
        self.assertEqual(self.run_batch()['encrypted'],1)
        self.assertEqual(self.manifest()['files'][0]['source']['mtime_ns'],-1000000000)
        self.assertEqual(self.run_batch()['skipped'],1)

    def test_source_change_during_encryption_is_not_published(self):
        src=self.source_file();real=encrypt.encrypt
        def change(*args): real(*args);src.write_bytes(b'new contents')
        with patch('batch.encrypt.encrypt',side_effect=change):result=self.run_batch()
        self.assertEqual(result['errors'],1);self.assertEqual(self.manifest()['files'],[])
        self.assertEqual(list((self.output/'objects').iterdir()),[])
        self.assertEqual(list((self.private/'keys').iterdir()),[])

    def test_random_id_collision_and_incomplete_existing_object_fail_closed(self):
        fixed=b'F'*16;real=os.urandom
        with patch('encrypt.os.urandom',side_effect=lambda size:fixed if size==16 else real(size)):
            self.source_file('a.mp4');self.run_batch();item=self.manifest()['files'][0]
            cipher=self.output/item['object_key'];old=cipher.read_bytes()
            self.source_file('b.mp4',b'different video')
            result=self.run_batch();self.assertEqual(result['errors'],1);self.assertEqual(cipher.read_bytes(),old)
            self.assertEqual(len(self.manifest()['files']),1)
        self.source_file('c.mp4')
        fixed=b'X'*16;path=self.output/vault.object_key(fixed.hex());path.write_bytes(b'partial existing object')
        with patch('encrypt.os.urandom',side_effect=lambda size:fixed if size==16 else real(size)):
            result=self.run_batch()
        self.assertGreaterEqual(result['errors'],1);self.assertEqual(path.read_bytes(),b'partial existing object')

    def test_interrupt_before_manifest_commit_recovers_without_reencryption(self):
        self.source_file();real=batch.write_manifest
        with patch('batch.write_manifest',side_effect=OSError('interrupted replace')):
            self.assertEqual(self.run_batch()['errors'],1)
        self.assertEqual(self.manifest()['files'],[]);self.assertTrue((self.private/'.pending.json').exists())
        cipher=next((self.output/'objects').glob('*.enc'));previous=cipher.read_bytes()
        with patch('batch.encrypt.encrypt',side_effect=AssertionError('must recover original ciphertext')):
            result=self.run_batch()
        self.assertEqual(result['recovered'],1);self.assertEqual(result['skipped'],1);self.assertEqual(result['errors'],0)
        self.assertEqual(cipher.read_bytes(),previous);self.assertFalse((self.private/'.pending.json').exists())
        self.assertEqual(json.loads((self.private/'manifest.json.bak').read_text())['files'],[])

    def test_interrupt_after_manifest_commit_is_idempotent_and_orphans_cleaned(self):
        self.source_file();real=os.unlink
        def fail(name,*args,**kwargs):
            if name=='.pending.json':raise OSError('interrupted after manifest')
            return real(name,*args,**kwargs)
        with patch('batch.os.unlink',side_effect=fail):self.assertEqual(self.run_batch()['errors'],1)
        self.assertEqual(len(self.manifest()['files']),1);original=(self.private/'manifest.json').read_bytes()
        self.assertEqual(self.run_batch()['recovered'],1);self.assertEqual((self.private/'manifest.json').read_bytes(),original)
        stage=self.private/'.staging'/('txn-'+'a'*32);stage.mkdir();(stage/'video.key').write_text('partial')
        orphan=self.output/'objects'/('.copy-'+'a'*32+'.tmp');orphan.write_bytes(b'partial ciphertext')
        self.assertEqual(self.run_batch()['skipped'],1);self.assertFalse(stage.exists());self.assertFalse(orphan.exists())

    def test_missing_private_metadata_cannot_silently_initialize_over_old_state(self):
        self.source_file();self.run_batch()
        layout=(self.private/'.batch.json').read_bytes();original=(self.private/'manifest.json').read_bytes()
        (self.private/'.batch.json').unlink()
        with self.assertRaises(vault.VaultError):self.run_batch()
        self.assertFalse((self.private/'.batch.json').exists());self.assertEqual((self.private/'manifest.json').read_bytes(),original)
        (self.private/'.batch.json').write_bytes(layout);(self.private/'manifest.json').unlink()
        with self.assertRaises(vault.VaultError):self.run_batch()
        self.assertFalse((self.private/'manifest.json').exists())
        fresh=self.root/'fresh-private';fresh.mkdir(mode=0o700);out=self.root/'fresh-output'
        (fresh/'.batch.json').write_text(json.dumps({'version':1,'input_dir':str(self.source),'output_dir':str(out)}))
        with patch('sys.stderr',io.StringIO()):result=batch.batch_encrypt(self.source,out,fresh)
        self.assertEqual(result['encrypted'],1,'initialization interrupted before any Manifest or key is safely resumable')

    def test_paths_links_and_overlap_cannot_escape(self):
        self.source_file();outside=self.root/'outside';outside.mkdir();(outside/'other.mp4').write_bytes(b'outside')
        (self.source/'linked').symlink_to(outside,target_is_directory=True)
        (self.source/'bad.mp4').symlink_to(outside/'other.mp4')
        result=self.run_batch(recursive=True);self.assertEqual(result['scanned'],2);self.assertEqual(result['errors'],1)
        self.assertEqual(len(self.manifest()['files']),1)
        for output,private in [(self.source/'out',self.private),(self.output,self.output/'private'),(self.source,self.private)]:
            with self.assertRaises(ValueError):batch.batch_encrypt(self.source,output,private)
        item=self.manifest()['files'][0];key=self.private/item['key_file'];key.unlink();key.symlink_to(outside/'other.mp4')
        with self.assertRaises(OSError):batch.batch_add(vault.unlock(self.empty,PASSWORD),self.private/'manifest.json')
        key.unlink();(self.private/'keys').rmdir();(self.private/'keys').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):batch.batch_add(vault.unlock(self.empty,PASSWORD),self.private/'manifest.json')

    def test_hostile_manifest_cannot_select_system_paths(self):
        self.source_file();self.run_batch();data=self.manifest()
        for field,value in [('key_file','../../etc/passwd'),('object_key','/etc/passwd'),('name','../outside.mp4'),('id','../bad')]:
            altered=json.loads(json.dumps(data));altered['files'][0][field]=value;self.write_manifest(altered)
            with patch('batch.key_text',side_effect=AssertionError('must reject before key reads')):
                with self.assertRaises(ValueError):batch.batch_add(vault.unlock(self.empty,PASSWORD),self.private/'manifest.json')
        self.write_manifest({'version':2,'files':[data['files'][0],data['files'][0]]})
        with self.assertRaises(ValueError):batch.batch_add(vault.unlock(self.empty,PASSWORD),self.private/'manifest.json')
        (self.private/'manifest.json').write_text('{"version":2,"version":2,"files":[]}')
        with self.assertRaises(ValueError):batch.batch_add(vault.unlock(self.empty,PASSWORD),self.private/'manifest.json')

    def test_upload_directory_cannot_mix_private_files_or_follow_links(self):
        self.source_file();self.output.mkdir();secret=self.output/'movie.key';secret.write_text('private sentinel')
        with self.assertRaises(vault.VaultError):self.run_batch()
        self.assertEqual(secret.read_text(),'private sentinel');self.assertFalse((self.private/'manifest.json').exists())
        secret.unlink();self.run_batch();item=self.manifest()['files'][0]
        leaked=self.output/'objects'/'manifest.json';leaked.write_text('private metadata')
        with self.assertRaises(vault.VaultError):self.run_batch()
        with self.assertRaises(vault.VaultError):batch.batch_add(vault.unlock(self.empty,PASSWORD),self.private/'manifest.json')
        leaked.unlink();cipher=self.output/item['object_key'];cipher.unlink();cipher.symlink_to(self.source/'movie.mp4')
        with self.assertRaises(vault.VaultError):self.run_batch()

    def test_batch_add_one_password_atomic_idempotent_and_password_rotation(self):
        self.source_file();self.source_file('folder/电影.mp4');self.run_batch(recursive=True)
        args=['batch-add','--vault',str(self.path),'--manifest',str(self.private/'manifest.json')]
        with patch('vault.prompt',return_value=PASSWORD) as prompt,patch('sys.stdout',io.StringIO()) as output:
            vault.main(args);self.assertEqual(prompt.call_count,1)
        raw=self.path.read_bytes();opened=vault.unlock(raw,PASSWORD)
        self.assertEqual(opened.data['version'],2);self.assertEqual(len(opened.data['files']),2)
        self.assertEqual(self.path.with_name('vault.enc.bak').read_bytes(),self.empty)
        self.assertTrue(all('url' not in f and f['key'] not in output.getvalue() for f in opened.data['files']))
        with patch('vault.prompt',return_value=PASSWORD),patch('sys.stdout',io.StringIO()):vault.main(args)
        self.assertEqual(self.path.read_bytes(),raw)
        changed=vault.change_password(opened,'A new public batch password')
        self.assertEqual(changed[vault.BODY_OFFSET:],raw[vault.BODY_OFFSET:])
        self.assertEqual(vault.unlock(changed,'A new public batch password').data,opened.data)
        bad=self.manifest()['files'][-1];(self.private/bad['key_file']).write_text('x'*43)
        with patch('vault.prompt',return_value=PASSWORD),self.assertRaises(SystemExit):vault.main(args)
        self.assertEqual(self.path.read_bytes(),raw)

    def test_legacy_migration_verifies_real_container_preserves_everything(self):
        src=self.source_file();cipher=self.root/'legacy.enc';keypath=self.root/'legacy.key'
        encrypt.encrypt(src,cipher,keypath);key=keypath.read_text().strip()
        raw=vault.add(vault.unlock(self.empty,PASSWORD),'Movies/原名.mp4','https://old.example/movie.enc',key,'11'*16)
        raw=vault.add(vault.unlock(raw,PASSWORD),'unmapped','https://old.example/unknown.enc',base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='),'22'*16)
        self.path.write_bytes(raw);original=cipher.read_bytes()
        args=['migrate','--vault',str(self.path),'--id','11'*16,'--cipher',str(cipher),'--output-dir',str(self.output)]
        with patch('vault.prompt',return_value=PASSWORD),patch('sys.stdout',io.StringIO()):vault.main(args)
        opened=vault.unlock(self.path.read_bytes(),PASSWORD);record=opened.data['files'][0]
        self.assertEqual(record['id'],original[24:40].hex());self.assertEqual(record['key'],key)
        self.assertEqual((self.output/record['objectKey']).read_bytes(),original);self.assertEqual(cipher.read_bytes(),original)
        self.assertEqual(opened.data['files'][1]['url'],'https://old.example/unknown.enc')
        self.assertEqual(self.path.with_name('vault.enc.bak').read_bytes(),raw)
        self.assertIsNone(batch.migrate(opened,record['id'],cipher,self.output))
        (self.output/record['objectKey']).write_bytes(b'collision')
        with self.assertRaises(ValueError):batch.migrate(opened,record['id'],cipher,self.output)
        wrong=vault.unlock(self.empty,PASSWORD)
        wrong=vault.unlock(vault.add(wrong,'movie','https://x.example/movie.enc',base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='),'33'*16),PASSWORD)
        with self.assertRaises(vault.InvalidTag):batch.migrate(wrong,'33'*16,cipher,self.output)

    def test_500_real_files_import_and_independent_ids(self):
        for i in range(500):self.source_file(f'Folder {i%5}/视频 {i:03}.mp4',f'video {i}'.encode())
        result=self.run_batch(recursive=True);self.assertEqual(result['encrypted'],500);self.assertEqual(result['errors'],0)
        raw=batch.batch_add(vault.unlock(self.empty,PASSWORD),self.private/'manifest.json')
        opened=vault.unlock(raw,PASSWORD)
        self.assertEqual(len(opened.data['files']),500);self.assertEqual(len({f['id'] for f in opened.data['files']}),500)
        self.assertIsNone(batch.batch_add(opened,self.private/'manifest.json'))

    def test_batch_streaming_under_96_mib_address_limit(self):
        self.source_file().unlink()
        with (self.source/'large.mp4').open('wb') as f:f.truncate(128*1024**2+137)
        script="""import resource,sys,json
resource.setrlimit(resource.RLIMIT_AS,(96*1024**2,96*1024**2))
import batch
r=batch.batch_encrypt(*sys.argv[1:]);rss=int(next(s.split()[1] for s in open('/proc/self/status') if s.startswith('VmHWM:')))
print(json.dumps({'result':r,'rss_kib':rss}))
"""
        p=subprocess.run([sys.executable,'-c',script,str(self.source),str(self.output),str(self.private)],cwd=ROOT,capture_output=True,text=True,timeout=180)
        self.assertEqual(p.returncode,0,p.stderr);result=json.loads(p.stdout)
        self.assertEqual(result['result']['encrypted'],1);self.assertEqual(result['result']['errors'],0)
        print('Batch 128 MiB under 96 MiB address limit, peak RSS KiB:',result['rss_kib'])

    @unittest.skipUnless(os.environ.get('SECURES3_LARGE_DOWNLOAD_TEST')=='1','Enable explicit 3 GiB batch test')
    def test_three_gib_batch_under_96_mib_address_limit(self):
        size=3*1024**3+137
        with (self.source/'large.mp4').open('wb') as f:f.truncate(size)
        script="""import resource,sys,json
resource.setrlimit(resource.RLIMIT_AS,(96*1024**2,96*1024**2))
import batch
r=batch.batch_encrypt(*sys.argv[1:]);rss=int(next(s.split()[1] for s in open('/proc/self/status') if s.startswith('VmHWM:')))
print(json.dumps({'result':r,'rss_kib':rss}))
"""
        p=subprocess.run([sys.executable,'-c',script,str(self.source),str(self.output),str(self.private)],cwd=ROOT,capture_output=True,text=True,timeout=240)
        self.assertEqual(p.returncode,0,p.stderr);result=json.loads(p.stdout)
        self.assertEqual(result['result']['encrypted'],1);self.assertEqual(result['result']['errors'],0)
        item=self.manifest()['files'][0]
        self.assertEqual(item['source']['size'],size)
        self.assertEqual((self.output/item['object_key']).stat().st_size,48+size+769*16)
        print('Batch real 3 GiB + 137 bytes under 96 MiB address limit, peak RSS KiB:',result['rss_kib'])


if __name__=='__main__':unittest.main()
