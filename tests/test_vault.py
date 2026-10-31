"""Vault core, atomic CLI operations and real browser crypto interop."""
import base64
import io
import json
import os
import pty
import select
import time
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_browser import ROOT, PlayerFixture
sys.path.insert(0,str(ROOT))
import vault
from cryptography.exceptions import InvalidTag

PASSWORD = 'A long Unicode 密码 🔐 e\u0301'  # Public test vector; pragma: allowlist secret
NEW_PASSWORD = 'Another long Unicode 密码 🔑'  # Public test vector; pragma: allowlist secret
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')


class VaultCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.empty = vault.create(PASSWORD)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'vault.enc'
        self.path.write_bytes(self.empty)

    def test_create_empty_unicode_password_and_wrong_password(self):
        v=vault.unlock(self.empty,PASSWORD)
        self.assertEqual(v.data['files'],[]);self.assertEqual(len(v.key),32)
        self.assertNotEqual(v.key,bytes(range(32)))
        with self.assertRaises(vault.VaultError):vault.unlock(self.empty,'wrong password')
        with self.assertRaises(vault.VaultError):vault.unlock(self.empty,PASSWORD.replace('e\u0301','é'))

    def test_add_list_remove_and_duplicates(self):
        v=vault.unlock(self.empty,PASSWORD)
        raw=vault.add(v,'电影 "A" <safe>.mp4','https://example.com/电影%20A.enc?x=%26',KEY,'01'*16)
        v=vault.unlock(raw,PASSWORD)
        self.assertEqual(v.meta.revision,2);self.assertEqual(v.data['files'][0]['key'],KEY)
        for kwargs in [dict(record_id='01'*16,key=base64.urlsafe_b64encode(bytes([2])*32).decode().rstrip('='),url='https://example.com/b.enc'),dict(record_id='02'*16,key=KEY,url='https://example.com/b.enc'),dict(record_id='02'*16,key=base64.urlsafe_b64encode(bytes([2])*32).decode().rstrip('='),url=v.data['files'][0]['url'])]:
            with self.assertRaises(vault.VaultError):vault.add(v,'duplicate',**kwargs)
        removed=vault.remove(v,'01'*16);self.assertEqual(vault.unlock(removed,PASSWORD).data['files'],[])
        with self.assertRaises(vault.VaultError):vault.remove(v,'03'*16)

    def test_password_change_only_rewraps_and_advances_envelope_revision(self):
        raw=vault.add(vault.unlock(self.empty,PASSWORD),'movie.mp4','https://example.com/a.enc',KEY)
        before=vault.unlock(raw,PASSWORD);changed=vault.change_password(before,NEW_PASSWORD)
        after=vault.unlock(changed,NEW_PASSWORD)
        self.assertEqual(before.key,after.key);self.assertEqual(before.data,after.data)
        self.assertEqual(raw[vault.BODY_OFFSET:],changed[vault.BODY_OFFSET:])
        self.assertEqual(before.meta.data_nonce,after.meta.data_nonce)
        self.assertNotEqual(before.meta.salt,after.meta.salt)
        self.assertNotEqual(before.meta.wrap_nonce,after.meta.wrap_nonce)
        self.assertEqual(after.meta.revision,before.meta.revision+1)
        self.assertEqual(after.meta.data_revision,before.meta.data_revision)
        with self.assertRaises(vault.VaultError):vault.unlock(changed,PASSWORD)

    def test_every_header_byte_wrapped_key_and_ciphertext_are_authenticated(self):
        good=vault.unlock(self.empty,PASSWORD)
        for i in list(range(128))+[128,150,175,176,len(self.empty)-1]:
            altered=bytearray(self.empty);altered[i]^=1
            with self.subTest(offset=i),self.assertRaises((vault.VaultError,InvalidTag)):
                vault.open_with_kek(bytes(altered),good.kek)
        for raw in (self.empty[:-1],self.empty+b'x',self.empty[:127]):
            with self.assertRaises(vault.VaultError):vault.parse(raw)

    def test_kdf_size_and_schema_bounds_precede_password_work(self):
        for offset,value in [(20,262145),(20,1),(24,1000000),(28,1000)]:
            raw=bytearray(self.empty);struct.pack_into('>I',raw,offset,value)
            with patch.object(vault,'derive',side_effect=AssertionError('KDF must not run')),self.assertRaises(vault.VaultError):vault.unlock(raw,PASSWORD)
        for size in [vault.MAX_FILE+1,0,127]:
            with self.assertRaises(vault.VaultError):vault.parse(bytes(size))
        for text in ['a'*1025,'\ud800','']:
            with self.assertRaises(vault.VaultError):vault.password_bytes(text)
        for url in ['javascript:alert(1)','https://a:b@example.com/x','https://example.com/x#key','http://example.com/x']:
            with self.assertRaises(vault.VaultError):vault.validate_url(url)

    def test_atomic_backup_and_interrupted_replace_recover(self):
        v=vault.unlock(self.empty,PASSWORD);new=vault.add(v,'Movie','https://example.com/a.enc',KEY)
        original_replace=os.replace
        def fail_current(src,dst,**kwargs):
            if dst=='vault.enc':raise OSError('simulated interrupted commit')
            return original_replace(src,dst,**kwargs)
        with vault.VaultFile(self.path) as f:
            with patch.object(vault.os,'replace',side_effect=fail_current),self.assertRaises(OSError):f.commit(new,previous=self.empty)
        self.assertEqual(self.path.read_bytes(),self.empty)
        backup=self.path.with_name('vault.enc.bak');self.assertEqual(backup.read_bytes(),self.empty)
        self.assertEqual(vault.unlock(backup.read_bytes(),PASSWORD).data['files'],[])
        self.assertFalse(list(self.root.glob('*.tmp')))
        with vault.VaultFile(self.path) as f:f.commit(new,previous=self.empty)
        self.assertEqual(self.path.read_bytes(),new);self.assertEqual(backup.read_bytes(),self.empty)
        self.assertEqual(self.path.stat().st_mode&0o777,0o600)
        with vault.VaultFile(self.path) as f:
            with self.assertRaises(vault.VaultError):f.commit(new,previous=b'wrong prior snapshot')

    def test_cli_init_add_list_remove_and_change_no_secret_output(self):
        path=self.root/'cli.enc';keyfile=self.root/'movie.key';keyfile.write_text(KEY+'\n')
        def run(args,passwords):
            out=io.StringIO()
            with patch('vault.prompt',side_effect=passwords),patch('sys.stdout',out):vault.main(args)
            text=out.getvalue();self.assertNotIn(PASSWORD,text);self.assertNotIn(KEY,text);return text
        run(['init','--output',str(path)],[PASSWORD])
        run(['add','--vault',str(path),'--name','Movie','--url','https://example.com/a.enc','--key-file',str(keyfile),'--id','ab'*16],[PASSWORD])
        self.assertEqual(len(json.loads(run(['list','--vault',str(path)],[PASSWORD]))['files']),1)
        run(['change-password','--vault',str(path)],[PASSWORD,NEW_PASSWORD])
        run(['remove','--vault',str(path),'--id','ab'*16],[NEW_PASSWORD])
        self.assertEqual(vault.unlock(path.read_bytes(),NEW_PASSWORD).data['files'],[])
        proc=subprocess.run([sys.executable,str(ROOT/'vault.py'),'init','--output',str(self.root/'pipe.enc')],input=PASSWORD,text=True,capture_output=True)
        self.assertNotEqual(proc.returncode,0);self.assertNotIn(PASSWORD,proc.stdout+proc.stderr)

    def test_limits_nonce_failure_and_missing_files(self):
        v=vault.unlock(self.empty,PASSWORD)
        with patch('vault.os.urandom',return_value=v.meta.wrap_nonce),self.assertRaises(vault.VaultError):vault.nonce(v.meta.wrap_nonce)
        for files in [[{'id':'x','name':'N','url':'https://example.com/a','key':KEY}], [dict(id='01'*16,name='x',url='https://example.com',key=KEY)]*10001]:
            with self.assertRaises(vault.VaultError):vault.update(v,files)
        with vault.VaultFile(self.root/'missing.enc') as f:
            with self.assertRaises(FileNotFoundError):f.read()
        with vault.VaultFile(self.path) as f:
            with self.assertRaises(FileExistsError):f.commit(self.empty)
        self.assertEqual(self.path.read_bytes(),self.empty)

    def test_real_terminal_password_input_does_not_echo(self):
        master,slave=pty.openpty()
        proc=subprocess.Popen([sys.executable,str(ROOT/'vault.py'),'init','--output',str(self.root/'terminal.enc')],stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
        os.close(slave);captured=b'';sent=0;deadline=time.monotonic()+15
        prompts=[b'New master password:',b'Repeat new master password:']
        try:
            while time.monotonic()<deadline:
                readable,_,_=select.select([master],[],[],0.1)
                if readable:
                    try:part=os.read(master,8192)
                    except OSError:break
                    if not part:break
                    captured+=part
                    if sent<2 and prompts[sent] in captured:
                        os.write(master,PASSWORD.encode()+b'\n');sent+=1
                if proc.poll() is not None:break
            proc.wait(timeout=5)
            self.assertEqual(proc.returncode,0)
            self.assertEqual(sent,2)
            self.assertTrue(PASSWORD.encode() not in captured,'terminal echoed the public test password')
            self.assertEqual(vault.unlock((self.root/'terminal.enc').read_bytes(),PASSWORD).data['files'],[])
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
            os.close(master)

    def test_upload_argument_boundaries_and_cache_metadata(self):
        with patch('vault.subprocess.run',return_value=subprocess.CompletedProcess([],0)) as run:
            vault.copy_remote(self.path,'remote:bucket/vault.enc',is_vault=True)
        args=run.call_args.args[0]
        self.assertIn('Cache-Control: no-store',args)
        self.assertEqual(args[-3:],['--',str(self.path),'remote:bucket/vault.enc'])
        self.assertFalse(run.call_args.kwargs.get('shell',False))

    def test_publish_failure_does_not_change_vault_then_retry_upload(self):
        import encrypt
        source=self.root/'movie.mp4';source.write_bytes(b'original video bytes')
        cipher=self.root/'movie.enc';key=self.root/'movie.key'
        args=['publish','--vault',str(self.path),'--input',str(source),'--output',str(cipher),'--key-out',str(key),'--name','Movie','--url','https://example.com/movie.enc','--remote','remote:bucket/movie.enc','--vault-remote','remote:bucket/vault.enc']
        with patch('vault.prompt',return_value=PASSWORD),patch('vault.copy_remote',side_effect=vault.VaultError('upload failed')),self.assertRaises(SystemExit):vault.main(args)
        self.assertEqual(self.path.read_bytes(),self.empty);self.assertTrue(cipher.exists());self.assertTrue(key.exists())
        retry=['publish','--vault',str(self.path),'--cipher',str(cipher),'--key-file',str(key),'--name','Movie','--url','https://example.com/movie.enc','--remote','remote:bucket/movie.enc','--vault-remote','remote:bucket/vault.enc']
        with patch('vault.prompt',return_value=PASSWORD),patch('vault.copy_remote',side_effect=[None,vault.VaultError('vault upload failed')]),self.assertRaises(SystemExit):vault.main(retry)
        updated=self.path.read_bytes();self.assertEqual(len(vault.unlock(updated,PASSWORD).data['files']),1)
        with patch('vault.prompt',return_value=PASSWORD),patch('vault.copy_remote'),patch('sys.stdout',io.StringIO()):vault.main(retry)
        self.assertEqual(self.path.read_bytes(),updated)
        self.assertEqual(source.read_bytes(),b'original video bytes')


class VaultCryptoBrowserTests(PlayerFixture):
    def setUp(self):
        super().setUp()
        self.page.add_script_tag(url=self.host+'vault-crypto.js')

    def test_python_browser_argon2_and_envelope_vectors(self):
        raw=vault.add(vault.unlock(vault.create(PASSWORD),PASSWORD),'中文 <safe>.mp4',self.objects+'movie.enc',KEY)
        expected=vault.unlock(raw,PASSWORD)
        result=self.page.evaluate('''async ({raw,password})=>{
          const bytes=ES3.decode64(raw),state=await ES3VaultCrypto.unlock(bytes,password);
          return {data:state.data,revision:state.meta.revision,extractable:state.kek.extractable};
        }''',{'raw':base64.urlsafe_b64encode(raw).decode().rstrip('='),'password':PASSWORD})
        self.assertEqual(result['data'],expected.data);self.assertFalse(result['extractable'])
        changed=vault.change_password(expected,NEW_PASSWORD)
        result=self.page.evaluate('''async ({raw,password})=>{
          try{await ES3VaultCrypto.unlock(ES3.decode64(raw),password);return true;}catch{return false;}
        }''',{'raw':base64.urlsafe_b64encode(changed).decode().rstrip('='),'password':PASSWORD})
        self.assertFalse(result)
        result=self.page.evaluate('''async ({raw,password})=>(await ES3VaultCrypto.unlock(ES3.decode64(raw),password)).data''',{'raw':base64.urlsafe_b64encode(changed).decode().rstrip('='),'password':NEW_PASSWORD})
        self.assertEqual(result,expected.data)

    def test_browser_rejects_metadata_and_tags_and_vendor_digest(self):
        provenance=json.loads((ROOT/'web/vendor/PROVENANCE.json').read_text())
        self.assertEqual(hashlib.sha256((ROOT/'web/vendor/argon2.umd.min.js').read_bytes()).hexdigest(),provenance['asset_sha256'])
        result=self.page.evaluate("""async({raw,password})=>{
          const bytes=ES3.decode64(raw),state=await ES3VaultCrypto.unlock(bytes,password),results=[];
          for(const offset of [32,48,64,76,88,96,104,127,128,175,176,bytes.length-1]){
            const b=bytes.slice();b[offset]^=1;
            try{await ES3VaultCrypto.open(b,state.kek);results.push(false);}catch{results.push(true);}
          }
          const huge=bytes.slice();new DataView(huge.buffer).setUint32(20,0xffffffff);
          try{ES3VaultCrypto.header(huge);results.push(false);}catch{results.push(true);}
          return results;
        }""",{'raw':base64.urlsafe_b64encode(vault.create(PASSWORD)).decode().rstrip('='),'password':PASSWORD})
        self.assertTrue(all(result))

    def test_argon2_lanes_and_unicode_byte_vector(self):
        salt=bytes(range(16));expected=vault.derive(PASSWORD,salt,65536,3,2)
        # A real Worker performs the WASM KDF; compare by encrypting a fixed test block.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        cipher=AESGCM(expected).encrypt(bytes(12),b'argon2 vector',None)
        result=self.page.evaluate('''async ({password,salt,cipher})=>{
          const key=await ES3VaultCrypto.derive(password,{salt:Uint8Array.from(salt),m:65536,t:3,p:2});
          return Array.from(new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(12)},key,ES3.decode64(cipher))));
        }''',{'password':PASSWORD,'salt':list(salt),'cipher':base64.urlsafe_b64encode(cipher).decode().rstrip('=')})
        self.assertEqual(bytes(result),b'argon2 vector')


if __name__=='__main__':unittest.main()
