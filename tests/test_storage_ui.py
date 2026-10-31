"""Real Chromium, two independently addressable Range replicas and V2 Vault."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import unittest

from test_browser import PlayerFixture
from test_download import PICKER
from test_vault import PASSWORD
import test_vault_ui as old_ui
import vault
import encrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class StorageIntegrationTests(PlayerFixture):
    unlock_ui = old_ui.VaultIntegrationTests.unlock_ui
    saved_digest = old_ui.VaultIntegrationTests.saved_digest

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.full_objects={'library.enc'}
        cls.r2=cls.data/'r2';cls.b2=cls.data/'b2';cls.r2.mkdir();cls.b2.mkdir()
        cls.object_prefixes={'/objects/r2/':cls.r2,'/objects/b2/':cls.b2}
        cls.files=[]
        for source,name in [('movie','Movies/电影 🎬 A.mp4'),('data','Series/同名 片.mp4')]:
            with (cls.data/(source+'.enc')).open('rb') as f:file_id=f.read(48)[24:40].hex()
            cls.files.append({'id':file_id,'name':name,'objectKey':vault.object_key(file_id),'key':(cls.data/(source+'.key')).read_text().strip()})
        encrypt.encrypt(cls.data/'original.mp4',cls.data/'legacy.enc',cls.data/'legacy.key')
        cls.files.append({'id':'ff'*16,'name':'Old URL.mp4','url':cls.objects+'legacy.enc','key':(cls.data/'legacy.key').read_text().strip()})
        for i in range(497):
            file_id=f'{i+1:032x}'
            cls.files.append({'id':file_id,'name':f'Archive/电影 {i:03}.mp4','objectKey':vault.object_key(file_id),'key':base64.urlsafe_b64encode(AESGCM.generate_key(256)).decode().rstrip('=')})
        cls.raw=vault.update(vault.unlock(vault.create(PASSWORD),PASSWORD),cls.files)
        cls.vid=vault.parse(cls.raw).vault_id.hex()
        first_origin=cls.host.split('/viewer/')[0]
        cls.sources=[{'id':'r2','name':'Cloudflare R2 (local simulator)','baseUrl':first_origin+'/objects/r2/'},
                     {'id':'b2','name':'Backblaze B2 (local simulator)','baseUrl':cls.objects+'b2/'}]

    def config(self,sources=None):
        config={'vaultUrl':self.objects+'library.enc','vaultId':self.vid,'storageSources':self.sources if sources is None else sources}
        self.context.unroute('**/config.js')
        self.context.route('**/config.js',lambda r:r.fulfill(status=200,content_type='text/javascript',body='globalThis.SECURES3_CONFIG='+json.dumps(config)+';'))

    def setUp(self):
        super().setUp()
        (self.data/'library.enc').write_bytes(self.raw)
        for source,item in zip(['movie','data'],self.files):
            for directory in (self.r2,self.b2):shutil.copyfile(self.data/(source+'.enc'),directory/(item['id']+'.enc'))
        self.context.add_init_script(PICKER)
        self.context.add_init_script('''window.pickerNames=[];const originalPicker=window.showSaveFilePicker;
          window.showSaveFilePicker=options=>{window.pickerNames.push(options.suggestedName);return originalPicker(options);};''')
        self.config();self.page.reload()

    def row(self,index=0): return self.page.locator('.vault-row').filter(has_text=Path(self.files[index]['name']).name)

    def play(self,index=0):
        self.row(index).get_by_role('button',name='播放',exact=True).click()
        self.page.wait_for_function('() => document.querySelector("video").readyState>=1')

    def test_500_records_two_sources_play_seek_download_and_incognito_share(self):
        self.unlock_ui();self.assertEqual(self.page.locator('.vault-row').count(),500)
        self.assertIn('Movies',self.page.locator('.vault-folder h3').all_text_contents())
        self.assertEqual(self.page.locator('#storage-source option').count(),2)
        self.page.locator('#vault-search').fill('Series/同名');self.assertEqual(self.page.locator('.vault-row').count(),1)
        self.page.locator('#vault-search').fill('')
        before=len([p for p,h in self.http_requests if 'library.enc' in p or 'vault-kdf.js' in p])
        self.page.locator('#storage-source').select_option('b2');self.play()
        self.assertEqual(self.page.locator('#url').input_value(),self.sources[1]['baseUrl']+self.files[0]['objectKey'])
        self.page.evaluate('document.querySelector("video").play();document.querySelector("video").currentTime=72')
        self.page.wait_for_function('() => document.querySelector("video").currentTime>72.3 && !document.querySelector("video").seeking')
        virtual=self.virtual();self.row(1).get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-status').textContent==='下载完成'",timeout=45000)
        self.assertEqual(self.saved_digest()['hash'],hashlib.sha256(self.plain).hexdigest());self.assertEqual(self.virtual(),virtual)
        self.assertEqual(self.page.evaluate('window.pickerNames.at(-1)'),'同名 片.mp4')
        self.assertEqual(before,len([p for p,h in self.http_requests if 'library.enc' in p or 'vault-kdf.js' in p]))
        self.context.grant_permissions(['clipboard-read','clipboard-write'])
        self.row().get_by_role('button',name='分享',exact=True).click();link=self.page.evaluate('navigator.clipboard.readText()')
        shared=json.loads(base64.urlsafe_b64decode(link.split('#')[1]+'==='))
        self.assertEqual(shared,{'v':1,'url':self.sources[1]['baseUrl']+self.files[0]['objectKey'],'key':self.files[0]['key']})
        self.assertNotIn(self.files[1]['key'],json.dumps(shared))
        friend=self.browser.new_context();self.addCleanup(friend.close);page=friend.new_page();seen=[];page.on('request',lambda r:seen.append(r.url))
        page.goto(link);page.wait_for_function('() => document.querySelector("video").readyState>=1')
        page.evaluate('document.querySelector("video").play()');page.wait_for_function('() => document.querySelector("video").currentTime>0.2')
        self.assertTrue(page.locator('#vault-panel').is_hidden());self.assertFalse(any('library.enc' in p or 'vault-kdf.js' in p for p in seen))
        self.play(2);self.assertEqual(self.page.locator('#url').input_value(),self.files[2]['url'])

    def test_source_switch_cancels_active_download_without_refetch_or_key_mix(self):
        self.unlock_ui();self.play()
        self.page.evaluate('''async()=>{
          const root=await navigator.storage.getDirectory(),handle=await root.getFileHandle('saved.mp4',{create:true}),w=await handle.createWritable();await w.write(new TextEncoder().encode('keep'));await w.close();
          const decrypt=ES3.decryptBlock;ES3.decryptBlock=async(...args)=>{const b=await decrypt(...args);await new Promise(r=>setTimeout(r,300));return b;};
        }''')
        self.row(1).get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-progress').value>0")
        before=len(self.http_requests);self.page.locator('#storage-source').select_option('b2')
        self.page.wait_for_function("() => document.querySelector('#download-status').textContent.includes('已取消')")
        self.assertEqual(self.saved_digest()['hash'],hashlib.sha256(b'keep').hexdigest())
        self.assertIsNone(self.page.locator('#video').get_attribute('src'))
        self.assertFalse(self.page.locator('#vault-library').is_hidden());self.assertEqual(self.page.locator('.vault-row').count(),500)
        self.assertFalse(any('library.enc' in p or 'vault-kdf.js' in p for p,h in self.http_requests[before:]))
        self.play();self.assertIn('/objects/b2/',self.page.locator('#url').input_value())

    def test_missing_or_corrupt_replica_fails_without_guessing_or_fallback(self):
        self.unlock_ui();path=self.b2/(self.files[0]['id']+'.enc');path.unlink()
        self.page.locator('#storage-source').select_option('b2');first=len(self.http_requests)
        self.row().get_by_role('button',name='播放',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#status').className==='error'")
        self.assertEqual(self.page.locator('.vault-row').count(),500)
        self.assertFalse(any('/objects/r2/' in p for p,h in self.http_requests[first:]))
        shutil.copyfile(self.data/'movie.enc',path)
        with path.open('r+b') as f:f.seek(50);value=f.read(1);f.seek(50);f.write(bytes([value[0]^1]))
        self.row().get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-status').classList.contains('error')")
        self.assertNotEqual(self.page.locator('#download-status').inner_text(),'下载完成')
        self.assertFalse(any('/objects/r2/' in p for p,h in self.http_requests[first:]))
        self.page.locator('#storage-source').select_option('r2');self.play()

    def test_authenticated_container_id_mismatch_is_rejected_for_play_and_download(self):
        fake='ab'*16;files=json.loads(json.dumps(self.files));files[0]['id']=fake;files[0]['objectKey']=vault.object_key(fake)
        raw=vault.update(vault.unlock(self.raw,PASSWORD),files);(self.data/'library.enc').write_bytes(raw)
        shutil.copyfile(self.data/'movie.enc',self.r2/(fake+'.enc'));self.page.reload();self.unlock_ui()
        self.row().get_by_role('button',name='播放',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#status').className==='error'")
        self.assertIn('Object ID',self.page.locator('#status').inner_text());self.assertIsNone(self.page.locator('#video').get_attribute('src'))
        self.row().get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-status').classList.contains('error')")
        self.assertIn('Object ID',self.page.locator('#download-status').inner_text())

    def test_url_join_encoding_and_hostile_source_or_schema_vectors(self):
        result=self.page.evaluate('''() => {
          const C=ES3VaultCrypto,id='a'.repeat(32),f={id,objectKey:C.objectKey(id)},valid=[],bad=[];
          for(const baseUrl of ['https://r2.example/','https://b2.example/file/bucket','https://example.com/旅行%20目录/']){
            const source=C.storageSources([{id:'s',name:'Source',baseUrl}])[0];valid.push(C.resolveObject(f,source));
          }
          for(const baseUrl of ['javascript:alert(1)','http://example.com/','https://user:pass@example.com/','https://example.com/?token=x','https://example.com/#fragment','https://example.com/a/../','https://example.com/%2e%2e/','https://example.com/%2f/','https://example.com/%5c/','https://example.com/%00/','https://example.com/%zz/']){
            try{C.storageSources([{id:'s',name:'Source',baseUrl}]);bad.push(false);}catch{bad.push(true);}
          }
          for(const objectKey of ['../a.enc','/objects/a.enc','objects/'+id+'.enc?x=1','https://evil.example/a.enc']){
            try{C.resolveObject({id,objectKey},{id:'s',name:'Source',baseUrl:'https://example.com/'});bad.push(false);}catch{bad.push(true);}
          }
          return {valid,bad};
        }''')
        self.assertTrue(all(result['bad']));self.assertEqual(result['valid'][1],'https://b2.example/file/bucket/objects/'+'a'*32+'.enc')
        self.assertEqual(result['valid'][2],'https://example.com/%E6%97%85%E8%A1%8C%20%E7%9B%AE%E5%BD%95/objects/'+'a'*32+'.enc')

    def test_unconfigured_or_invalid_sources_keep_legacy_records_available(self):
        for sources in ([],[{'id':'evil','name':'bad','baseUrl':'javascript:alert(1)'}]):
            self.config(sources);self.page.reload();self.unlock_ui()
            self.assertTrue(self.row().get_by_role('button',name='播放',exact=True).is_disabled())
            self.assertTrue(self.row().get_by_role('button',name='下载',exact=True).is_disabled())
            self.assertIn('配置',self.page.locator('#storage-note').inner_text())
            self.play(2);self.assertEqual(self.page.locator('#url').input_value(),self.files[2]['url'])


if __name__=='__main__':unittest.main()
