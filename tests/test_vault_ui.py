"""Real Chromium Vault + shared player E2E. Only public config and OS picker substituted."""
import base64
import hashlib
import json
from pathlib import Path
import unittest

from test_browser import PlayerFixture
from test_download import PICKER
from test_vault import PASSWORD, NEW_PASSWORD
import vault
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultIntegrationTests(PlayerFixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.full_objects={'library.enc'}
        cls.files=[{'id':'01'*16,'name':'电影 A <safe>.mp4','url':cls.objects+'movie.enc','key':(cls.data/'movie.key').read_text().strip()},
                   {'id':'02'*16,'name':'短片 B.mp4','url':cls.objects+'data.enc','key':(cls.data/'data.key').read_text().strip()}]
        for i in range(2,100):
            cls.files.append({'id':f'{i+1:032x}','name':f'Archive {i:03}.mp4','url':cls.objects+f'future-{i}.enc','key':base64.urlsafe_b64encode(AESGCM.generate_key(256)).decode().rstrip('=')})
        cls.raw=vault.update(vault.unlock(vault.create(PASSWORD),PASSWORD),cls.files)
        cls.vid=vault.parse(cls.raw).vault_id.hex()
        (cls.data/'library.enc').write_bytes(cls.raw)

    def setUp(self):
        super().setUp()
        (self.data/'library.enc').write_bytes(self.raw)
        self.context.add_init_script(PICKER)
        self.config(self.context)
        self.page.reload()

    def config(self,context,url=None):
        config={'vaultUrl':url or self.objects+'library.enc','vaultId':self.vid}
        context.route('**/config.js',lambda route:route.fulfill(status=200,content_type='text/javascript',body='globalThis.SECURES3_CONFIG='+json.dumps(config)+';'))

    def unlock_ui(self,password=PASSWORD):
        self.page.locator('#master-password').fill(password)
        self.page.locator('#unlock-vault').click()
        self.page.wait_for_function("() => !document.querySelector('#unlock-vault').disabled",timeout=45000)

    def row(self,index=0):
        return self.page.locator('.vault-row').filter(has_text=self.files[index]['name'])

    def saved_digest(self):
        return self.page.evaluate('''async()=>{
          const f=await window.savedHandle.getFile();const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',await f.arrayBuffer()));
          return {size:f.size,hash:Array.from(digest,x=>x.toString(16).padStart(2,'0')).join('')};
        }''')

    def test_100_records_play_seek_download_share_incognito_and_lock(self):
        self.unlock_ui()
        self.assertFalse(self.page.locator('#vault-library').is_hidden())
        self.assertEqual(self.page.locator('.vault-row').count(),100)
        self.assertIn('100',self.page.locator('#vault-count').inner_text())
        self.assertEqual(self.page.locator('#master-password').input_value(),'')
        self.assertEqual(self.page.locator('#vault-files img').count(),0)
        self.page.locator('#vault-search').fill('archive 050')
        self.assertEqual(self.page.locator('.vault-row').count(),1)
        self.page.locator('#vault-search').fill('')
        self.row().get_by_role('button',name='播放',exact=True).click()
        self.page.wait_for_function('() => document.querySelector("video").readyState>=1')
        self.page.evaluate('document.querySelector("video").play()')
        self.page.evaluate('document.querySelector("video").currentTime=72')
        self.page.wait_for_function('() => document.querySelector("video").currentTime>72.3 && !document.querySelector("video").seeking')
        virtual=self.virtual()
        self.row().get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-status').textContent==='下载完成'",timeout=45000)
        self.assertEqual(self.virtual(),virtual,'library download must not switch playback')
        with (self.data/'movie.mp4').open('rb') as f:expected=hashlib.file_digest(f,'sha256').hexdigest()
        self.assertEqual(self.saved_digest()['hash'],expected)
        self.context.grant_permissions(['clipboard-read','clipboard-write'])
        self.row().get_by_role('button',name='分享',exact=True).click()
        link=self.page.evaluate('navigator.clipboard.readText()')
        shared=json.loads(base64.urlsafe_b64decode(link.split('#')[1]+'==='))
        self.assertEqual(shared,{'v':1,'url':self.files[0]['url'],'key':self.files[0]['key']})
        vault_key=base64.urlsafe_b64encode(vault.unlock(self.raw,PASSWORD).key).decode().rstrip('=')
        self.assertNotIn(vault_key,json.dumps(shared));self.assertNotIn(self.files[1]['key'],json.dumps(shared))
        friend=self.browser.new_context();self.addCleanup(friend.close);self.config(friend)
        page=friend.new_page();requests=[];page.on('request',lambda r:requests.append(r.url))
        page.goto(link);page.wait_for_function('() => document.querySelector("video").readyState>=1')
        self.assertTrue(page.locator('#vault-panel').is_hidden())
        self.assertFalse(any('library.enc' in url or 'vault-kdf.js' in url or '/vendor/' in url for url in requests))
        page.evaluate('document.querySelector("video").play()')
        page.wait_for_function('() => document.querySelector("video").currentTime>0.2')
        self.page.locator('#lock-vault').click()
        self.assertTrue(self.page.locator('#vault-library').is_hidden())
        self.assertEqual(self.page.locator('.vault-row').count(),0)
        self.assertEqual(self.page.locator('#key').input_value(),'')
        self.assertEqual(self.page.locator('#url').input_value(),'')
        self.assertEqual(self.page.locator('#video').get_attribute('src'),None)
        self.assertNotEqual(self.page.evaluate('async url=>(await fetch(url,{headers:{Range:"bytes=0-15"}})).status',virtual),206)

    def test_refresh_revision_rollback_and_password_change(self):
        self.unlock_ui()
        old=self.raw;opened=vault.unlock(old,PASSWORD)
        extra={'id':'ef'*16,'name':'New item','url':self.objects+'new.enc','key':base64.urlsafe_b64encode(AESGCM.generate_key(256)).decode().rstrip('=')}
        updated=vault.update(opened,[*self.files,extra]);(self.data/'library.enc').write_bytes(updated)
        self.page.locator('#refresh-vault').click()
        self.page.wait_for_function("() => document.querySelectorAll('.vault-row').length===101")
        (self.data/'library.enc').write_bytes(old)
        self.page.locator('#refresh-vault').click()
        self.page.wait_for_function("() => !document.querySelector('#vault-unlock').hidden")
        self.assertIn('回滚',self.page.locator('#vault-status').inner_text())
        self.assertEqual(self.page.locator('.vault-row').count(),0)
        changed=vault.change_password(vault.unlock(updated,PASSWORD),NEW_PASSWORD)
        self.assertEqual(changed[vault.BODY_OFFSET:],updated[vault.BODY_OFFSET:])
        (self.data/'library.enc').write_bytes(changed)
        self.unlock_ui(NEW_PASSWORD)
        self.assertEqual(self.page.locator('.vault-row').count(),101)
        # A second password change forces an already-unlocked reader to enter the new password.
        again=vault.change_password(vault.unlock(changed,NEW_PASSWORD),PASSWORD)
        (self.data/'library.enc').write_bytes(again)
        self.page.locator('#refresh-vault').click()
        self.page.wait_for_function("() => !document.querySelector('#vault-unlock').hidden")
        self.assertEqual(self.page.locator('.vault-row').count(),0)
        self.unlock_ui(PASSWORD)
        self.assertEqual(self.page.locator('.vault-row').count(),101)

    def test_wrong_password_corruption_and_empty_library(self):
        self.unlock_ui('this is the wrong password')
        self.assertTrue(self.page.locator('#vault-library').is_hidden());self.assertEqual(self.page.locator('.vault-row').count(),0)
        damaged=bytearray(self.raw);damaged[-1]^=1;(self.data/'library.enc').write_bytes(damaged)
        self.unlock_ui()
        self.assertTrue(self.page.locator('#vault-library').is_hidden());self.assertEqual(self.page.locator('.vault-row').count(),0)
        empty=vault.update(vault.unlock(self.raw,PASSWORD),[]);(self.data/'library.enc').write_bytes(empty)
        self.page.reload();self.unlock_ui()
        self.assertFalse(self.page.locator('#vault-library').is_hidden());self.assertIn('0',self.page.locator('#vault-count').inner_text())

    def test_secrets_never_enter_http_console_or_browser_storage(self):
        seen=[];self.page.on('console',lambda m:seen.append(m.text));first=len(self.http_requests)
        self.unlock_ui()
        self.row().get_by_role('button',name='播放',exact=True).click()
        self.page.wait_for_function('() => !!document.querySelector("video").src')
        observed=json.dumps(self.http_requests[first:])+json.dumps(seen)
        self.assertNotIn(PASSWORD,observed)
        self.assertTrue(all(f['key'] not in observed for f in self.files))
        self.assertEqual(self.page.evaluate('Object.keys(localStorage).length'),0)
        self.assertEqual(self.page.evaluate('Object.keys(sessionStorage).length'),0)
        self.assertEqual(self.page.evaluate('async()=>await caches.keys()'),[])
        self.assertEqual(self.page.evaluate('async()=>await indexedDB.databases()'),[])

    def test_lock_cancels_file_download_and_keeps_existing_target(self):
        self.unlock_ui()
        self.page.evaluate('''async()=>{
          const root=await navigator.storage.getDirectory(),handle=await root.getFileHandle('saved.mp4',{create:true}),w=await handle.createWritable();await w.write(new TextEncoder().encode('keep original'));await w.close();
          const decrypt=ES3.decryptBlock;ES3.decryptBlock=async(...args)=>{const data=await decrypt(...args);await new Promise(r=>setTimeout(r,120));return data;};
        }''')
        self.row().get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-progress').value>0")
        self.page.locator('#lock-vault').click()
        self.page.wait_for_function("() => document.querySelector('#download-status').textContent.includes('已取消')")
        self.assertEqual(self.saved_digest()['hash'],hashlib.sha256(b'keep original').hexdigest())
        self.assertEqual(self.page.locator('.vault-row').count(),0)

    def test_actual_response_csp_allows_wasm_but_still_blocks_eval(self):
        cls=type(self);cls.strict_headers=True
        try:
            origin=self.host.split('/viewer/')[0]
            self.context.unroute('**/config.js');self.config(self.context,origin+'/objects/library.enc')
            response=self.page.reload();self.assertIn("'wasm-unsafe-eval'",response.headers['content-security-policy'])
            self.unlock_ui();self.assertEqual(self.page.locator('.vault-row').count(),100)
            self.page.evaluate("() => {const s=document.createElement('script');s.src='csp-probe.js';document.head.append(s);}")
            self.page.wait_for_function('() => !!window.cspProbe');self.assertTrue(self.page.evaluate('window.cspProbe.evalBlocked'))
        finally:cls.strict_headers=False

    def test_insecure_context_disables_master_password_unlock(self):
        self.context.add_init_script("Object.defineProperty(window,'isSecureContext',{value:false,configurable:true})")
        self.page.reload()
        self.assertTrue(self.page.locator('#master-password').is_disabled())
        self.assertTrue(self.page.locator('#unlock-vault').is_disabled())
        self.assertIn('HTTPS',self.page.locator('#vault-status').inner_text())

    def test_invalid_fragment_returns_to_locked_vault_mode(self):
        self.page.goto(self.host+'#invalid-not-json')
        self.page.wait_for_function("() => document.querySelector('#status').className==='error'")
        self.assertFalse(self.page.locator('#vault-panel').is_hidden())
        self.assertTrue(self.page.locator('#vault-library').is_hidden())
        self.assertTrue(self.page.locator('#form').is_hidden())
        self.assertEqual(self.page.locator('#key').input_value(),'')
        self.assertNotIn('#',self.page.url)

    def test_lock_while_unlocking_cannot_later_reveal_library(self):
        self.page.locator('#master-password').fill(PASSWORD)
        self.page.locator('#unlock-vault').click()
        self.page.locator('#manual-mode').click()
        self.page.wait_for_timeout(800)
        self.assertTrue(self.page.locator('#vault-panel').is_hidden())
        self.assertEqual(self.page.locator('.vault-row').count(),0)
        self.assertEqual(self.page.locator('#master-password').input_value(),'')
        self.assertEqual(self.page.locator('#key').input_value(),'')

    def test_same_revision_fork_and_wrong_pinned_identity_fail_closed(self):
        self.unlock_ui()
        prior=vault.unlock(self.raw,PASSWORD)
        # A NAS restore/compromised key can create an authenticated fork with the same counter.
        fork=vault.seal(vault.replace(prior.meta,wrap_nonce=vault.nonce(prior.meta.wrap_nonce),data_nonce=vault.nonce(prior.meta.data_nonce)),prior.data,prior.key,prior.kek)
        (self.data/'library.enc').write_bytes(fork)
        self.page.locator('#refresh-vault').click()
        self.page.wait_for_function("() => !document.querySelector('#vault-unlock').hidden")
        self.assertIn('冲突',self.page.locator('#vault-status').inner_text())
        other=vault.create(PASSWORD);(self.data/'library.enc').write_bytes(other)
        self.page.reload();self.unlock_ui()
        self.assertTrue(self.page.locator('#vault-library').is_hidden())
        self.assertIn('ID',self.page.locator('#vault-status').inner_text())

    def test_worker_restart_and_other_tab_isolation_in_vault_mode(self):
        self.unlock_ui();self.row().get_by_role('button',name='播放',exact=True).click()
        self.page.wait_for_function('() => document.querySelector("video").readyState>=1');url=self.virtual()
        other=self.context.new_page();other.goto(self.host)
        self.assertNotEqual(other.evaluate('async u=>(await fetch(u,{headers:{Range:"bytes=0-7"}})).status',url),206)
        cdp=self.context.new_cdp_session(self.page);versions=[]
        cdp.on('ServiceWorker.workerVersionUpdated',lambda e:versions.extend(e['versions']))
        cdp.send('ServiceWorker.enable');self.page.wait_for_timeout(300)
        running=[v for v in versions if v['runningStatus']=='running'];self.assertTrue(running)
        cdp.send('ServiceWorker.stopWorker',{'versionId':running[-1]['versionId']})
        self.assertEqual(self.page.evaluate('async u=>{const r=await fetch(u,{headers:{Range:"bytes=0-7"}});await r.arrayBuffer();return r.status;}',url),206)


if __name__=='__main__':unittest.main()
