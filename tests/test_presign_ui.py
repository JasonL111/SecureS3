"""Real Chromium V3 lifecycle; local Range services require exact synthetic query bytes."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import unittest

from test_browser import PlayerFixture
from test_download import PICKER
from test_vault import PASSWORD
import test_vault_ui as old_ui
import vault
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from encrypt import encrypt


class PresignIntegrationTests(PlayerFixture):
    unlock_ui=old_ui.VaultIntegrationTests.unlock_ui
    saved_digest=old_ui.VaultIntegrationTests.saved_digest

    @classmethod
    def setUpClass(cls):
        super().setUpClass();cls.full_objects={'library.enc'};cls.expected={};cls.reject=False;cls.files=[]
        cls.expires=int(time.time())+3600;date=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        for name,title in [('movie','Movies/私有电影.mp4'),('data','旅行/原始下载.mp4')]:
            with (cls.data/(name+'.enc')).open('rb') as f:file_id=f.read(48)[24:40].hex()
            # The baseline mock uses the basename to read local files; opaque names match the header.
            (cls.data/(file_id+'.enc')).write_bytes((cls.data/(name+'.enc')).read_bytes())
            object_key=vault.object_key(file_id)
            prefix1=cls.host.split('/viewer/')[0]+'/objects/private-r2/'
            q='z=keep%2fcase%2Bplus%20space&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date='+date+'&X-Amz-Expires=3600&X-Amz-Credential=TESTONLY%2f'+date[:8]+'%2fauto%2fs3%2faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature='+hashlib.sha256(file_id.encode()).hexdigest()
            url1=prefix1+object_key+'?'+q
            url2=cls.objects+'private-b2/'+object_key+'?Authorization=TEST_ONLY_OBJECT_'+file_id
            for url in (url1,url2):
                from urllib.parse import urlsplit
                u=urlsplit(url);cls.expected[u.path]=u.query
            cls.files.append({'id':file_id,'name':title,'objectKey':object_key,'key':(cls.data/(name+'.key')).read_text().strip(),
                              'access':{'r2':{'type':'presigned','url':url1,'expiresAt':cls.expires},'b2':{'type':'presigned','url':url2,'expiresAt':cls.expires}}})
        encrypt(cls.data/'original.mp4',cls.data/'legacy-v3.enc',cls.data/'legacy-v3.key')
        cls.files.append({'id':'f0'*16,'name':'Legacy URL','url':cls.objects+'legacy-v3.enc','key':(cls.data/'legacy-v3.key').read_text().strip()})
        cls.raw=vault.update(vault.unlock(vault.create(PASSWORD),PASSWORD),cls.files);cls.vid=vault.parse(cls.raw).vault_id.hex()

    @classmethod
    def range_authorizer(cls,url):
        if '/private-' not in url.path:return True
        return not cls.reject and cls.expected.get(url.path)==url.query

    def setUp(self):
        super().setUp();type(self).reject=False;(self.data/'library.enc').write_bytes(self.raw)
        config={'vaultUrl':self.objects+'library.enc','vaultId':self.vid,
                'storageSources':[{'id':'r2','name':'R2 Private','type':'presigned'},{'id':'b2','name':'B2 Native Private','type':'presigned'},
                                  {'id':'missing','name':'Not signed','type':'presigned'},
                                  {'id':'public','name':'Explicit public replica','baseUrl':self.objects}]}
        self.context.route('**/config.js',lambda r:r.fulfill(status=200,content_type='text/javascript',body='globalThis.SECURES3_CONFIG='+json.dumps(config)+';'))
        self.context.add_init_script(PICKER);self.page.reload()

    def row(self,index=0):return self.page.locator('.vault-row').filter(has_text=Path(self.files[index]['name']).name)

    def play(self,index=0):
        self.row(index).get_by_role('button',name='播放',exact=True).click();self.page.wait_for_function('() => document.querySelector("video").readyState>=1')

    def test_signed_query_play_seek_download_hash_and_get_only(self):
        self.unlock_ui();self.assertEqual(self.page.locator('.vault-row').count(),3)
        self.play();self.page.evaluate('document.querySelector("video").play();document.querySelector("video").currentTime=72')
        self.page.wait_for_function('() => document.querySelector("video").currentTime>72.3 && !document.querySelector("video").seeking')
        self.assertEqual(self.page.locator('#url').input_value(),'');self.assertEqual(self.page.locator('#key').input_value(),'')
        self.assertNotIn('X-Amz',self.page.content());self.assertNotIn('Authorization=',self.virtual())
        result=self.request(method='HEAD');self.assertEqual(result['status'],200)
        self.row(1).get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-status').textContent==='下载完成'",timeout=45000)
        self.assertEqual(self.saved_digest()['hash'],hashlib.sha256(self.plain).hexdigest())
        self.assertFalse(any(method=='HEAD' and '/private-' in p for method,p in self.http_methods))
        private=[p for method,p in self.http_methods if '/private-' in p]
        self.assertTrue(private);self.assertTrue(any('keep%2fcase%2Bplus%20space' in p and 'TESTONLY%2f' in p for p in private))

    def test_private_source_switch_and_single_file_incognito_share(self):
        self.unlock_ui();self.play();old=self.virtual()
        self.page.locator('#storage-source').select_option('b2');self.assertIsNone(self.page.locator('#video').get_attribute('src'))
        self.play();self.assertNotEqual(self.virtual(),old)
        self.context.grant_permissions(['clipboard-read','clipboard-write']);self.row().get_by_role('button',name='分享',exact=True).click()
        link=self.page.evaluate('navigator.clipboard.readText()');shared=json.loads(base64.urlsafe_b64decode(link.split('#')[1]+'==='))
        self.assertEqual(shared,{'v':1,'url':self.files[0]['access']['b2']['url'],'key':self.files[0]['key']})
        self.assertNotIn(self.files[1]['key'],json.dumps(shared));self.assertIn('过期',self.page.locator('#status').inner_text())
        friend=self.browser.new_context();self.addCleanup(friend.close);page=friend.new_page();seen=[];page.on('request',lambda r:seen.append(r.url))
        page.goto(link);page.wait_for_function('() => document.querySelector("video").readyState>=1')
        page.evaluate('document.querySelector("video").play()');page.wait_for_function('() => document.querySelector("video").currentTime>0.2')
        self.assertEqual(page.locator('#url').input_value(),'');self.assertNotIn('TEST_ONLY_OBJECT',page.content())
        self.assertFalse(any('library.enc' in p or 'vault-kdf.js' in p for p in seen))

    def test_missing_and_expired_grants_fail_before_network_or_clipboard(self):
        self.unlock_ui();before=len(self.http_methods);self.page.locator('#storage-source').select_option('missing')
        self.row().get_by_role('button',name='播放',exact=True).click()
        self.assertIn('尚未生成',self.page.locator('#vault-status').inner_text());self.assertEqual(len(self.http_methods),before)
        self.page.locator('#storage-source').select_option('r2')
        self.page.evaluate('expires=>{Date.now=()=>expires*1000+1000;}',self.expires)
        for label in ('播放','下载','分享'):
            self.row().get_by_role('button',name=label,exact=True).click()
            self.assertIn('过期',self.page.locator('#vault-status').inner_text())
        self.assertEqual(len(self.http_methods),before)

    def test_403_before_recorded_expiry_is_access_error_and_does_not_retry(self):
        self.unlock_ui();type(self).reject=True;seen=[];self.page.on('console',lambda m:seen.append(m.text))
        self.row().get_by_role('button',name='播放',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#status').className==='error'")
        text=self.page.locator('#status').inner_text();self.assertIn('403',text);self.assertNotIn('AES-GCM',text)
        self.row(1).get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-status').classList.contains('error')")
        self.assertIn('403',self.page.locator('#download-status').inner_text())
        count=len(self.http_methods);self.page.wait_for_timeout(400);self.assertEqual(count,len(self.http_methods))
        self.assertTrue(all('TEST_ONLY_OBJECT' not in s and 'X-Amz-Signature' not in s for s in seen))

    def test_expired_sigv4_share_is_reported_without_loading_vault(self):
        friend=self.browser.new_context();self.addCleanup(friend.close);page=friend.new_page();page.add_init_script('Date.now=()=>4102444800000')
        seen=[];page.on('request',lambda r:seen.append(r.url))
        data={'v':1,'url':self.files[0]['access']['r2']['url'],'key':self.files[0]['key']}
        fragment=base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
        page.goto(self.host+'#'+fragment)
        page.wait_for_function("() => document.querySelector('#status').className==='error'")
        self.assertIn('过期',page.locator('#status').inner_text());self.assertTrue(page.locator('#vault-panel').is_hidden())
        self.assertFalse(any('library.enc' in p or '/private-' in p for p in seen))

    def test_legacy_url_and_explicit_public_replica_still_play(self):
        self.unlock_ui();self.play(2);self.assertEqual(self.page.locator('#url').input_value(),self.files[2]['url'])
        self.page.locator('#storage-source').select_option('public');self.play()
        self.assertEqual(self.page.locator('#url').input_value(),self.objects+self.files[0]['objectKey'])

    def test_private_worker_restart_expiry_and_other_tab_isolation(self):
        self.unlock_ui();self.play();url=self.virtual()
        other=self.context.new_page();other.goto(self.host)
        self.assertNotEqual(other.evaluate('async u=>(await fetch(u,{headers:{Range:"bytes=0-7"}})).status',url),206)
        cdp=self.context.new_cdp_session(self.page);versions=[]
        cdp.on('ServiceWorker.workerVersionUpdated',lambda e:versions.extend(e['versions']))
        cdp.send('ServiceWorker.enable');self.page.wait_for_timeout(200)
        running=[v for v in versions if v['runningStatus']=='running'];self.assertTrue(running)
        cdp.send('ServiceWorker.stopWorker',{'versionId':running[-1]['versionId']})
        self.assertEqual(self.page.evaluate('async u=>{const r=await fetch(u,{headers:{Range:"bytes=0-7"}});await r.arrayBuffer();return r.status;}',url),206)
        self.page.evaluate("current.expiresAt=Math.floor(Date.now()/1000)-1;navigator.serviceWorker.controller.postMessage({type:'close',id:current.id})")
        self.page.wait_for_timeout(100);before=len(self.http_methods)
        self.assertEqual(self.page.evaluate('async u=>(await fetch(u,{headers:{Range:"bytes=0-7"}})).status',url),502)
        self.assertEqual(len(self.http_methods),before)

    def test_mid_download_expiry_aborts_native_file_and_preserves_existing_target(self):
        self.unlock_ui()
        self.page.evaluate('''async expires=>{
          const root=await navigator.storage.getDirectory(),h=await root.getFileHandle('saved.mp4',{create:true}),w=await h.createWritable();await w.write(new TextEncoder().encode('keep'));await w.close();
          const decrypt=ES3.decryptBlock;let n=0;ES3.decryptBlock=async(...args)=>{const b=await decrypt(...args);if(++n===2)Date.now=()=>expires*1000+1000;return b;};
        }''',self.expires)
        self.row(1).get_by_role('button',name='下载',exact=True).click()
        self.page.wait_for_function("() => document.querySelector('#download-status').classList.contains('error')")
        self.assertIn('过期',self.page.locator('#download-status').inner_text());self.assertEqual(self.saved_digest()['hash'],hashlib.sha256(b'keep').hexdigest())

    def test_python_js_schema_and_canonical_access_order_match(self):
        opened=vault.unlock(self.raw,PASSWORD)
        new=copy.deepcopy(opened.data['files']);new[0]['access']={'z':new[0]['access']['r2'],'A':new[0]['access']['b2'],'a2':new[0]['access']['r2']}
        raw=vault.update(opened,new)
        actual=self.page.evaluate('''async({raw,password})=>(await ES3VaultCrypto.unlock(ES3.decode64(raw),password)).data''',
                                  {'raw':base64.urlsafe_b64encode(raw).decode().rstrip('='),'password':PASSWORD})
        self.assertEqual(actual,vault.unlock(raw,PASSWORD).data)
        data=copy.deepcopy(opened.data);vectors=[]
        for modify in [lambda d:d.update(version=2),lambda d:d['files'][0]['access'].update({'1bad':d['files'][0]['access']['r2']}),
                       lambda d:d['files'][0]['access']['r2'].update(expiresAt=True),lambda d:d['files'][0]['access']['r2'].update(type='public'),
                       lambda d:d['files'][0]['access']['r2'].update(url='javascript:alert(1)'),lambda d:d['files'][0]['access']['r2'].update(url='https://example.invalid/objects/wrong.enc?x=1'),
                       lambda d:d['files'][0]['access']['r2'].update(extra='unknown')]:
            bad=copy.deepcopy(data);modify(bad);vectors.append(bad)
            with self.assertRaises(ValueError):vault.validate_data(bad,bad['revision'])
        result=self.page.evaluate('''values=>values.map(d=>{try{ES3VaultCrypto.validateData(d,d.revision);return false;}catch{return true;}})''',vectors)
        self.assertTrue(all(result))


if __name__=='__main__':unittest.main()
