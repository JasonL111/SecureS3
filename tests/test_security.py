"""Adversarial regressions: cryptography, filesystem races, browser isolation."""
import base64
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_browser import PlayerFixture, ROOT
sys.path.insert(0,str(ROOT))
import encrypt as enc


class FilesystemSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source.mp4'
        self.output=self.root/'output.enc';self.key=self.root/'output.key'
        self.source.write_bytes(b'A'*(enc.CHUNK+7))

    def test_same_size_source_mutation_fails_and_cleans_outputs(self):
        original=enc.AESGCM.encrypt;once=[False]
        def mutate(cipher,*args):
            result=original(cipher,*args)
            if not once[0]:
                once[0]=True
                with self.source.open('r+b') as f:f.write(b'B');f.flush();os.fsync(f.fileno())
            return result
        with patch.object(enc.AESGCM,'encrypt',mutate),self.assertRaises(OSError):
            enc.encrypt(self.source,self.output,self.key)
        self.assertFalse(self.output.exists());self.assertFalse(self.key.exists())

    def test_failure_cleanup_does_not_delete_replaced_original(self):
        saved=self.root/'saved.enc'
        def replace(*args):
            self.output.rename(saved);self.source.rename(self.output)
            raise OSError('simulated disk failure after directory entry replacement')
        with patch.object(enc.AESGCM,'encrypt',replace),self.assertRaises(OSError):
            enc.encrypt(self.source,self.output,self.key)
        self.assertTrue(self.output.exists(),'cleanup deleted the renamed original video')
        self.assertEqual(self.output.stat().st_size,enc.CHUNK+7)

    def test_hardlinks_and_output_symlinks_never_overwrite_source(self):
        for method in ('hard','symbolic'):
            if method=='hard':os.link(self.source,self.output)
            else:self.output.symlink_to(self.source)
            with self.assertRaises((OSError,ValueError)):enc.encrypt(self.source,self.output,self.key)
            self.assertEqual(self.source.read_bytes(),b'A'*(enc.CHUNK+7));self.output.unlink()

    def test_mutable_shared_output_directory_is_rejected(self):
        shared=self.root/'shared';shared.mkdir(mode=0o777);shared.chmod(0o777)
        with self.assertRaises((OSError,ValueError)):
            enc.encrypt(self.source,shared/'out.enc',self.key)

    def test_renamed_key_is_not_uploadable_ciphertext(self):
        fake=self.root/'private.enc';fake.write_text('A'*43+'\n')
        shim=self.root/'rclone';marker=self.root/'called'
        shim.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\n');shim.chmod(0o700)
        result=subprocess.run(['sh',str(ROOT/'upload.sh'),str(fake),'remote:bucket/file.enc'],env={**os.environ,'PATH':str(self.root)+os.pathsep+os.environ['PATH']},capture_output=True)
        self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists())

    def test_fifo_input_is_rejected_without_waiting_for_a_writer(self):
        self.source.unlink();os.mkfifo(self.source)
        with self.assertRaises(ValueError):enc.encrypt(self.source,self.output,self.key)
        self.assertFalse(self.output.exists());self.assertFalse(self.key.exists())

    def test_key_permissions_with_permissive_umask(self):
        before=os.umask(0)
        try:enc.encrypt(self.source,self.output,self.key)
        finally:os.umask(before)
        self.assertEqual(self.key.stat().st_mode & 0o777,0o600)

    def test_parent_directory_replacement_does_not_redirect_cleanup(self):
        private=self.root/'private';private.mkdir(mode=0o700);moved=self.root/'moved'
        output=private/'out.enc'
        def replace(*args):
            private.rename(moved);private.mkdir(mode=0o700);output.write_bytes(b'replacement must survive')
            raise OSError('simulated parent replacement')
        with patch.object(enc.AESGCM,'encrypt',replace),self.assertRaises(OSError):enc.encrypt(self.source,output,self.key)
        self.assertEqual(output.read_bytes(),b'replacement must survive')
        self.assertFalse((moved/'out.enc').exists());self.assertTrue(self.source.exists())

    def test_gcm_cross_file_swap_tag_header_truncation(self):
        enc.encrypt(self.source,self.output,self.key)
        raw=self.output.read_bytes();header=raw[:48];key=base64.urlsafe_b64decode(self.key.read_text().strip()+'=');aes=AESGCM(key)
        other=self.root/'other.enc';otherkey=self.root/'other.key'
        enc.encrypt(self.source,other,otherkey)
        self.assertNotEqual(self.key.read_text(),otherkey.read_text())
        first=raw[48:48+enc.CHUNK+16]
        def decrypt(h,data,index=0):return aes.decrypt(h[24:32]+struct.pack('>I',index),data,h+struct.pack('>I',index))
        for i in range(48):
            bad=bytearray(header);bad[i]^=1
            with self.subTest(header_byte=i),self.assertRaises(InvalidTag):decrypt(bytes(bad),first)
        for i in (0,len(first)-1):
            bad=bytearray(first);bad[i]^=1
            with self.assertRaises(InvalidTag):decrypt(header,bytes(bad))
        for data in (first[:-1],other.read_bytes()[48:48+enc.CHUNK+16],raw[48+enc.CHUNK+16:]):
            with self.assertRaises(InvalidTag):decrypt(header,data)
        with self.assertRaises(InvalidTag):decrypt(header,first,1)
        with self.assertRaises(InvalidTag):AESGCM(base64.urlsafe_b64decode(otherkey.read_text().strip()+'=')).decrypt(header[24:32]+bytes(4),first,header+bytes(4))


class ProtocolSecurityTests(unittest.TestCase):
    def test_adversarial_protocol_and_worker_harness(self):
        run=subprocess.run(['node','tests/security_protocol.cjs'],cwd=ROOT,capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertIn('tests 14',run.stdout)


class BrowserSecurityTests(PlayerFixture):
    def test_cross_tab_and_non_player_cannot_read_or_close_session(self):
        self.load();url=self.virtual()
        other=self.context.new_page();other.goto(self.host)
        sibling=self.context.new_page();sibling.goto(self.host+'unrelated.html')
        for page in (other,sibling):
            result=page.evaluate('async url=>{const r=await fetch(url,{headers:{Range:"bytes=0-15"}});return {status:r.status,body:await r.text()}}',url)
            self.assertNotEqual(result['status'],206)
            page.evaluate('id=>navigator.serviceWorker.controller.postMessage({type:"close",id})',url.split('/')[-1])
        result=self.request('bytes=0-15');self.assertEqual(result['status'],206)
        self.assertEqual(base64.b64decode(result['body']),self.plain[:16])

    def test_worker_restart_keeps_cross_tab_isolation_and_coalesces_recovery(self):
        self.load();url=self.virtual()
        other=self.context.new_page();other.goto(self.host)
        cdp=self.context.new_cdp_session(self.page);versions=[]
        cdp.on('ServiceWorker.workerVersionUpdated',lambda e:versions.extend(e['versions']))
        cdp.send('ServiceWorker.enable');self.page.wait_for_timeout(300)
        running=[v for v in versions if v['runningStatus']=='running'];self.assertTrue(running)
        cdp.send('ServiceWorker.stopWorker',{'versionId':running[-1]['versionId']})
        status=other.evaluate('async url=>(await fetch(url,{headers:{Range:"bytes=0-15"}})).status',url)
        self.assertNotEqual(status,206)
        statuses=self.page.evaluate('async url=>Promise.all([0,1,2].map(async()=>{const r=await fetch(url,{headers:{Range:"bytes=0-15"}});await r.arrayBuffer();return r.status;}))',url)
        self.assertEqual(statuses,[206]*3)

    def test_pagehide_clears_key_dom_session_and_video(self):
        self.load();url=self.virtual()
        self.page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide'))")
        self.page.wait_for_timeout(100)
        self.assertEqual(self.page.locator('#key').input_value(),'')
        self.assertEqual(self.page.locator('#video').get_attribute('src'),None)
        self.assertTrue(self.page.locator('#download').is_disabled())
        self.assertNotEqual(self.page.evaluate('async url=>(await fetch(url,{headers:{Range:"bytes=0-15"}})).status',url),206)

    def test_share_key_is_absent_from_actual_http_and_console(self):
        key=(self.data/'data.key').read_text().strip();logs=[]
        self.page.on('console',lambda m:logs.append(m.text))
        first=len(self.http_requests)
        data={'v':1,'url':self.objects+'data.enc','key':key}
        fragment=base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
        self.page.goto(self.host+'#'+fragment)
        self.page.wait_for_function("() => !document.querySelector('#download').disabled")
        observed=self.http_requests[first:]
        self.assertTrue(observed)
        self.assertTrue(all(key not in path and fragment not in path and key not in json.dumps(headers) for path,headers in observed),'key leaked into HTTP')
        self.assertTrue(all(key not in text for text in logs),'key leaked into console')

    def test_cross_origin_document_cannot_obtain_plaintext(self):
        self.load();url=self.virtual()
        foreign=self.context.new_page();foreign.goto(self.objects.replace('/objects/','/viewer/'))
        readable=foreign.evaluate("""async url=>{try{const r=await fetch(url,{headers:{Range:'bytes=0-15'}});await r.arrayBuffer();return r.status===206;}catch{return false;}}""",url)
        self.assertFalse(readable)
        self.assertEqual(self.request('bytes=0-15')['status'],206)

    def test_malformed_share_never_echoes_secret_and_is_removed(self):
        marker='AUDIT_PRIVATE_MARKER'
        bad=base64.urlsafe_b64encode((marker+' broken JSON').encode()).decode().rstrip('=')
        self.page.goto(self.host+'#'+bad)
        self.page.wait_for_function("() => document.querySelector('#status').className==='error'")
        self.assertNotIn(marker[:6],self.page.locator('#status').inner_text())
        self.assertNotIn('#',self.page.url)

    def test_hostile_urls_share_json_and_no_dom_xss(self):
        for data in [None,[],{'v':1,'url':'javascript:window.__xss=1','key':'A'*43}, {'v':1,'url':self.objects+'data.enc','key':'<img src=x onerror=window.__xss=1>'},{'v':1,'url':'https://u:p@example.com/file','key':'A'*43}]:
            fragment=base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
            self.page.goto(self.host+'#'+fragment)
            self.page.wait_for_function("() => document.querySelector('#status').className==='error'")
            self.assertFalse(self.page.evaluate('Boolean(window.__xss)'))
            self.assertTrue(self.page.locator('#download').is_disabled())
        self.assertEqual(self.page.evaluate('Object.keys(localStorage).length'),0)
        self.assertEqual(self.page.evaluate('async()=>await caches.keys()'),[])

    def test_document_csp_blocks_inline_and_eval(self):
        self.page.evaluate("""() => {
          const script=document.createElement('script');script.textContent='window.__inline=1';document.head.append(script);
          const probe=document.createElement('script');probe.src='csp-probe.js';document.head.append(probe);
        }""")
        self.page.wait_for_function('() => !!window.cspProbe')
        self.assertEqual(self.page.evaluate('({inline:!!window.__inline,evalBlocked:window.cspProbe.evalBlocked})'),{'inline':False,'evalBlocked':True})

    def test_response_headers_enforce_frame_and_worker_csp(self):
        cls=type(self);cls.strict_headers=True
        try:
            response=self.page.reload()
            headers=response.headers
            self.assertIn("frame-ancestors 'none'",headers['content-security-policy'])
            self.assertEqual(headers['referrer-policy'],'no-referrer')
            self.assertEqual(headers['cross-origin-opener-policy'],'same-origin')
            # A genuine worker script response carries its own CSP; document meta is insufficient.
            allowed=self.page.evaluate("""async url => {
              const reg=await navigator.serviceWorker.register('worker-probe.js',{scope:'./probe/'});
              await new Promise(resolve=>{const check=()=>reg.active?.state==='activated'?resolve():setTimeout(check,10);check();});
              return new Promise(resolve=>{const c=new MessageChannel();c.port1.onmessage=e=>{c.port1.close();resolve(e.data);};reg.active.postMessage({url},[c.port2]);});
            }""",self.objects+'data.enc')
            self.assertFalse(allowed,'worker must block non-self plain HTTP under the actual response CSP')
            self.page.evaluate("""() => {const f=document.createElement('iframe');f.src='./';document.body.append(f);}""")
            self.page.wait_for_timeout(300)
            self.assertTrue(self.page.evaluate("document.querySelector('iframe').contentDocument===null"))
        finally:cls.strict_headers=False


if __name__=='__main__':unittest.main()
