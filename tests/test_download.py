"""Use a real native FileSystemWritableFileStream in headless Chromium.
Only the OS picker is replaced with a temporary OPFS handle; no Blob download.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
import unittest

from test_browser import PlayerFixture
from encrypt import encrypt, CHUNK

PICKER = '''
Object.defineProperty(window, 'showSaveFilePicker', {configurable:true, value:async options => {
  window.pickerOptions = options;
  const root = await navigator.storage.getDirectory();
  window.savedHandle = await root.getFileHandle('saved.mp4', {create:true});
  return window.savedHandle;
}});
'''


class DownloadTests(PlayerFixture):
    def setUp(self):
        super().setUp()
        self.context.add_init_script(PICKER)
        self.page.reload()

    def start_download(self):
        self.page.locator('#download').click()

    def wait_download(self):
        self.page.wait_for_function("() => document.querySelector('#cancel-download').disabled && !document.querySelector('#download').disabled", timeout=180000)
        return self.page.locator('#download-status').inner_text()

    def file_info(self):
        # Whole-file hashing is restricted to small test fixtures, not the downloader.
        return self.page.evaluate('''async () => {
          const root = await navigator.storage.getDirectory();
          const handle = await root.getFileHandle('saved.mp4'); const f = await handle.getFile();
          const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', await f.arrayBuffer()));
          return {size:f.size, hash:Array.from(hash,x=>x.toString(16).padStart(2,'0')).join('')};
        }''')

    def seed_target(self):
        self.page.evaluate('''async () => {
          const root = await navigator.storage.getDirectory();
          const handle = await root.getFileHandle('saved.mp4', {create:true});
          const writer = await handle.createWritable(); await writer.write(new TextEncoder().encode('existing file')); await writer.close();
        }''')

    def assert_target_preserved(self):
        self.assertEqual(self.file_info(), {'size':13, 'hash':hashlib.sha256(b'existing file').hexdigest()})

    def test_small_empty_and_non_aligned_download_sha256(self):
        for name, data in [('small', b'a small original MP4 byte sequence'), ('nothing', b''), ('data', self.plain)]:
            with self.subTest(name=name):
                if name != 'data':
                    (self.data / f'{name}.mp4').write_bytes(data)
                    encrypt(self.data / f'{name}.mp4', self.data / f'{name}.enc', self.data / f'{name}.key')
                self.load(name); self.start_download()
                self.assertEqual(self.wait_download(), '下载完成')
                self.assertEqual(self.file_info(), {'size':len(data), 'hash':hashlib.sha256(data).hexdigest()})
                self.assertEqual(self.page.locator('#download-progress').get_attribute('value'), '100')

    def test_progress_backpressure_and_filename(self):
        self.load()
        self.page.evaluate('''() => {
          // Observe actual disk writes and check that the next block waits.
          const nativePicker = window.showSaveFilePicker;
          window.samples=[]; window.blocksBeforeWrites=[]; let blocks=0;
          const decrypt = ES3.decryptBlock;
          ES3.decryptBlock=async (...args)=>{ blocks++; return decrypt(...args); };
          window.showSaveFilePicker=async options=>{
            const handle=await nativePicker(options);
            return {createWritable:async options=>{
              const writable=await handle.createWritable(options);
              return {write:async data=>{
                const count=blocks; await new Promise(r=>setTimeout(r,80));
                window.blocksBeforeWrites.push(blocks-count); await writable.write(data);
                window.samples.push({bytes:data.byteLength,progress:document.querySelector('#download-progress').value});
              },close:()=>writable.close(),abort:()=>writable.abort()};
            }};
          };
        }''')
        self.start_download(); self.assertEqual(self.wait_download(), '下载完成')
        data = self.page.evaluate('({samples, blocksBeforeWrites, name:pickerOptions.suggestedName})')
        self.assertEqual(data['name'], 'data.mp4')
        self.assertEqual(data['blocksBeforeWrites'], [0] * 4)
        self.assertEqual(sum(x['bytes'] for x in data['samples']), len(self.plain))
        self.assertEqual([round(x['progress'], 4) for x in data['samples']], [round(i * CHUNK / len(self.plain) * 100, 4) for i in range(4)])
        names = self.page.evaluate('''() => ['movie.mp4.enc','test.enc','%2E%2E%2Fbad%5Cname.enc','CON.enc','%00.enc','%ZZ.enc',''].map(name=>ES3Download.filename('https://example.com/'+name+'?private=ignored'))''')
        self.assertEqual(names[:2], ['movie.mp4', 'test.mp4'])
        for name in names:
            self.assertTrue(name.endswith('.mp4'))
            self.assertFalse(any(c in name for c in '/\\\x00:'))
        self.assertEqual(names[-2:], ['video.mp4', 'video.mp4'])
        long_name=self.page.evaluate("ES3Download.filename('https://example.com/'+encodeURIComponent('😀'.repeat(200))+'.enc')")
        self.assertLessEqual(len(long_name.encode()),255)

    def test_cancel_preserves_existing_file_and_can_retry(self):
        self.load(); self.seed_target()
        self.page.evaluate('''() => {
          const decrypt=ES3.decryptBlock;
          ES3.decryptBlock=async(...args)=>{ const plain=await decrypt(...args); await new Promise(r=>setTimeout(r,200)); return plain; };
        }''')
        self.start_download()
        self.page.wait_for_function("() => document.querySelector('#download-progress').value > 0")
        self.page.locator('#cancel-download').click()
        self.assertIn('已取消', self.wait_download()); self.assert_target_preserved()
        self.start_download(); self.assertEqual(self.wait_download(), '下载完成')
        self.assertEqual(self.file_info()['hash'], hashlib.sha256(self.plain).hexdigest())

    def test_late_network_tamper_expiry_and_range_failures(self):
        self.load(); self.seed_target()
        for mode, expected in [('late-network','失败'), ('late-truncated','失败'), ('late-tamper','认证失败'), ('late-expired','过期'), ('late-bad','Content-Range'), ('ignore','HTTP 206')]:
            with self.subTest(mode=mode):
                self.seed_target()
                # Only the page's download request changes; playback has its own Worker copy.
                self.page.evaluate('''mode => {
                  window.originalDecrypt ||= ES3.decryptBlock;
                  ES3.decryptBlock=(s,i,signal)=>window.originalDecrypt({...s,url:s.url+'?mode='+mode},i,signal);
                }''', mode)
                self.start_download(); status = self.wait_download()
                self.assertIn(expected, status); self.assertNotIn('下载完成', status)
                self.assert_target_preserved()

    def test_wrong_key_gate_and_authentication_abort(self):
        self.load(key=base64.urlsafe_b64encode(bytes(32)).decode().rstrip('='))
        self.assertTrue(self.page.locator('#download').is_disabled())
        self.load(); self.seed_target()
        error = self.page.evaluate('''async () => {
          const key = await crypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['decrypt']);
          const root=await navigator.storage.getDirectory(); const handle=await root.getFileHandle('saved.mp4');
          const writer=await handle.createWritable({keepExistingData:false});
          try { await ES3Download.save({...current,key}, writer, {signal:new AbortController().signal}); return 'unexpected success'; }
          catch(e) { return e.message; }
        }''')
        self.assertIn('认证失败', error); self.assert_target_preserved()

    def test_session_reload_cancels_previous_download(self):
        self.load(); self.seed_target()
        self.page.evaluate("""() => {
          const decrypt=ES3.decryptBlock;
          ES3.decryptBlock=async(...args)=>{const b=await decrypt(...args); await new Promise(r=>setTimeout(r,200)); return b;};
        }""")
        self.start_download()
        self.page.wait_for_function("() => document.querySelector('#download-progress').value > 0")
        self.load()
        self.assertIn('已取消',self.wait_download()); self.assert_target_preserved()
        self.start_download(); self.assertEqual(self.wait_download(),'下载完成')

    def test_disk_failure_and_close_failure_never_report_success(self):
        self.load(); self.seed_target()
        for fail in ('write', 'close'):
            with self.subTest(fail=fail):
                self.page.evaluate('''fail=>{
                  window.nativePicker ||= window.showSaveFilePicker;
                  window.showSaveFilePicker=async options=>{
                    const h=await window.nativePicker(options);
                    return {createWritable:async options=>{
                      const w=await h.createWritable(options);
                      return {write:data=>fail==='write'?Promise.reject(Error('磁盘写入失败')):w.write(data),
                        close:()=>Promise.reject(Error('磁盘关闭失败')),abort:()=>w.abort()};
                    }};
                  };
                }''', fail)
                self.start_download(); self.assertIn('下载失败', self.wait_download()); self.assert_target_preserved()

    def test_unsupported_api_and_picker_cancellation(self):
        self.page.evaluate("Object.defineProperty(window, 'showSaveFilePicker', {value:undefined, configurable:true})")
        # Re-run initialization in the same secure context to exercise capability detection.
        self.page.evaluate('window.unsupportedUI=ES3Download.setup()')
        self.assertIn('不支持大文件直接保存', self.page.locator('#download-status').inner_text())
        self.assertTrue(self.page.locator('#download').is_disabled())
        self.page.reload(); self.load()
        self.page.evaluate("() => {window.showSaveFilePicker=async()=>{throw new DOMException('Dismissed','AbortError')};}")
        self.start_download(); self.assertIn('已取消', self.wait_download())

    def test_existing_worker_upgrade_keeps_download_available(self):
        cls=type(self)
        try:
            cls.legacy_worker=True
            self.page.evaluate("async () => {await navigator.serviceWorker.register('sw.js',{scope:'./'}); await navigator.serviceWorker.ready;}")
            # Simulate a previously installed Worker that replies without the new header.
            cls.legacy_worker=False; cls.delay_worker=True
            self.page.reload()
            self.load()
            self.assertFalse(self.page.locator('#download').is_disabled())
            self.start_download(); self.assertEqual(self.wait_download(),'下载完成')
        finally:
            cls.legacy_worker=False; cls.delay_worker=False

    def test_share_link_download_during_playback_and_seek(self):
        data = {'v':1,'url':self.objects+'movie.enc','key':(self.data/'movie.key').read_text().strip()}
        fragment=base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
        self.page.goto(self.host+'#'+fragment)
        self.page.wait_for_function("() => document.querySelector('video').readyState >= 1 && !document.querySelector('#download').disabled")
        self.page.evaluate('''() => {
          const decrypt=ES3.decryptBlock;
          ES3.decryptBlock=async(...args)=>{ const plain=await decrypt(...args); await new Promise(r=>setTimeout(r,100)); return plain; };
          document.querySelector('video').play();
        }''')
        self.start_download()
        self.page.evaluate('document.querySelector("video").currentTime=72')
        self.page.wait_for_function('() => document.querySelector("video").currentTime>72.3 && !document.querySelector("video").seeking')
        self.assertEqual(self.wait_download(), '下载完成')
        with (self.data/'movie.mp4').open('rb') as f: expected=hashlib.file_digest(f,'sha256').hexdigest()
        self.assertEqual(self.file_info()['hash'], expected)

    @unittest.skipUnless(os.environ.get('SECURES3_LARGE_DOWNLOAD_TEST') == '1', 'Set SECURES3_LARGE_DOWNLOAD_TEST=1 for a real 3 GiB disk/HTTP test')
    def test_three_gib_streamed_to_native_file_with_bounded_memory(self):
        if shutil.disk_usage(self.data).free < 8 * 1024**3:
            self.skipTest('Needs at least 8 GiB of temporary disk space')
        source, ciphertext, key = (self.data / x for x in ('large.mp4','large.enc','large.key'))
        try:
            size = 3 * 1024**3 + 137
            with source.open('wb') as f:
                f.truncate(size); f.write(b'3 GiB streaming test'); f.seek(size-4); f.write(b'END!')
            print('\nEncrypting real 3 GiB + 137 byte fixture...', flush=True)
            encrypt(source, ciphertext, key)
            # Incognito OPFS has a separate global cap. A disposable persistent profile
            # exercises native writes at multi-GB scale without that test-only cap.
            self.context.close()
            self.context=self.pw.chromium.launch_persistent_context(str(self.data/'large-profile'),
                executable_path=shutil.which('chromium'),headless=True,args=['--no-sandbox'])
            self.addCleanup(self.context.close)
            self.context.add_init_script(PICKER)
            self.page=self.context.new_page(); self.page.goto(self.host)
            self.load('large')
            # Allow enough space for this test origin; real user-picked files are not OPFS.
            self.context.new_cdp_session(self.page).send('Storage.overrideQuotaForOrigin',
                {'origin':self.host.split('/viewer/')[0], 'quotaSize':8*1024**3})
            print('Native test file storage estimate:',self.page.evaluate('navigator.storage.estimate()'),flush=True)
            process_info=self.context.browser.new_browser_cdp_session().send('SystemInfo.getProcessInfo')['processInfo']
            pids=[p['id'] for p in process_info if p['type']=='renderer']
            def rss():
                total=0
                for pid in pids:
                    try:
                        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
                            if line.startswith('VmRSS:'): total+=int(line.split()[1])*1024
                    except FileNotFoundError: pass
                return total
            baseline=rss(); peak=[baseline]; stop=threading.Event()
            def monitor():
                while not stop.wait(0.02): peak[0]=max(peak[0],rss())
            watcher=threading.Thread(target=monitor,daemon=True); watcher.start()
            print('Streaming 3 GiB through real HTTP ranges, Web Crypto and native file writes...',flush=True)
            try:
                self.start_download(); self.assertEqual(self.wait_download(),'下载完成')
            finally:
                stop.set(); watcher.join()
            # Hash in 4 MiB slices, never arrayBuffer() the whole 3 GiB file.
            actual=self.page.evaluate('''async () => {
              const file=await window.savedHandle.getFile(), hashes=[];
              for(let pos=0;pos<file.size;pos+=ES3.CHUNK){
                const digest=await crypto.subtle.digest('SHA-256',await file.slice(pos,pos+ES3.CHUNK).arrayBuffer());
                hashes.push(Array.from(new Uint8Array(digest),x=>x.toString(16).padStart(2,'0')).join(''));
              }
              return {size:file.size,hashes};
            }''')
            self.assertEqual(actual['size'],size)
            with source.open('rb') as f:
                expected=[]
                while block:=f.read(CHUNK): expected.append(hashlib.sha256(block).hexdigest())
            self.assertEqual(actual['hashes'],expected)
            self.assertGreater(baseline,0)
            self.assertLess(peak[0]-baseline,512*1024**2)
            print(f'3 GiB native save verified: {len(expected)} block hashes; renderer RSS baseline/peak {baseline/1024**2:.1f}/{peak[0]/1024**2:.1f} MiB',flush=True)
        finally:
            for p in (source,ciphertext,key): p.unlink(missing_ok=True)


if __name__=='__main__': unittest.main()
