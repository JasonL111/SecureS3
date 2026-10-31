"""Real Chromium integration; two local origins emulate static hosting and S3."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import unittest
from urllib.parse import urlsplit, parse_qs

from playwright.sync_api import sync_playwright
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from encrypt import encrypt, CHUNK

ROOT = Path(__file__).resolve().parents[1]


class PlayerFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.data = Path(cls.temp.name)
        cls.plain = os.urandom(CHUNK * 3 + 517)
        (cls.data / 'data.mp4').write_bytes(cls.plain)
        encrypt(cls.data / 'data.mp4', cls.data / 'data.enc', cls.data / 'data.key')
        subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'testsrc2=size=640x360:rate=24', '-t', '90', '-c:v', 'libx264', '-preset', 'ultrafast', '-b:v', '300k', '-pix_fmt', 'yuv420p', str(cls.data / 'original.mp4')], check=True)
        original = (cls.data / 'original.mp4').read_bytes()
        # Place a valid 64 MiB free atom before the tail moov, preserving mdat offsets.
        moov = original.rfind(b'moov') - 4
        assert moov > 0 and original[moov + 4:moov + 8] == b'moov'
        with (cls.data / 'movie.mp4').open('wb') as f:
            f.write(original[:moov]); f.write(struct.pack('>I4s', 64 * 1024**2, b'free'))
            f.seek(64 * 1024**2 - 8, 1); f.write(original[moov:])
        encrypt(cls.data / 'movie.mp4', cls.data / 'movie.enc', cls.data / 'movie.key')
        cls.requests = []
        cls.http_requests = []
        cls.legacy_worker = False
        cls.delay_worker = False
        cls.strict_headers = False
        data, requests = cls.data, cls.requests

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs): super().__init__(*args, directory=str(ROOT / 'web'), **kwargs)
            def log_message(self, *args): pass
            def end_headers(self):
                if cls.strict_headers:
                    for line in (ROOT/'web/_headers').read_text().splitlines()[1:]:
                        if not line.startswith('  '): break
                        name,value=line.strip().split(':',1);self.send_header(name,value.strip())
                super().end_headers()
            def do_GET(self):
                cls.http_requests.append((self.path, dict(self.headers)))
                url = urlsplit(self.path)
                if not url.path.startswith('/objects/'):
                    # Serve the app in a subdirectory to test Pages-style deployment.
                    if url.path.startswith('/viewer/'): self.path = self.path[len('/viewer'):]
                    if self.path in ('/csp-probe.js','/worker-probe.js'):
                        body=("window.cspProbe={};try{new Function('return 1')();window.cspProbe.evalBlocked=false;}catch{window.cspProbe.evalBlocked=true;}"
                            if self.path=='/csp-probe.js' else
                            "self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));self.addEventListener('message',e=>e.waitUntil(fetch(e.data.url).then(()=>e.ports[0].postMessage(true),()=>e.ports[0].postMessage(false))));")
                        raw=body.encode();self.send_response(200);self.send_header('Content-Type','text/javascript');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);return
                    if self.path == '/sw.js' and (cls.legacy_worker or cls.delay_worker):
                        body=(ROOT/'web/sw.js').read_text()
                        if cls.legacy_worker: body=body.replace(', header: s.meta.bytes','')
                        if cls.delay_worker: body=body.replace('self.skipWaiting()', 'new Promise(resolve => setTimeout(() => resolve(self.skipWaiting()), 300))')
                        raw=body.encode()
                        self.send_response(200); self.send_header('Content-Type','text/javascript')
                        self.send_header('Cache-Control','no-cache'); self.send_header('Content-Length',str(len(raw)))
                        self.end_headers(); self.wfile.write(raw); return
                    return super().do_GET()
                path = data / Path(url.path).name
                mode = parse_qs(url.query).get('mode', [''])[0]
                value = self.headers.get('Range', '')
                requests.append((path.name, value, mode))
                if not value and path.name in getattr(cls, 'full_objects', set()):
                    if not path.is_file(): self.send_error(404); return
                    raw=path.read_bytes();self.send_response(200)
                    self.send_header('Content-Type','application/octet-stream')
                    self.send_header('Content-Length',str(len(raw)))
                    self.send_header('Access-Control-Allow-Origin','*')
                    self.send_header('Cache-Control','no-store');self.end_headers()
                    try:self.wfile.write(raw)
                    except (BrokenPipeError,ConnectionResetError):pass
                    return
                match = re.fullmatch(r'bytes=(\d+)-(\d+)', value)
                if not match: self.send_error(400); return
                start, end = map(int, match.groups())
                if mode.startswith('late-'):
                    mode = mode[5:] if start >= 48 + CHUNK + 16 else ''
                if mode == 'expired':
                    self.send_response(403); self.send_header('Access-Control-Allow-Origin', '*'); self.end_headers(); return
                if mode == 'network': self.connection.close(); return
                if not path.is_file(): self.send_error(404); return
                size = path.stat().st_size
                self.send_response(200 if mode == 'ignore' else 206)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Expose-Headers', 'Content-Range,Content-Length,Accept-Ranges,ETag')
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Content-Range', f'bytes {start + (mode == "bad")}-{end}/{size}')
                self.send_header('Content-Length', str(end - start + 1))
                self.end_headers()
                try:
                    with path.open('rb') as f:
                        f.seek(start)
                        payload = f.read(end - start + 1)
                        if mode == 'tamper' and start >= 48: payload = bytes([payload[0] ^ 1]) + payload[1:]
                        self.wfile.write(payload[:len(payload)//2] if mode == 'truncated' else payload)
                except (BrokenPipeError, ConnectionResetError): pass

        cls.servers = [ThreadingHTTPServer(('127.0.0.1', 0), Handler) for _ in range(2)]
        for server in cls.servers: threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.host = f'http://127.0.0.1:{cls.servers[0].server_port}/viewer/'
        cls.objects = f'http://127.0.0.1:{cls.servers[1].server_port}/objects/'
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch(executable_path=shutil.which('chromium'), headless=True, args=['--no-sandbox', '--autoplay-policy=no-user-gesture-required'])

    @classmethod
    def tearDownClass(cls):
        cls.browser.close(); cls.pw.stop()
        for s in cls.servers: s.shutdown(); s.server_close()
        cls.temp.cleanup()

    def setUp(self):
        self.context = self.browser.new_context()
        self.page = self.context.new_page()
        self.page.goto(self.host)
        self.addCleanup(self.context.close)

    def load(self, name='data', mode='', key=None):
        self.page.locator('#url').fill(self.objects + name + '.enc' + ('?mode=' + mode if mode else ''))
        self.page.locator('#key').fill(key or (self.data / (name + '.key')).read_text().strip())
        self.page.locator('#load').click()
        self.page.wait_for_function("() => !document.querySelector('#load').disabled")

    def virtual(self):
        return self.page.evaluate("document.querySelector('video').src")

    def request(self, value=None, method='GET'):
        return self.page.evaluate('''async ({url, range, method}) => {
          const r = await fetch(url, {method, headers: range === null ? {} : {Range: range}});
          const bytes = new Uint8Array(await r.arrayBuffer());
          let binary = ''; for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
          return {status: r.status, range: r.headers.get('Content-Range'), length: r.headers.get('Content-Length'), body: btoa(binary)};
        }''', {'url': self.virtual(), 'range': value, 'method': method})


class BrowserTests(PlayerFixture):
    def test_ranges_python_js_compatibility(self):
        self.load()
        self.assertTrue(self.virtual())
        for value, start, end in [('bytes=0-1023', 0, 1023), ('bytes=4194284-8388640', CHUNK - 20, CHUNK * 2 + 32), ('bytes=10000000-', 10000000, len(self.plain)-1), ('bytes=-65536', len(self.plain)-65536, len(self.plain)-1)]:
            with self.subTest(value=value):
                result = self.request(value)
                self.assertEqual(result['status'], 206)
                self.assertEqual(result['range'], f'bytes {start}-{end}/{len(self.plain)}')
                self.assertEqual(base64.b64decode(result['body']), self.plain[start:end + 1])
        for value in ('bytes=999999999-', 'bytes=-0', 'bytes=9-2', 'bytes=a-b', 'bytes=0-1,3-4', 'bytes=9007199254740992-'):
            result = self.request(value); self.assertEqual(result['status'], 416); self.assertEqual(result['range'], f'bytes */{len(self.plain)}')
        result = self.request(method='HEAD'); self.assertEqual(result['status'], 200); self.assertEqual(int(result['length']), len(self.plain)); self.assertEqual(result['body'], '')
        result = self.request(); self.assertEqual(result['status'], 200); self.assertEqual(base64.b64decode(result['body']), self.plain)

    def test_storage_failures_and_wrong_key(self):
        for mode, message in [('ignore', 'HTTP 206'), ('bad', 'Content-Range'), ('expired', '过期'), ('network', '网络'), ('tamper', '认证失败')]:
            with self.subTest(mode=mode):
                self.load(mode=mode)
                self.assertIn(message, self.page.locator('#status').inner_text())
        self.load(key=base64.urlsafe_b64encode(bytes(32)).decode().rstrip('='))
        self.assertIn('认证失败', self.page.locator('#status').inner_text())

    def test_header_validation_and_empty(self):
        result = self.page.evaluate('''() => {
          const results = [];
          const h = new Uint8Array(48), v = new DataView(h.buffer);
          h.set(new TextEncoder().encode('ES3VID01')); v.setUint32(8, 1); v.setUint32(12, 4194304);
          results.push(ES3.parseHeader(h).total === 64);
          for (const mutate of [b => b[0] ^= 1, b => b[8] = 1, b => b[12] = 1, b => b[40] = 1, b => b.fill(255, 16, 24)]) {
            const b = h.slice(); mutate(b); try { ES3.parseHeader(b); results.push(false); } catch { results.push(true); }
          }
          return results;
        }''')
        self.assertTrue(all(result))
        (self.data / 'empty.mp4').write_bytes(b'')
        encrypt(self.data / 'empty.mp4', self.data / 'empty.enc', self.data / 'empty.key')
        self.load('empty'); result = self.request(); self.assertEqual((result['status'], result['length'], result['body']), (200, '0', ''))
        self.assertEqual(self.request('bytes=0-')['status'], 416)

    def test_play_seek_share_and_worker_restart(self):
        data = {'v': 1, 'url': self.objects + 'movie.enc', 'key': (self.data / 'movie.key').read_text().strip()}
        fragment = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
        self.page.goto(self.host + '#' + fragment)
        self.page.wait_for_function("() => document.querySelector('video').readyState >= 1", timeout=30000)
        self.assertNotIn('#', self.page.url)
        self.assertGreater(self.page.evaluate('document.querySelector("video").duration'), 89)
        self.page.evaluate('document.querySelector("video").play()')
        self.page.wait_for_function('() => document.querySelector("video").currentTime > 0.3')
        self.page.evaluate('document.querySelector("video").currentTime = 72')
        self.page.wait_for_function('() => document.querySelector("video").currentTime > 72.3 && !document.querySelector("video").seeking', timeout=30000)
        self.page.evaluate('document.querySelector("video").pause()')
        # Actual worker termination via Chromium's ServiceWorker domain.
        cdp = self.context.new_cdp_session(self.page)
        versions = []
        cdp.on('ServiceWorker.workerVersionUpdated', lambda e: versions.extend(e['versions']))
        cdp.send('ServiceWorker.enable')
        self.page.wait_for_timeout(500)
        running = [v for v in versions if v['runningStatus'] == 'running']
        self.assertTrue(running, versions)
        cdp.send('ServiceWorker.stopWorker', {'versionId': running[-1]['versionId']})
        result = self.request('bytes=-128')
        expected = (self.data / 'movie.mp4').read_bytes()[-128:]
        self.assertEqual(base64.b64decode(result['body']), expected)
        self.page.evaluate('document.querySelector("video").currentTime = 40; document.querySelector("video").play()')
        self.page.wait_for_function('() => document.querySelector("video").currentTime > 40.3 && !document.querySelector("video").seeking', timeout=30000)
        self.context.grant_permissions(['clipboard-read', 'clipboard-write'])
        self.page.locator('#share').click()
        copied = self.page.evaluate('navigator.clipboard.readText()')
        decoded = json.loads(base64.urlsafe_b64decode(copied.split('#')[1] + '==='))
        self.assertEqual(decoded, data)
        movie_ranges = [(int(m[1]), int(m[2])) for name, value, _ in self.requests if name == 'movie.enc' and (m := re.fullmatch(r'bytes=(\d+)-(\d+)', value))]
        # Metadata is at the end; seeking must skip the large free atom rather than fetch it all.
        covered = set()
        for start, end in movie_ranges: covered.update(range(start // CHUNK, end // CHUNK + 1))
        self.assertLess(len(covered), 10, movie_ranges)
        self.assertTrue(any(start > 60 * 1024**2 for start, _ in movie_ranges))
        print('Chromium playback + 72s/40s seeks + worker restart passed; fetched encrypted block IDs:', sorted(covered))

    def test_cancellation_and_streaming(self):
        self.load()
        result = self.page.evaluate('''async url => {
          const c = new AbortController(); const r = await fetch(url, {signal:c.signal});
          const reader = r.body.getReader(); const first = await reader.read();
          c.abort(); let cancelled = false; try { while (!(await reader.read()).done) {} } catch { cancelled = true; }
          return {status:r.status, length:first.value.length, cancelled};
        }''', self.virtual())
        self.assertEqual(result['status'], 200); self.assertLessEqual(result['length'], CHUNK); self.assertTrue(result['cancelled'])
        self.assertEqual(self.request('bytes=1-3')['status'], 206)


if __name__ == '__main__': unittest.main()
