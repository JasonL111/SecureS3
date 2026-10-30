'use strict';
const $ = id => document.getElementById(id);
const video = $('video');
const downloads = ES3Download.setup();
let current = null, revision = 0;
function status(text, error = false) { $('status').textContent = text; $('status').className = error ? 'error' : ''; }
function shareData() {
  const url = ES3.validateURL($('url').value.trim()), key = $('key').value.trim();
  if (ES3.decode64(key).length !== 32) throw Error('AES 密钥必须是 32 字节的 Base64URL 字符串');
  return {v: 1, url, key};
}
async function worker() {
  if (!isSecureContext || !('serviceWorker' in navigator)) throw Error('需要 HTTPS 和支持 Service Worker 的浏览器');
  const reg = await navigator.serviceWorker.register(new URL('sw.js', location.href), {scope: './', updateViaCache: 'none'});
  // An existing page may still be controlled by the pre-download Worker.
  // Wait for the newly registered Worker to activate and claim it before messaging.
  const installing = reg.installing;
  if (installing) {
    await new Promise((resolve, reject) => {
      const finish = error => { clearTimeout(timer); installing.removeEventListener('statechange', changed); error ? reject(error) : resolve(); };
      const changed = () => {
        if (installing.state === 'activated') finish();
        else if (installing.state === 'redundant') finish(Error('Worker 更新失败，请刷新重试'));
      };
      const timer = setTimeout(() => finish(Error('Worker 更新超时，请刷新重试')), 15000);
      installing.addEventListener('statechange', changed); changed();
    });
  }
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise((resolve, reject) => {
      const onChange = () => { if (navigator.serviceWorker.controller) { clearTimeout(timer); navigator.serviceWorker.removeEventListener('controllerchange', onChange); resolve(); } };
      const timer = setTimeout(() => { navigator.serviceWorker.removeEventListener('controllerchange', onChange); reject(Error('Worker 未接管页面，请刷新重试')); }, 10000);
      navigator.serviceWorker.addEventListener('controllerchange', onChange); onChange();
    });
  }
  return reg;
}
function configure(data) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => { channel.port1.close(); reject(Error('加载超时，请检查网络后重试')); }, 35000);
    channel.port1.onmessage = e => { clearTimeout(timer); channel.port1.close(); e.data.error ? reject(Error(e.data.error)) : resolve(e.data); };
    navigator.serviceWorker.controller.postMessage({type: 'configure', ...data}, [channel.port2]);
  });
}
navigator.serviceWorker?.addEventListener('message', event => {
  if (event.source !== navigator.serviceWorker.controller) return;
  if (event.data?.type === 'restore' && event.ports[0]) {
    event.ports[0].postMessage(current?.id === event.data.id ? current : null);
  }
  if (event.data?.type === 'playback-error' && event.data.id === current?.id) status(event.data.error, true);
});
async function load(event) {
  event?.preventDefault();
  const attempt = ++revision;
  $('load').disabled = true;
  downloads.setSession(null);
  try {
    const data = shareData();
    status('正在验证密文和密钥…');
    await worker();
    const key = await crypto.subtle.importKey('raw', ES3.decode64(data.key), 'AES-GCM', false, ['decrypt']);
    if (current) navigator.serviceWorker.controller.postMessage({type: 'close', id: current.id});
    video.removeAttribute('src'); video.load();
    current = {id: crypto.randomUUID(), url: data.url, key};
    const verified = await configure(current);
    if (attempt !== revision) return;
    current.meta = ES3.parseHeader(verified.header);
    downloads.setSession(current);
    video.src = new URL('__video__/' + current.id, location.href).href;
    video.load();
    status('已验证，正在读取视频信息…');
  } catch (error) { if (attempt === revision) status(error.message, true); }
  finally { if (attempt === revision) $('load').disabled = false; }
}
$('form').addEventListener('submit', load);
$('share').addEventListener('click', async () => {
  try {
    const data = shareData();
    const url = new URL(location.href); url.search = ''; url.hash = ES3.encode64(new TextEncoder().encode(JSON.stringify(data)));
    await navigator.clipboard.writeText(url.href);
    status('分享链接已复制。链接包含密钥，请只发给可信的人。');
  } catch (error) { status('复制失败：' + error.message, true); }
});
video.addEventListener('loadedmetadata', () => status('视频已就绪，点击播放。可随时拖动进度条。'));
video.addEventListener('error', () => {
  if ($('status').className === 'error') return;
  status(video.error?.code === 3 || video.error?.code === 4 ? '无法播放：MP4 编码不受支持，或视频数据不可用。请检查文件与密钥。' : '视频加载中断，请检查网络或更换已过期的 URL 后重新加载。', true);
});
window.addEventListener('pagehide', () => { downloads.cancel(); if (current) navigator.serviceWorker.controller?.postMessage({type: 'close', id: current.id}); });
function readShare() {
  if (location.hash.length <= 1) return;
  try {
    if (location.hash.length > 32768) throw Error('分享链接过长');
    const data = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(ES3.decode64(location.hash.slice(1))));
    if (data.v !== 1 || typeof data.url !== 'string' || typeof data.key !== 'string') throw Error('分享链接格式错误');
    $('url').value = data.url; $('key').value = data.key;
    // Remove the secret from the current address/history entry; do not persist it elsewhere.
    history.replaceState(null, '', location.pathname + location.search);
    load();
  } catch (error) { status('无法读取分享链接：' + error.message, true); }
}

window.addEventListener('hashchange', readShare);
readShare();
