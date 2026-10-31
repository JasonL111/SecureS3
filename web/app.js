'use strict';
const $ = id => document.getElementById(id);
const video = $('video');
const downloads = ES3Download.setup();
let current = null, revision = 0, selectedFile = null;
function status(text, error = false) { $('status').textContent = text; $('status').className = error ? 'error' : ''; }
function checkedFile(file) {
  const url = ES3.validateURL(file.url.trim()), key = file.key.trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(key) || ES3.decode64(key).length !== 32 || ES3.encode64(ES3.decode64(key)) !== key) throw Error('AES 密钥必须是 32 字节的 Base64URL 字符串');
  return {v: 1, url, key};
}
function shareData() { return checkedFile({url:$('url').value, key:$('key').value}); }
function stopPlayer() {
  ++revision; downloads.cancel(); downloads.setSession(null);
  if (current) navigator.serviceWorker.controller?.postMessage({type:'close',id:current.id});
  current = null; selectedFile=null; $('key').value = ''; $('url').value = ''; $('load').disabled = false;
  $('playing-name').textContent = ''; $('playing-name').hidden = true;
  video.pause(); video.removeAttribute('src'); video.load();
  status('粘贴密文链接和密钥，或打开专用分享链接。');
}
function playFile(file) {
  selectedFile=file;
  const sensitive=file.expiresAt!==undefined || ES3.temporaryURL(file.url);
  $('url').value = sensitive?'':file.url; $('key').value = sensitive?'':file.key;
  $('playing-name').textContent = file.name; $('playing-name').hidden = false;
  return load(null,file);
}
async function shareFile(file) {
  try {
    const data = checkedFile(file), url = new URL(location.href);
    ES3.checkAccess(file.expiresAt ?? ES3.urlExpiry(data.url));
    url.search = ''; url.hash = ES3.encode64(new TextEncoder().encode(JSON.stringify(data)));
    if (url.hash.length > 32769) throw Error('分享链接过长');
    await navigator.clipboard.writeText(url.href);
    const expires=file.expiresAt??ES3.urlExpiry(data.url);
    status('分享链接已复制，仅含当前视频权限。'+(expires ? `临时授权于 ${new Date(expires*1000).toLocaleString()} 过期；旧链接不会随 Vault 自动更新。` : ES3.temporaryURL(data.url)?'临时授权过期后须重新分享；旧链接不会自动更新。':'请私下分享。'));
  } catch (error) { status('复制失败：' + error.message, true); }
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
async function load(event, selected = null) {
  event?.preventDefault();
  const attempt = ++revision;
  $('load').disabled = true;
  downloads.setSession(null);
  try {
    const data = selected ? checkedFile(selected) : shareData();
    const expiresAt=selected?.expiresAt??ES3.urlExpiry(data.url);ES3.checkAccess(expiresAt);
    selectedFile=selected || null;
    status('正在验证密文和密钥…');
    await worker();
    if (attempt !== revision) return;
    const key = await crypto.subtle.importKey('raw', ES3.decode64(data.key), 'AES-GCM', false, ['decrypt']);
    if (attempt !== revision) return;
    if (current) navigator.serviceWorker.controller.postMessage({type: 'close', id: current.id});
    video.removeAttribute('src'); video.load();
    const candidate = {id: ES3.sessionId(), url: data.url, key, expiresAt};
    current = candidate;
    const verified = await configure(candidate);
    if (attempt !== revision) return;
    candidate.meta = ES3.parseHeader(verified.header);
    if (selected?.objectKey) ES3VaultCrypto.checkFileId(candidate.meta,selected.id);
    downloads.setSession({...candidate,name:selected?.name});
    video.src = new URL('__video__/' + candidate.id, location.href).href;
    video.load();
    status('已验证，正在读取视频信息…');
  } catch (error) { if (attempt === revision) {
    if (current) navigator.serviceWorker.controller?.postMessage({type:'close',id:current.id});
    current=null;selectedFile=null;downloads.setSession(null);status(error.message, true);
  } }
  finally { if (attempt === revision) $('load').disabled = false; }
}
$('form').addEventListener('submit', load);
$('share').addEventListener('click', () => shareFile(selectedFile || {url:$('url').value,key:$('key').value}));
video.addEventListener('loadedmetadata', () => status('视频已就绪，点击播放。可随时拖动进度条。'+(current?.expiresAt?` 临时授权截至 ${new Date(current.expiresAt*1000).toLocaleString()}，本地时间不保证服务器接受请求。`:current && ES3.temporaryURL(current.url)?' 此分享使用临时授权，到期后请索取新链接。':'')));
video.addEventListener('error', () => {
  if ($('status').className === 'error') return;
  status(video.error?.code === 3 || video.error?.code === 4 ? '无法播放：MP4 编码不受支持，或视频数据不可用。请检查文件与密钥。' : '视频加载中断，请检查网络或更换已过期的 URL 后重新加载。', true);
});
window.addEventListener('pagehide', stopPlayer);
function readShare() {
  if (location.hash.length <= 1) return false;
  const fragment = location.hash.slice(1);
  history.replaceState(null, '', location.pathname + location.search);
  try {
    if (fragment.length > 32768) throw Error('分享链接过长');
    const data = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(ES3.decode64(fragment)));
    if (!data || Array.isArray(data) || data.v !== 1 || typeof data.url !== 'string' || typeof data.key !== 'string') throw Error('分享链接格式错误');
    const file = checkedFile(data);
    vaultUI.shareMode();
    const temporary=ES3.temporaryURL(file.url);
    $('url').value = temporary?'':file.url; $('key').value = temporary?'':file.key;
    if(temporary)$('form').hidden=true;
    // Remove the secret from the current address/history entry; do not persist it elsewhere.
    load(null,temporary?file:null); return true;
  } catch (error) { vaultUI.defaultMode(); status('无法读取分享链接：格式无效或不受支持。', true); return true; }
}

const vaultUI = ES3Vault.setup({play:playFile, stop:stopPlayer, share:shareFile, download:file => downloads.startFile(file)}, downloads.supported);
window.addEventListener('hashchange', () => { if (!readShare()) vaultUI.defaultMode(); });
if (!readShare()) vaultUI.defaultMode();
