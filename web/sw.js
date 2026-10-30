'use strict';
importScripts('protocol.js');
const sessions = new Map();
const scope = new URL(self.registration.scope);
const prefix = scope.pathname + '__video__/';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

// Bound concurrent ciphertext/decrypted allocations, including multiple video requests.
let active = 0;
const queue = [];
async function limited(fn, signal) {
  if (signal.aborted) throw new DOMException('Cancelled', 'AbortError');
  await new Promise((resolve, reject) => {
    const entry = {grant() { signal.removeEventListener('abort', abort); active++; resolve(); }};
    function abort() { const i = queue.indexOf(entry); if (i >= 0) queue.splice(i, 1); reject(new DOMException('Cancelled', 'AbortError')); }
    if (active < 3) entry.grant();
    else { queue.push(entry); signal.addEventListener('abort', abort, {once: true}); }
  });
  try { return await fn(); }
  finally { active--; queue.shift()?.grant(); }
}
async function fetchBytes(url, start, end, total, signal) {
  const response = await fetch(url, {headers: {Range: `bytes=${start}-${end}`},
    mode: 'cors', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal});
  const fail = async message => { await response.body?.cancel(); throw Error(message); };
  if (response.status === 401 || response.status === 403) return fail('对象无权访问或 URL 已过期，请更换视频 URL');
  if (response.status !== 206) return fail('存储服务必须返回 HTTP 206；请检查 Range、CORS 和对象 URL');
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers.get('Content-Range') || '');
  if (!match || Number(match[1]) !== start || Number(match[2]) !== end ||
      !Number.isSafeInteger(Number(match[3])) || Number(match[3]) <= end ||
      (total !== null && Number(match[3]) !== total)) return fail('存储服务返回了错误的 Content-Range');
  const length = end - start + 1, declared = response.headers.get('Content-Length');
  if (declared !== null && Number(declared) !== length) return fail('存储服务返回了错误的 Content-Length');
  const encoding = response.headers.get('Content-Encoding');
  if (encoding && encoding !== 'identity') return fail('密文对象不能使用 Content-Encoding 压缩');
  const bytes = new Uint8Array(length), reader = response.body.getReader();
  let offset = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      if (offset + value.length > length) throw Error('密文响应超出请求范围');
      bytes.set(value, offset); offset += value.length;
    }
    if (offset !== length) throw Error('密文下载中断或长度不足');
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  return {bytes, total: Number(match[3])};
}
async function decryptBlock(session, index, signal) {
  return limited(async () => {
    const b = ES3.block(session.meta, index);
    const {bytes} = await fetchBytes(session.url, b.start, b.start + b.length + 15, session.meta.total, signal);
    try { return new Uint8Array(await crypto.subtle.decrypt(ES3.auth(session.meta, index), session.key, bytes)); }
    catch { throw Error('AES-GCM 认证失败：密钥错误、文件被修改或对象已替换'); }
  }, signal);
}
async function configure(data, owner) {
  if (!/^[a-f0-9-]{36}$/.test(data.id) || !owner?.url?.startsWith(scope.href)) throw Error('无效会话来源');
  if (data.key?.type !== 'secret' || data.key.algorithm.name !== 'AES-GCM' || data.key.algorithm.length !== 256 || data.key.extractable) throw Error('无效 AES 密钥');
  const url = ES3.validateURL(data.url), controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const header = await limited(() => fetchBytes(url, 0, ES3.HEADER - 1, null, controller.signal), controller.signal);
    const meta = ES3.parseHeader(header.bytes);
    if (meta.total !== header.total) throw Error('加密文件总长度不正确');
    const session = {url, key: data.key, meta, owner: owner.id};
    await decryptBlock(session, 0, controller.signal); // Authenticate header and key before playback.
    // Remove dead clients and keep at most one session per page; no persistent key storage.
    const live = new Set((await self.clients.matchAll()).map(c => c.id));
    for (const [id, s] of sessions) if (!live.has(s.owner) || s.owner === owner.id) sessions.delete(id);
    sessions.set(data.id, session);
    return session;
  } finally { clearTimeout(timeout); }
}
self.addEventListener('message', event => {
  if (event.data?.type === 'close') {
    if (sessions.get(event.data.id)?.owner === event.source?.id) sessions.delete(event.data.id);
    return;
  }
  if (event.data?.type !== 'configure' || !event.ports[0]) return;
  event.waitUntil(configure(event.data, event.source).then(s => event.ports[0].postMessage({ok: true, size: s.meta.size}))
    .catch(e => event.ports[0].postMessage({error: safeError(e)})));
});
function safeError(error) {
  if (error.name === 'AbortError') return '请求已取消或超时';
  if (error instanceof TypeError) return '网络请求失败，请检查网络、CORS 和视频 URL';
  return error.message;
}
async function recover(id, clientId) {
  const existing = sessions.get(id);
  if (existing) {
    if (existing.owner !== clientId) throw Error('会话不属于当前页面');
    return existing;
  }
  const client = await self.clients.get(clientId);
  if (!client || !client.url.startsWith(scope.href)) throw Error('请重新打开播放器');
  const data = await new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => { channel.port1.close(); reject(Error('页面未提供会话，请重新加载视频')); }, 5000);
    channel.port1.onmessage = e => { clearTimeout(timer); channel.port1.close(); e.data ? resolve(e.data) : reject(Error('播放会话已关闭')); };
    client.postMessage({type: 'restore', id}, [channel.port2]);
  });
  return configure({...data, id}, client);
}
async function videoResponse(event, id) {
  const request = event.request;
  if (!['GET', 'HEAD'].includes(request.method)) return new Response(null, {status: 405, headers: {Allow: 'GET, HEAD'}});
  const controller = new AbortController();
  const abort = () => controller.abort();
  request.signal.addEventListener('abort', abort, {once: true});
  try {
    const session = await recover(id, event.clientId);
    const range = ES3.range(request.method === 'HEAD' ? null : request.headers.get('Range'), session.meta.size);
    const headers = new Headers({'Content-Type': 'video/mp4', 'Accept-Ranges': 'bytes',
      'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff'});
    if (!range) {
      request.signal.removeEventListener('abort', abort);
      headers.set('Content-Range', `bytes */${session.meta.size}`);
      headers.set('Content-Length', '0');
      return new Response(null, {status: 416, headers});
    }
    headers.set('Content-Length', String(Math.max(0, range.end - range.start + 1)));
    if (range.status === 206) headers.set('Content-Range', `bytes ${range.start}-${range.end}/${session.meta.size}`);
    if (request.method === 'HEAD' || session.meta.size === 0) {
      request.signal.removeEventListener('abort', abort);
      return new Response(null, {status: range.status, headers});
    }
    let position = range.start;
    const cleanup = () => request.signal.removeEventListener('abort', abort);
    const stream = new ReadableStream({
      async pull(output) {
        try {
          const index = Math.floor(position / ES3.CHUNK);
          const plain = await decryptBlock(session, index, controller.signal);
          const start = position - index * ES3.CHUNK;
          const end = Math.min(plain.length, range.end - index * ES3.CHUNK + 1);
          output.enqueue(plain.subarray(start, end));
          position = index * ES3.CHUNK + end;
          if (position > range.end) { cleanup(); output.close(); }
        } catch (error) {
          cleanup(); controller.abort(); output.error(error);
          const client = await self.clients.get(session.owner);
          client?.postMessage({type: 'playback-error', id, error: safeError(error)});
        }
      },
      cancel() { cleanup(); controller.abort(); }
    }, {highWaterMark: 0});
    return new Response(stream, {status: range.status, headers});
  } catch (error) {
    request.signal.removeEventListener('abort', abort);
    return new Response(safeError(error), {status: 502, headers: {'Cache-Control': 'no-store'}});
  }
}
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin === scope.origin && url.pathname.startsWith(prefix)) {
    event.respondWith(videoResponse(event, url.pathname.slice(prefix.length)));
  }
});
