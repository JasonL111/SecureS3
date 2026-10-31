'use strict';
importScripts('protocol.js');
const sessions = new Map(), pending = new Map(), restoring = new Map();
const MAX_SESSIONS = 32, MAX_QUEUE = 24;
const validId = id => typeof id === 'string' && /^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.test(id);
const scope = new URL(self.registration.scope);
const prefix = scope.pathname + '__video__/';
function player(client) {
  if (!client || client.type !== 'window') return false;
  const url = new URL(client.url);
  return url.origin === scope.origin && [scope.pathname, scope.pathname + 'index.html'].includes(url.pathname);
}
function drop(id) {
  const session = sessions.get(id);
  if (!session) return;
  sessions.delete(id);
  for (const controller of session.controllers) controller.abort(new DOMException('播放会话已关闭', 'AbortError'));
  session.key = null;
}
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
    else { if (queue.length >= MAX_QUEUE) { reject(Error('请求过多，请稍后重试')); return; } queue.push(entry); signal.addEventListener('abort', abort, {once: true}); }
  });
  try { return await fn(); }
  finally { active--; queue.shift()?.grant(); }
}
function decryptBlock(session, index, signal) {
  return limited(() => ES3.decryptBlock(session, index, signal), signal);
}
async function configure(data, owner) {
  if (!validId(data.id) || !player(owner)) throw Error('无效会话来源');
  if ((sessions.has(data.id) && sessions.get(data.id).owner !== owner.id) ||
      [...pending.values()].some(p => p.id === data.id && p.owner !== owner.id)) throw Error('会话不属于当前页面');
  if (data.key?.type !== 'secret' || data.key.algorithm.name !== 'AES-GCM' || data.key.algorithm.length !== 256 || data.key.extractable) throw Error('无效 AES 密钥');
  if (pending.size >= MAX_SESSIONS && !pending.has(owner.id)) throw Error('播放页面过多');
  const url = ES3.validateURL(data.url), controller = new AbortController();
  pending.get(owner.id)?.controller.abort();
  const ticket = {id: data.id, owner: owner.id, controller};
  pending.set(owner.id, ticket);
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const header = await limited(() => ES3.fetchBytes(url, 0, ES3.HEADER - 1, null, controller.signal), controller.signal);
    const meta = ES3.parseHeader(header.bytes);
    if (meta.total !== header.total) throw Error('加密文件总长度不正确');
    const session = {url, key: data.key, meta, owner: owner.id, controllers: new Set()};
    await decryptBlock(session, 0, controller.signal);
    const live = new Set((await self.clients.matchAll()).filter(player).map(c => c.id));
    for (const [id, s] of sessions) if (!live.has(s.owner)) drop(id);
    controller.signal.throwIfAborted();
    if (pending.get(owner.id) !== ticket || !live.has(owner.id) || !player(await self.clients.get(owner.id))) throw Error('播放会话已关闭');
    controller.signal.throwIfAborted();
    if (sessions.size >= MAX_SESSIONS && ![...sessions.values()].some(s => s.owner === owner.id)) throw Error('播放页面过多');
    for (const [id, s] of sessions) if (s.owner === owner.id) drop(id);
    sessions.set(data.id, session);
    return session;
  } finally {
    clearTimeout(timeout);
    if (pending.get(owner.id) === ticket) pending.delete(owner.id);
  }
}
self.addEventListener('message', event => {
  if (!player(event.source)) { event.ports[0]?.postMessage({error: '无效会话来源'}); return; }
  if (event.data?.type === 'close') {
    const ticket = pending.get(event.source.id);
    if (ticket?.id === event.data.id) { ticket.controller.abort(); pending.delete(event.source.id); }
    restoring.get(event.source.id + ':' + event.data.id)?.cancel();
    if (sessions.get(event.data.id)?.owner === event.source?.id) drop(event.data.id);
    return;
  }
  if (event.data?.type !== 'configure' || !event.ports[0]) return;
  event.waitUntil(configure(event.data, event.source).then(s => event.ports[0].postMessage({ok: true, size: s.meta.size, header: s.meta.bytes}))
    .catch(e => event.ports[0].postMessage({error: safeError(e)})));
});
function safeError(error) {
  if (error.name === 'AbortError') return '请求已取消或超时';
  if (error instanceof TypeError) return '网络请求失败，请检查网络、CORS 和视频 URL';
  return error.message;
}
async function recover(id, clientId) {
  const client = await self.clients.get(clientId);
  if (!player(client)) throw Error('请重新打开播放器');
  const existing = sessions.get(id);
  if (existing) {
    if (existing.owner !== clientId) throw Error('会话不属于当前页面');
    return existing;
  }
  const tag = clientId + ':' + id;
  if (restoring.has(tag)) return restoring.get(tag).promise;
  let cancel;
  const recovery = (async () => {
    const data = await new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      cancel = () => { clearTimeout(timer); channel.port1.close(); reject(Error('播放会话已关闭')); };
      const timer = setTimeout(cancel, 5000);
      channel.port1.onmessage = e => { clearTimeout(timer); channel.port1.close(); e.data ? resolve(e.data) : reject(Error('播放会话已关闭')); };
      client.postMessage({type: 'restore', id}, [channel.port2]);
    });
    return configure({...data, id}, client);
  })();
  restoring.set(tag, {promise: recovery, cancel});
  try { return await recovery; } finally { restoring.delete(tag); }
}
let responses = 0;
const perClient = new Map();
async function videoResponse(event, id) {
  const request = event.request;
  if (!validId(id) || request.mode === 'navigate') return new Response(null, {status: 403});
  if (!['GET', 'HEAD'].includes(request.method)) return new Response(null, {status: 405, headers: {Allow: 'GET, HEAD'}});
  if (responses >= 32 || (perClient.get(event.clientId) || 0) >= 8) return new Response(null, {status: 429});
  responses++; perClient.set(event.clientId, (perClient.get(event.clientId) || 0) + 1);
  let finished = false, session, onAbort;
  const cleanup = () => {
    if (finished) return;
    finished = true; responses--;
    const left = perClient.get(event.clientId) - 1;
    if (left) perClient.set(event.clientId, left); else perClient.delete(event.clientId);
    request.signal.removeEventListener('abort', abort);
    if (onAbort) controller.signal.removeEventListener('abort', onAbort);
    session?.controllers.delete(controller);
  };
  const controller = new AbortController();
  const abort = () => controller.abort();
  request.signal.addEventListener('abort', abort, {once: true});
  try {
    session = await recover(id, event.clientId);
    const range = ES3.range(request.method === 'HEAD' ? null : request.headers.get('Range'), session.meta.size);
    const headers = new Headers({'Content-Type': 'video/mp4', 'Accept-Ranges': 'bytes',
      'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff'});
    if (!range) {
      cleanup();
      headers.set('Content-Range', `bytes */${session.meta.size}`);
      headers.set('Content-Length', '0');
      return new Response(null, {status: 416, headers});
    }
    headers.set('Content-Length', String(Math.max(0, range.end - range.start + 1)));
    if (range.status === 206) headers.set('Content-Range', `bytes ${range.start}-${range.end}/${session.meta.size}`);
    if (request.method === 'HEAD' || session.meta.size === 0) {
      cleanup();
      return new Response(null, {status: range.status, headers});
    }
    let position = range.start;
    session.controllers.add(controller);
    const stream = new ReadableStream({
      start(output) {
        onAbort = () => { cleanup(); output.error(controller.signal.reason); };
        controller.signal.addEventListener('abort', onAbort, {once: true});
        if (controller.signal.aborted) onAbort();
      },
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
    cleanup();
    return new Response(safeError(error), {status: 502, headers: {'Cache-Control': 'no-store'}});
  }
}
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin === scope.origin && url.pathname.startsWith(prefix)) {
    event.respondWith(videoResponse(event, url.pathname.slice(prefix.length)));
  }
});
