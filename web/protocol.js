/* Shared by the page, worker and tests. No dependencies. */
'use strict';
globalThis.ES3 = (() => {
  const CHUNK = 4194304, HEADER = 48;
  function parseHeader(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== HEADER) throw Error('文件头长度错误');
    const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (new TextDecoder().decode(bytes.subarray(0, 8)) !== 'ES3VID01' ||
        v.getUint32(8) !== 1 || v.getUint32(12) !== CHUNK ||
        bytes.subarray(40).some(x => x !== 0)) throw Error('不支持的加密文件格式');
    const big = v.getBigUint64(16);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('文件过大');
    const size = Number(big), count = Math.max(1, Math.ceil(size / CHUNK));
    const total = HEADER + size + count * 16;
    if (count > 2 ** 32 || !Number.isSafeInteger(total)) throw Error('文件边界溢出');
    return {bytes, size, count, total};
  }
  function block(meta, index) {
    if (!Number.isSafeInteger(meta.size) || meta.size < 0 || meta.count !== Math.max(1, Math.ceil(meta.size / CHUNK)) || meta.count > 2 ** 32) throw Error('块元数据错误');
    if (!Number.isInteger(index) || index < 0 || index >= meta.count) throw Error('块序号错误');
    const length = Math.min(CHUNK, meta.size - index * CHUNK);
    return {start: HEADER + index * (CHUNK + 16), length};
  }
  function auth(meta, index) {
    block(meta, index);
    const nonce = new Uint8Array(12), aad = new Uint8Array(HEADER + 4);
    nonce.set(meta.bytes.subarray(24, 32));
    new DataView(nonce.buffer).setUint32(8, index);
    aad.set(meta.bytes);
    new DataView(aad.buffer).setUint32(HEADER, index);
    return {name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128};
  }
  function range(value, size) {
    if (!Number.isSafeInteger(size) || size < 0) throw Error('文件长度错误');
    if (value === null) return {start: 0, end: size - 1, status: 200};
    if (typeof value !== 'string' || value.length > 128) return null;
    const m = /^bytes=(\d*)-(\d*)$/.exec(value);
    if (!m || (!m[1] && !m[2]) || size === 0) return null;
    const a = m[1] ? Number(m[1]) : null, b = m[2] ? Number(m[2]) : null;
    if ((a !== null && !Number.isSafeInteger(a)) || (b !== null && !Number.isSafeInteger(b))) return null;
    if (a === null) return b > 0 ? {start: Math.max(0, size - b), end: size - 1, status: 206} : null;
    if (a >= size || (b !== null && b < a)) return null;
    return {start: a, end: b === null ? size - 1 : Math.min(b, size - 1), status: 206};
  }
  function decode64(text) {
    if (typeof text !== 'string' || text.length > 32768 || !/^[A-Za-z0-9_-]+$/.test(text)) throw Error('Base64URL 格式错误');
    return Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  }
  function encode64(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function validateURL(text) {
    if (typeof text !== 'string' || text.length > 8192 || /[\x00-\x20\x7f\\]/.test(text)) throw Error('视频 URL 无效或过长');
    let u;
    try { u = new URL(text); } catch { throw Error('视频 URL 格式无效'); }
    if (u.href.length > 8192 || u.username || u.password || u.hash || (u.protocol !== 'https:' &&
        !(u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)))) {
      throw Error('请使用 HTTPS 密文 URL（本地测试允许 localhost）');
    }
    return text; // Validate only: preserve signed query bytes, order and percent escapes.
  }
  function checkAccess(expiresAt) {
    if (expiresAt === undefined || expiresAt === null) return;
    if (!Number.isSafeInteger(expiresAt) || expiresAt < 1 || expiresAt > 253402300799) throw Error('临时访问授权元数据无效');
    if (expiresAt <= Date.now()/1000) throw Error('访问授权已过期。请在 NAS 重新运行 presign 并刷新 Vault，或索取新的分享链接。');
  }
  function urlExpiry(text) {
    try {
      const q=new URL(text).searchParams,date=q.get('X-Amz-Date'),ttl=q.get('X-Amz-Expires');
      if (q.get('X-Amz-Algorithm')!=='AWS4-HMAC-SHA256' || !/^[0-9]{8}T[0-9]{6}Z$/.test(date||'') || !/^[1-9][0-9]{0,5}$/.test(ttl||'') || +ttl>604800) return undefined;
      const time=Date.UTC(+date.slice(0,4),+date.slice(4,6)-1,+date.slice(6,8),+date.slice(9,11),+date.slice(11,13),+date.slice(13,15));
      if (new Date(time).toISOString().replace(/[-:]/g,'').replace('.000','')!==date) return undefined;
      return time/1000+Number(ttl);
    } catch {return undefined;}
  }
  function temporaryURL(text) {
    try {const q=new URL(text).searchParams;return q.has('X-Amz-Signature') || q.has('Authorization');} catch {return false;}
  }
  async function fetchBytes(url, start, end, total, signal) {
    url = validateURL(url);
    const length = end - start + 1;
    if (![start, end, length].every(Number.isSafeInteger) || start < 0 || end < start || end >= Number.MAX_SAFE_INTEGER || length > CHUNK + 16 ||
        (total !== null && (!Number.isSafeInteger(total) || total <= end))) throw Error('密文请求范围无效');
    signal?.throwIfAborted();
    const controller = new AbortController();
    const abort = () => controller.abort(signal.reason);
    signal?.addEventListener('abort', abort, {once: true});
    const timer = setTimeout(() => controller.abort(new DOMException('密文请求超时，请检查网络后重试', 'TimeoutError')), 120000);
    let reader;
    try {
      const response = await fetch(url, {headers: {Range: `bytes=${start}-${end}`},
        mode: 'cors', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: controller.signal});
      const fail = async message => { await response.body?.cancel(); throw Error(message); };
      if (response.status === 401 || response.status === 403) return await fail(`访问授权被拒绝（HTTP ${response.status}），可能已过期、撤销或权限不足。请重新 presign 并刷新 Vault，或索取新的分享链接。`);
      if (response.status !== 206) return await fail('存储服务必须返回 HTTP 206；请检查 Range、CORS 和对象 URL');
      const number = text => /^\d{1,16}$/.test(text || '') && Number.isSafeInteger(Number(text)) ? Number(text) : NaN;
      const match = /^bytes (\d{1,16})-(\d{1,16})\/(\d{1,16})$/.exec(response.headers.get('Content-Range') || '');
      if (!match || number(match[1]) !== start || number(match[2]) !== end ||
          !Number.isSafeInteger(number(match[3])) || number(match[3]) <= end ||
          (total !== null && number(match[3]) !== total)) return await fail('存储服务返回了错误的 Content-Range');
      const declared = response.headers.get('Content-Length');
      if (declared !== null && number(declared) !== length) return await fail('存储服务返回了错误的 Content-Length');
      const encoding = response.headers.get('Content-Encoding');
      if (encoding && encoding !== 'identity') return await fail('密文对象不能使用 Content-Encoding 压缩');
      const type = response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase();
      if (type && !['application/octet-stream', 'binary/octet-stream', 'video/mp4'].includes(type)) return await fail('密文对象的 Content-Type 不受支持');
      if (!response.body) throw Error('密文响应正文缺失');
      const bytes = new Uint8Array(length);
      reader = response.body.getReader();
      let offset = 0;
      for (;;) {
        const {done, value} = await reader.read();
        if (done) break;
        if (offset + value.length > length) throw Error('密文响应超出请求范围');
        bytes.set(value, offset); offset += value.length;
      }
      if (offset !== length) throw Error('密文下载中断或长度不足');
      return {bytes, total: number(match[3])};
    } catch (error) {
      controller.abort();
      if (reader) await reader.cancel().catch(() => {});
      throw error;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reader?.releaseLock();
    }
  }
  async function decryptBlock(session, index, signal) {
    checkAccess(session.expiresAt);
    const b = block(session.meta, index);
    const {bytes} = await fetchBytes(session.url, b.start, b.start + b.length + 15, session.meta.total, signal);
    try { return new Uint8Array(await crypto.subtle.decrypt(auth(session.meta, index), session.key, bytes)); }
    catch { throw Error('AES-GCM 认证失败：密钥错误、文件被修改或对象已替换'); }
  }
  function sessionId() { return Array.from(crypto.getRandomValues(new Uint8Array(16)), x => x.toString(16).padStart(2, '0')).join(''); }
  return {sessionId, CHUNK, HEADER, parseHeader, block, auth, range, decode64, encode64, validateURL, checkAccess, urlExpiry, temporaryURL, fetchBytes, decryptBlock};
})();
