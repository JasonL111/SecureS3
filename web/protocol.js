/* Shared by the page, worker and tests. No dependencies. */
'use strict';
globalThis.ES3 = (() => {
  const CHUNK = 4194304, HEADER = 48;
  function parseHeader(bytes) {
    if (bytes.byteLength !== HEADER) throw Error('文件头长度错误');
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
    if (!Number.isInteger(index) || index < 0 || index >= meta.count) throw Error('块序号错误');
    const length = Math.min(CHUNK, meta.size - index * CHUNK);
    return {start: HEADER + index * (CHUNK + 16), length};
  }
  function auth(meta, index) {
    const nonce = new Uint8Array(12), aad = new Uint8Array(HEADER + 4);
    nonce.set(meta.bytes.subarray(24, 32));
    new DataView(nonce.buffer).setUint32(8, index);
    aad.set(meta.bytes);
    new DataView(aad.buffer).setUint32(HEADER, index);
    return {name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128};
  }
  function range(value, size) {
    if (value === null) return {start: 0, end: size - 1, status: 200};
    const m = /^bytes=(\d*)-(\d*)$/.exec(value);
    if (!m || (!m[1] && !m[2]) || size === 0) return null;
    const a = m[1] ? Number(m[1]) : null, b = m[2] ? Number(m[2]) : null;
    if ((a !== null && !Number.isSafeInteger(a)) || (b !== null && !Number.isSafeInteger(b))) return null;
    if (a === null) return b > 0 ? {start: Math.max(0, size - b), end: size - 1, status: 206} : null;
    if (a >= size || (b !== null && b < a)) return null;
    return {start: a, end: b === null ? size - 1 : Math.min(b, size - 1), status: 206};
  }
  function decode64(text) {
    if (!/^[A-Za-z0-9_-]+$/.test(text)) throw Error('Base64URL 格式错误');
    return Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  }
  function encode64(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function validateURL(text) {
    const u = new URL(text);
    if (u.username || u.password || u.hash || (u.protocol !== 'https:' &&
        !(u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)))) {
      throw Error('请使用 HTTPS 密文 URL（本地测试允许 localhost）');
    }
    return u.href;
  }
  return {CHUNK, HEADER, parseHeader, block, auth, range, decode64, encode64, validateURL};
})();
