/* ES3VLT01 format and bounded local cryptography. See VAULT_FORMAT.md. */
'use strict';
globalThis.ES3VaultCrypto = (() => {
  const HEADER = 128, OFFSET = 176, MAX_DATA = 4194304, MAX_FILE = OFFSET + MAX_DATA + 16;
  const encoder = new TextEncoder();
  const wrapLabel = encoder.encode('SecureS3 Vault wrap v1\0');
  const dataLabel = encoder.encode('SecureS3 Vault data v1\0');
  const concat = (...arrays) => { const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0)); let p = 0; for (const a of arrays) {out.set(a, p); p += a.length;} return out; };
  function validateKdf(m, t, p) {
    if (![m,t,p].every(Number.isInteger) || m < 65536 || m > 262144 || t < 3 || t > 6 || p < 1 || p > 4 || m % (4 * p)) throw Error('不支持或过大的 Argon2id 参数');
  }
  function header(raw, complete = true) {
    if (!(raw instanceof Uint8Array) || raw.length < HEADER || raw.length > MAX_FILE) throw Error('Vault 长度错误');
    const bytes = raw.slice(0, HEADER), v = new DataView(bytes.buffer);
    if (new TextDecoder().decode(bytes.subarray(0, 8)) !== 'ES3VLT01' || v.getUint32(8) !== 1 || v.getUint32(12) !== 1 || v.getUint32(16) !== 19 || bytes.subarray(112).some(x => x)) throw Error('不支持的 Vault 格式');
    const m = v.getUint32(20), t = v.getUint32(24), p = v.getUint32(28);
    validateKdf(m,t,p);
    const revision = v.getBigUint64(88), dataRevision = v.getBigUint64(96), length = v.getBigUint64(104);
    if (dataRevision < 1n || dataRevision > revision || revision > 4294967295n || length < 16n || length > BigInt(MAX_DATA + 16) || (complete && OFFSET + Number(length) !== raw.length)) throw Error('Vault 版本或长度错误');
    return {bytes, m,t,p, revision:Number(revision), dataRevision:Number(dataRevision), length:Number(length),
      id:Array.from(bytes.subarray(32,48), x => x.toString(16).padStart(2,'0')).join(''),
      salt:bytes.slice(48,64), wrapNonce:bytes.slice(64,76), dataNonce:bytes.slice(76,88)};
  }
  function utf8(text) {
    if (typeof text !== 'string' || /[\uD800-\uDFFF]/u.test(text)) throw Error('必须使用完整 Unicode 字符');
    return encoder.encode(text);
  }
  function passwordBytes(password) {
    if (typeof password !== 'string' || password.length > 1024) throw Error('主密码过长');
    const bytes = utf8(password);
    if (!bytes.length || bytes.length > 1024) throw Error('主密码长度必须在 1–1024 UTF-8 字节之间');
    return bytes;
  }
  function validateURL(text) {
    if (typeof text !== 'string' || /[\x00-\x20\x7f\\]/.test(text) || !/^https?:\/\//.test(text)) throw Error('Vault 中的视频 URL 无效');
    const url = new URL(text), authority = text.split('/')[2];
    if (!authority || authority.includes('@') || /[^\x00-\x7f]/.test(authority)) throw Error('URL 主机须使用 ASCII/Punycode，且不能含用户信息');
    ES3.validateURL(text);
    if (!url.hostname) throw Error('URL 主机无效');
    return text;
  }
  function relativeName(name) {
    if (typeof name !== 'string' || !name || utf8(name).length > 1024 || /[\x00-\x1f\x7f\\]/.test(name) || /^[A-Za-z]:/.test(name) || name.split('/').some(p => !p || p === '.' || p === '..')) throw Error('视频相对路径无效');
    return name;
  }
  function objectKey(id) {
    if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) throw Error('Object ID 无效');
    return `objects/${id}.enc`;
  }
  function checkFileId(meta, id) {
    const actual = Array.from(meta.bytes.subarray(24,40), x => x.toString(16).padStart(2,'0')).join('');
    if (actual !== id) throw Error('Object ID 与已认证视频文件头不一致');
  }
  function sourceId(id) {
    if (typeof id !== 'string' || !/^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(id) || ['constructor','prototype'].includes(id)) throw Error('临时授权来源 ID 无效');
    return id;
  }
  function validateAccess(access, object) {
    if (!access || Array.isArray(access) || typeof access!=='object' || Object.keys(access).length<1 || Object.keys(access).length>32) throw Error('访问授权目录无效');
    return Object.fromEntries(Object.keys(access).sort().map(id => {
      sourceId(id);const a=access[id];
      if (!a || Array.isArray(a) || Object.keys(a).sort().join(',')!=='expiresAt,type,url' || a.type!=='presigned' || !Number.isSafeInteger(a.expiresAt) || a.expiresAt<1 || a.expiresAt>253402300799 || typeof a.url!=='string' || /[^\x00-\x7f]/.test(a.url)) throw Error('临时授权格式错误');
      validateURL(a.url);const u=new URL(a.url);
      if (!u.pathname.endsWith('/'+object) || !u.search || a.url.includes('#')) throw Error('临时授权与视频对象不一致');
      return [id,{type:'presigned',url:a.url,expiresAt:a.expiresAt}];
    }));
  }
  function storageSources(raw = []) {
    if (!Array.isArray(raw) || raw.length > 32) throw Error('存储源配置格式错误');
    const ids = new Set();
    return raw.map(s => {
      const privateSource=s?.type==='presigned';
      if (!s || Object.keys(s).sort().join(',') !== (privateSource?'id,name,type':'baseUrl,id,name') || typeof s.id !== 'string' || !/^[a-zA-Z0-9_-]{1,32}$/.test(s.id) || ids.has(s.id) || typeof s.name !== 'string' || !s.name || utf8(s.name).length > 128 || /[\x00-\x1f\x7f]/.test(s.name)) throw Error('存储源 ID 或名称无效');
      if(privateSource){sourceId(s.id);ids.add(s.id);return {id:s.id,name:s.name,type:'presigned'};}
      validateURL(s.baseUrl);
      const url = new URL(s.baseUrl);
      if (url.search || url.hash || /[?#]/.test(s.baseUrl)) throw Error('存储源前缀不能含 Query 或 fragment');
      const path = s.baseUrl.slice(s.baseUrl.indexOf('/',s.baseUrl.indexOf('://')+3));
      // Inspect before URL normalization, including encoded dot/slash segments.
      if (s.baseUrl.indexOf('/',s.baseUrl.indexOf('://')+3) !== -1) {
        for (const segment of path.split('/')) {
          const decoded = decodeURIComponent(segment);
          if (decoded === '.' || decoded === '..' || /[/\\\x00-\x1f\x7f]/.test(decoded)) throw Error('存储源路径不能逃逸或包含编码分隔符');
        }
      }
      if (!url.pathname.endsWith('/')) url.pathname += '/';
      ids.add(s.id); return {id:s.id,name:s.name,baseUrl:url.href};
    });
  }
  function resolveAccess(file, source) {
    if (file.objectKey !== objectKey(file.id)) throw Error('对象路径与 Object ID 不一致');
    if (!source) throw Error('请先在 config.js 配置并选择存储源');
    if (file.access && Object.hasOwn(file.access,source.id)) {
      const grant=validateAccess(file.access,file.objectKey)[source.id];ES3.checkAccess(grant.expiresAt);
      return {url:grant.url,expiresAt:grant.expiresAt};
    }
    if (source.type==='presigned') throw Error('此存储源尚未生成访问授权。请在 NAS 上运行 presign 命令并刷新 Vault。');
    const base = storageSources([source])[0].baseUrl, url = new URL(file.objectKey,base);
    if (!url.href.startsWith(base) || url.origin !== new URL(base).origin) throw Error('对象路径逃逸');
    return {url:ES3.validateURL(url.href)};
  }
  function resolveObject(file, source) {return resolveAccess(file,source).url;}
  function validateData(data, revision) {
    const fields = (value, keys) => value && !Array.isArray(value) && typeof value === 'object' && Object.keys(value).sort().join(',') === keys;
    if (!fields(data, 'files,revision,version') || ![1,2,3].includes(data.version) || data.revision !== revision || !Array.isArray(data.files) || data.files.length > 10000) throw Error('Vault 目录格式错误');
    const ids = new Set(), urls = new Set(), keys = new Set();
    const files = data.files.map(f => {
      const opaque = !!f && Object.hasOwn(f,'objectKey'), location = opaque ? 'objectKey' : 'url';
      const hasAccess=!!f && Object.hasOwn(f,'access');
      if (!fields(f, (hasAccess?'access,':'')+(opaque ? 'id,key,name,objectKey' : 'id,key,name,url')) || (opaque && data.version < 2) || (hasAccess && (!opaque || data.version!==3)) || typeof f.id !== 'string' || !/^[a-f0-9]{32}$/.test(f.id) || typeof f.name !== 'string' || !f.name || utf8(f.name).length > 1024 || /[\x00-\x1f\x7f]/.test(f.name)) throw Error('Vault 条目格式错误');
      if (opaque) {relativeName(f.name);if(f.objectKey !== objectKey(f.id))throw Error('对象路径无效');}
      else validateURL(f.url);
      if (typeof f.key !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(f.key) || ES3.encode64(ES3.decode64(f.key)) !== f.key || ES3.decode64(f.key).length !== 32) throw Error('Vault 文件密钥格式错误');
      const address = location + ':' + f[location];
      if (ids.has(f.id) || urls.has(address) || keys.has(f.key)) throw Error('Vault 中存在重复条目');
      ids.add(f.id); urls.add(address); keys.add(f.key);
      const record={id:f.id, name:f.name, [location]:f[location], key:f.key};
      if(hasAccess)record.access=validateAccess(f.access,f.objectKey);
      return record;
    });
    return {version:data.version, revision, files};
  }
  async function derive(password, meta, signal) {
    signal?.throwIfAborted();
    const bytes = passwordBytes(password);
    const worker = new Worker(new URL('vault-kdf.js', location.href));
    let timer, abort;
    try {
      const result = await new Promise((resolve, reject) => {
        abort = () => reject(new DOMException('解锁已取消','AbortError'));
        signal?.addEventListener('abort', abort, {once:true});
        timer = setTimeout(() => reject(Error('主密码派生超时')), 30000);
        worker.onmessage = e => e.data instanceof ArrayBuffer && e.data.byteLength === 32 ? resolve(new Uint8Array(e.data)) : reject(Error('主密码派生失败'));
        worker.onerror = event => { event.preventDefault(); reject(Error('本地 Argon2id 组件无法运行，请检查 WASM 与 CSP')); };
        worker.postMessage({password:bytes, salt:meta.salt, m:meta.m,t:meta.t,p:meta.p}, [bytes.buffer]);
      });
      try { signal?.throwIfAborted(); return await crypto.subtle.importKey('raw', result, 'AES-GCM', false, ['decrypt']); }
      finally { result.fill(0); }
    } finally {
      clearTimeout(timer); signal?.removeEventListener('abort', abort); worker.terminate();
      if (bytes.byteLength) bytes.fill(0);
    }
  }
  async function open(raw, kek, signal) {
    const meta = header(raw); signal?.throwIfAborted();
    let keyBytes, plain;
    try {
      keyBytes = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:meta.wrapNonce,additionalData:concat(wrapLabel,meta.bytes),tagLength:128}, kek, raw.subarray(128,OFFSET)));
      if (keyBytes.length !== 32) throw Error('Vault Key 长度错误');
      const key = await crypto.subtle.importKey('raw',keyBytes,'AES-GCM',false,['decrypt']); keyBytes.fill(0);
      signal?.throwIfAborted();
      plain = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:meta.dataNonce,additionalData:concat(dataLabel,meta.bytes.subarray(32,48),meta.bytes.subarray(96,112)),tagLength:128},key,raw.subarray(OFFSET)));
      signal?.throwIfAborted();
      const text = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(plain);
      const data = validateData(JSON.parse(text),meta.dataRevision);
      if (JSON.stringify(data) !== text) throw Error('Vault JSON 编码不规范');
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256',raw));
      signal?.throwIfAborted();
      return {meta,kek,data,hash:Array.from(digest,x=>x.toString(16).padStart(2,'0')).join('')};
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      throw Error('主密码错误或 Vault 已损坏');
    } finally { keyBytes?.fill(0); plain?.fill(0); }
  }
  async function unlock(raw,password,signal) {
    const meta = header(raw);
    return open(raw,await derive(password,meta,signal),signal);
  }
  async function fetchVault(text, signal) {
    const url = ES3.validateURL(text); signal?.throwIfAborted();
    const controller = new AbortController(), abort = () => controller.abort(signal.reason);
    signal?.addEventListener('abort',abort,{once:true});
    const timer = setTimeout(()=>controller.abort(new DOMException('Vault 下载超时','TimeoutError')),60000);
    let reader;
    try {
      const r = await fetch(url,{mode:'cors',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',signal:controller.signal});
      if (r.status !== 200 || !r.body) {await r.body?.cancel();throw Error('无法获取完整 Vault，请检查 URL、CORS 或有效期');}
      const declared=r.headers.get('Content-Length'), encoding=r.headers.get('Content-Encoding');
      const type=r.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase();
      if(type && !['application/octet-stream','binary/octet-stream'].includes(type)){await r.body.cancel();throw Error('Vault Content-Type 无效');}
      if (encoding && encoding !== 'identity') {await r.body.cancel();throw Error('Vault 不允许 Content-Encoding 压缩');}
      if (declared !== null && (!/^\d{1,8}$/.test(declared) || +declared > MAX_FILE || +declared < OFFSET + 16)) {await r.body.cancel();throw Error('Vault 响应长度无效');}
      reader=r.body.getReader();
      // Fixed 4 MiB metadata bound, never allocate according to untrusted KDF/data length.
      const buffer=new Uint8Array(MAX_FILE);let offset=0,expected=null;
      for(;;){const {done,value}=await reader.read();if(done)break;
        if(offset+value.length>MAX_FILE || (expected!==null && offset+value.length>expected))throw Error('Vault 超过长度限制');
        buffer.set(value,offset);offset+=value.length;
        if(expected===null && offset>=HEADER){expected=OFFSET+header(buffer.subarray(0,HEADER),false).length;if(offset>expected)throw Error('Vault 长度错误');}
      }
      if(expected!==offset || (declared!==null && +declared!==offset))throw Error('Vault 下载被截断');
      return buffer.slice(0,offset);
    } catch(e){controller.abort();await reader?.cancel().catch(()=>{});throw e;}
    finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);reader?.releaseLock();}
  }
  return {HEADER,OFFSET,MAX_FILE,header,validateKdf,validateData,passwordBytes,derive,open,unlock,fetchVault,
    relativeName,objectKey,checkFileId,storageSources,resolveObject,resolveAccess,validateAccess,sourceId};
})();
