/* Offline adversarial unit tests. Node is a test runner, never an app backend. */
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {webcrypto, randomUUID} = require('node:crypto');
const {MessageChannel} = require('node:worker_threads');
require('../web/protocol.js');
const E = globalThis.ES3;
const header = size => {
  const b=new Uint8Array(48),v=new DataView(b.buffer);
  b.set(new TextEncoder().encode('ES3VID01'));v.setUint32(8,1);v.setUint32(12,E.CHUNK);v.setBigUint64(16,BigInt(size));return b;
};
const response = (headers={}, body=new Uint8Array(64),status=206) => new Response(body,{status,headers:{'Content-Range':'bytes 0-63/64','Content-Length':'64',...headers}});
test('header and range fuzz: deterministic 6000 hostile cases and integer boundaries',()=>{
  let seed=12983;const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
  for(const size of [0,1,E.CHUNK,E.CHUNK+1,2**32]){
    const m=E.parseHeader(header(size));assert.ok(Number.isSafeInteger(m.total));
    for(const i of [0,m.count-1]){const b=E.block(m,i);assert.ok(b.start+b.length+16<=m.total);}
  }
  for(const b of [header(Number.MAX_SAFE_INTEGER),new Uint8Array(47),new Uint8Array(49)])assert.throws(()=>E.parseHeader(b));
  const m=E.parseHeader(header(E.CHUNK+2));
  for(const i of [-1,0.5,NaN,Infinity,2**32,2**53])assert.throws(()=>E.block(m,i));
  let accepted=0,rejected=0,validRanges=0;
  for(let i=0;i<3000;i++){
    const b=header(random()*2097152);b[random()%48]^=(random()%255)+1;
    let x;try{x=E.parseHeader(b);}catch(e){assert.ok(e instanceof Error);rejected++;}
    if(x){accepted++;assert.ok(Number.isSafeInteger(x.total));assert.ok(x.count>=1&&x.count<=2**32);const block=E.block(x,x.count-1);assert.equal(block.start+block.length+16,x.total);}
    const size=random(),a=random(),z=random();
    const text=[`bytes=${a}-${z}`,`bytes=${a}-`,`bytes=-${z}`,`bytes=-${a}-${z}`,`bytes=${a}-${z},0-1`,'bytes=9007199254740992-','items=0-1','bytes=a-b'][i%8];
    // An independent BigInt oracle keeps implementation Number rounding out of expected results.
    const match=/^bytes=(\d*)-(\d*)$/.exec(text);let expected=null;
    if(size>0&&match&&(match[1]||match[2])){
      const a=match[1]?BigInt(match[1]):null,z=match[2]?BigInt(match[2]):null,n=BigInt(size),max=BigInt(Number.MAX_SAFE_INTEGER);
      if((a===null||a<=max)&&(z===null||z<=max)){
        if(a===null&&z>0n)expected={start:Number(z>=n?0n:n-z),end:size-1,status:206};
        else if(a!==null&&a<n&&(z===null||z>=a))expected={start:Number(a),end:Number(z===null||z>=n?n-1n:z),status:206};
      }
    }
    const actual=E.range(text,size);assert.deepEqual(actual,expected);if(actual)validRanges++;
  }
  assert.ok(accepted>0&&rejected>0&&validRanges>0);
});
test('auth rejects wrapping nonce indices',()=>{
  const m=E.parseHeader(header(1));
  for(const i of [-1,2**32,0.5,NaN])assert.throws(()=>E.auth(m,i));
});
test('remote headers, encodings, extra/truncated data fail closed', async()=>{
  const original=global.fetch;
  try {
    for(const [headers,body,status] of [
      [{'Content-Range':'bytes 1-64/65'},undefined,206],
      [{'Content-Range':'bytes 0-63/9007199254740992'},undefined,206],
      [{'Content-Length':'0x40'},undefined,206],
      [{'Content-Length':'6.4e1'},undefined,206],
      [{'Content-Encoding':'gzip'},undefined,206],
      [{},new Uint8Array(65),206],[{},new Uint8Array(63),206],[{},undefined,200],
      [{'Content-Type':'text/html'},undefined,206],
    ]){
      global.fetch=async()=>response(headers,body,status);
      await assert.rejects(()=>E.fetchBytes('https://objects.test/x',0,63,64,new AbortController().signal));
    }
  } finally {global.fetch=original;}
});
test('fetch allocation and URL lengths are bounded before any request',async()=>{
  let calls=0; const original=global.fetch;global.fetch=async()=>{calls++;return response();};
  try{await assert.rejects(()=>E.fetchBytes('https://objects.test/x',0,Number.MAX_SAFE_INTEGER,null,new AbortController().signal));assert.equal(calls,0);}
  finally{global.fetch=original;}
  assert.throws(()=>E.validateURL('https://objects.test/'+'a'.repeat(20000)));
  assert.throws(()=>E.validateURL('https://objects.test/'+'中文'.repeat(1500)));
  for(const url of ['javascript:alert(1)','data:text/plain,x','file:///x','http://objects.test/x','https://u:p@objects.test/x','https://objects.test/x#secret'])assert.throws(()=>E.validateURL(url));
});
test('stalled response headers and body have a finite timeout', async()=>{
  const originalFetch=global.fetch, originalTimeout=global.setTimeout;
  global.setTimeout=(fn,ms,...args)=>originalTimeout(fn,ms>=1000?15:ms,...args);
  try {
    for(const body of [false,true]){
      global.fetch=async(_url,{signal})=>{
        if(body)return new Response(new ReadableStream({start(c){c.enqueue(new Uint8Array(64));signal.addEventListener('abort',()=>c.error(signal.reason),{once:true});}}),{status:206,headers:{'Content-Range':'bytes 0-63/64','Content-Length':'64'}});
        return new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));
      };
      const c=new AbortController();
      const outcome=await Promise.race([E.fetchBytes('https://objects.test/x',0,63,64,c.signal).then(()=> 'unexpected success',()=> 'rejected'),new Promise(r=>originalTimeout(()=>r('hung'),100))]);
      c.abort();assert.equal(outcome,'rejected');
    }
  }finally{global.fetch=originalFetch;global.setTimeout=originalTimeout;}
});
async function workerHarness(){
  const events={},live=new Map(); let gate=null;
  const metadata={bytes:header(16),size:16,count:1,total:80};
  const sandbox={URL,Map,Set,Promise,Uint8Array,AbortController,DOMException,Headers,Response,ReadableStream,MessageChannel,crypto:webcrypto,setTimeout,clearTimeout,
    importScripts(){},ES3:{...E,fetchBytes:async url=>{if(gate&&url.endsWith('/slow'))await gate.promise;return {bytes:metadata.bytes,total:80};},parseHeader:()=>metadata,decryptBlock:async()=>new Uint8Array(16)},
    self:{registration:{scope:'https://viewer.test/'},addEventListener:(name,fn)=>events[name]=fn,skipWaiting(){},clients:{claim:async()=>{},get:async id=>live.get(id),matchAll:async()=>[...live.values()]}}};
  vm.createContext(sandbox);vm.runInContext(fs.readFileSync(process.env.SECURES3_AUDIT_WORKER || 'web/sw.js','utf8'),sandbox);
  const key=await webcrypto.subtle.importKey('raw',new Uint8Array(32),'AES-GCM',false,['decrypt']);
  const owner=(id,url='https://viewer.test/')=>{const c={id,url,type:'window',postMessage:(_data,ports)=>ports[0].postMessage(null)};live.set(id,c);return c;};
  const configure=(source,id,url='https://objects.test/fast')=>new Promise((resolve,reject)=>{
    try{events.message({source,origin:'https://viewer.test',data:{type:'configure',id,url,key},ports:[{postMessage:resolve}],waitUntil:p=>p.catch(reject)});}catch(e){reject(e);}
  });
  const close=(source,id)=>events.message({source,origin:'https://viewer.test',data:{type:'close',id},ports:[],waitUntil(){}});
  const request=async(source,id,method='HEAD')=>{let response;events.fetch({clientId:source.id,request:{url:'https://viewer.test/__video__/'+id,method,mode:'cors',headers:new Headers(),signal:new AbortController().signal},respondWith:p=>response=p});return response;};
  const head=async(source,id)=>(await request(source,id)).status;
  const hold=()=>{let release;const promise=new Promise(r=>release=r);gate={promise};return release;};
  return {owner,configure,close,head,request,hold,live,sandbox};
}
test('another client cannot overwrite an existing session ID', async()=>{
  const h=await workerHarness(),a=h.owner('a'),b=h.owner('b'),id=randomUUID();
  assert.equal((await h.configure(a,id)).ok,true);
  assert.ok((await h.configure(b,id)).error);
  assert.equal(await h.head(a,id),200);
});
test('only player documents configure and recover sessions',async()=>{
  const h=await workerHarness(),other=h.owner('other','https://viewer.test/unrelated.html');
  assert.ok((await h.configure(other,randomUUID())).error);
});
test('close cancels pending configurations; dead clients cannot retain keys',async()=>{
  for(const dead of [false,true]){
    const h=await workerHarness(),a=h.owner('a'),id=randomUUID(),release=h.hold();
    const pending=h.configure(a,id,'https://objects.test/slow');await new Promise(r=>setTimeout(r,0));
    if(dead)h.live.delete(a.id);else h.close(a,id);
    release();assert.ok((await pending).error);
  }
});
test('stale concurrent configuration cannot supersede the latest session',async()=>{
  const h=await workerHarness(),a=h.owner('a'),idA=randomUUID(),idB=randomUUID(),release=h.hold();
  const pending=h.configure(a,idA,'https://objects.test/slow');await new Promise(r=>setTimeout(r,0));
  assert.equal((await h.configure(a,idB)).ok,true);release();assert.ok((await pending).error);
  assert.equal(await h.head(a,idB),200);
});
test('worker job queue has a fixed capacity',async()=>{
  const h=await workerHarness();
  const result=await vm.runInContext(`(async()=>{let release;const gate=new Promise(r=>release=r);const jobs=Array.from({length:80},()=>limited(()=>gate,new AbortController().signal).then(()=>true,()=>false));await new Promise(r=>setTimeout(r,0));release();return Promise.all(jobs);})()`,h.sandbox);
  assert.ok(result.some(x=>!x));
});

test('session identifiers use 128-bit CSPRNG material',()=>{
  const ids=Array.from({length:1000},()=>E.sessionId());
  assert.equal(new Set(ids).size,1000);assert.ok(ids.every(id=>/^[a-f0-9]{32}$/.test(id)));
});
test('worker sessions have a fixed capacity',async()=>{
  const h=await workerHarness();let accepted=0,rejected=0;
  for(let i=0;i<40;i++){const owner=h.owner('owner'+i);const result=await h.configure(owner,randomUUID());if(result.ok)accepted++;else rejected++;}
  assert.equal(accepted,32);assert.equal(rejected,8);
});

test('closing a session aborts its existing plaintext response',async()=>{
  const h=await workerHarness(),owner=h.owner('a'),id=randomUUID();
  await h.configure(owner,id);const response=await h.request(owner,id,'GET');
  h.close(owner,id);await assert.rejects(()=>response.arrayBuffer());
});
test('closing during a restore handshake cannot recreate the session',async()=>{
  const h=await workerHarness(),owner=h.owner('a'),id=randomUUID();let port;
  owner.postMessage=(_data,ports)=>{port=ports[0];};
  const response=h.request(owner,id);await new Promise(r=>setTimeout(r,0));
  h.close(owner,id);
  const key=await webcrypto.subtle.importKey('raw',new Uint8Array(32),'AES-GCM',false,['decrypt']);
  port.postMessage({url:'https://objects.test/fast',key});
  assert.notEqual((await response).status,200);port.close();
});
