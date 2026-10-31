'use strict';
importScripts('vault-crypto.js','vendor/argon2.umd.min.js');
self.onmessage = async event => {
  const {password,salt,m,t,p} = event.data;
  try {
    ES3VaultCrypto.validateKdf(m,t,p);
    if (!(password instanceof Uint8Array) || !password.length || password.length > 1024 || !(salt instanceof Uint8Array) || salt.length !== 16) throw Error('Invalid KDF input');
    const derived = await hashwasm.argon2id({password,salt,memorySize:m,iterations:t,parallelism:p,hashLength:32,outputType:'binary'});
    const copy = new Uint8Array(derived); derived.fill(0);
    self.postMessage(copy.buffer,[copy.buffer]);
  } catch {self.postMessage({error:true});}
  finally {if(password instanceof Uint8Array)password.fill(0);}
};
