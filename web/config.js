// Public configuration only. Never put passwords or keys here.
globalThis.SECURES3_CONFIG = Object.freeze({
  vaultUrl: '', // e.g. https://your-r2-domain.example/vault.enc
  vaultId: '',  // Optional: trusted public ID printed by vault.py (32 lowercase hex).
  // Public: {id:'r2',name:'R2',baseUrl:'https://your-domain/'}
  // Private: {id:'r2',name:'R2 Private',type:'presigned'} (no baseUrl or API secrets).
  storageSources: []
});
