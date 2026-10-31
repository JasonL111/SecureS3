'use strict';
globalThis.ES3Vault = (() => {
  function setup(actions, canDownload) {
    const $ = id => document.getElementById(id), C = ES3VaultCrypto;
    const config = globalThis.SECURES3_CONFIG || {};
    const available = isSecureContext && !!globalThis.crypto?.subtle && typeof Worker === 'function';
    $('vault-url').value = typeof config.vaultUrl === 'string' ? config.vaultUrl : '';
    const pin = config.vaultId || '';
    let state = null, mode = 'vault', job = null, fetchJob = null, cached = null, generation = 0, openedURL = '';
    // Non-secret checkpoints live only in this page. A reload cannot guarantee freshness.
    const floors = new Map();
    const status = (text, error = false) => { $('vault-status').textContent = text; $('vault-status').classList.toggle('error',error); };
    function clear() {
      generation++; job?.abort(); job = null;
      fetchJob?.controller.abort(); fetchJob = null; cached = null; state = null;
      $('master-password').value = ''; $('vault-search').value = ''; $('vault-files').replaceChildren(); $('vault-count').textContent = '0 个视频';
      $('vault-unlock').hidden = false; $('vault-library').hidden = true; $('unlock-vault').disabled = !available; $('master-password').disabled = !available;
      actions.stop();
    }
    function lock() {
      clear(); mode = 'vault'; $('heading').textContent = 'SecureS3 Vault';
      $('vault-panel').hidden = false; $('player-panel').hidden = true; $('form').hidden = true;
      status('已锁定。密钥引用已释放；再次使用需重新解锁。');
    }
    function check(candidate) {
      if (pin && (!/^[a-f0-9]{32}$/.test(pin) || candidate.meta.id !== pin)) throw Error('Vault ID 与受信配置不一致');
      const old = floors.get(candidate.meta.id);
      if (old && (candidate.meta.revision < old.revision || (candidate.meta.revision === old.revision && candidate.hash !== old.hash))) throw Error('检测到旧版或冲突 Vault，已拒绝回滚');
      floors.set(candidate.meta.id,{revision:candidate.meta.revision,hash:candidate.hash});
      if (floors.size > 32) floors.delete(floors.keys().next().value);
    }
    function render() {
      if (!state) return;
      const query = $('vault-search').value.toLocaleLowerCase();
      const files = state.data.files.filter(f => f.name.toLocaleLowerCase().includes(query));
      $('vault-count').textContent = query ? `${files.length} / ${state.data.files.length} 个视频` : `${files.length} 个视频`;
      const fragment = document.createDocumentFragment();
      for (const file of files) {
        const row = document.createElement('article'); row.className = 'vault-row';
        const name = document.createElement('span'); name.className = 'vault-name'; name.textContent = file.name; row.append(name);
        const buttons = document.createElement('div'); buttons.className = 'actions';
        for (const [label, action] of [['播放',() => actions.play(file)],['下载',() => actions.download(file)],['分享',() => actions.share(file)]]) {
          const b = document.createElement('button'); b.type = 'button'; b.className = 'secondary'; b.textContent = label;
          b.disabled = label === '下载' && !canDownload;
          b.addEventListener('click',action); buttons.append(b);
        }
        row.append(buttons); fragment.append(row);
      }
      $('vault-files').replaceChildren(fragment);
      if (!files.length) {const p = document.createElement('p');p.textContent = query ? '没有匹配的视频。' : '视频库为空，请在 NAS 添加视频。';$('vault-files').append(p);}
    }
    function show(candidate, url) {
      check(candidate); state = candidate; openedURL = url;
      $('vault-unlock').hidden = true; $('vault-library').hidden = false; $('player-panel').hidden = false; $('form').hidden = true;
      status(`已解锁 · Vault 版本 ${candidate.meta.revision} · 本地解密`);render();
    }
    function prefetch() {
      const url = $('vault-url').value.trim();
      if (!url) return;
      const attempt = generation, controller = new AbortController();
      status('正在获取加密 Vault…');
      const promise = C.fetchVault(url,controller.signal).then(raw => {
        if (attempt === generation) {cached = {url,raw};status('加密 Vault 已获取，请输入主密码本地解锁。');}
        return raw;
      }).catch(() => {if(attempt===generation)status('Vault 获取失败，请检查 URL、CORS 后重试。',true);return null;});
      fetchJob = {url,controller,promise};
    }
    function defaultMode() {
      clear();mode = 'vault';$('heading').textContent = 'SecureS3 Vault';$('vault-panel').hidden = false;
      const fallback = !$('vault-url').value.trim();
      $('player-panel').hidden = !fallback; $('form').hidden = !fallback;
      status(fallback ? '未配置 Vault，可输入其 URL 或直接手动播放。' : '请输入主密码，仅在浏览器本地解锁。');
      if (!available) {status('Vault 需要 HTTPS 或 localhost，以及支持 Web Crypto / Worker 的浏览器。',true);return;}
      if (!fallback) prefetch();
    }
    function shareMode() {
      clear();mode = 'share';$('heading').textContent = '单视频分享';$('vault-panel').hidden = true;$('player-panel').hidden = false;$('form').hidden = false;
    }
    $('vault-unlock').addEventListener('submit',async event => {
      event.preventDefault(); if (job || !available) return;
      let password = $('master-password').value; $('master-password').value = '';
      const url = $('vault-url').value.trim(), attempt = ++generation, controller = new AbortController();job = controller;
      $('unlock-vault').disabled = true;status('正在本地派生密钥并解锁…');actions.stop();
      try {
        if (pin && !/^[a-f0-9]{32}$/.test(pin)) throw Error('Vault ID 配置格式错误');
        const raw = cached?.url === url ? cached.raw : fetchJob?.url === url ? await fetchJob.promise : await C.fetchVault(url,controller.signal);
        controller.signal.throwIfAborted(); if (!raw) throw Error('无法获取 Vault，请重试');
        const unlocking = C.unlock(raw,password,controller.signal);password = null;
        const candidate = await unlocking;
        if (attempt !== generation) return;
        show(candidate,url);
      } catch (e) {if(attempt===generation){lock();status(e.name==='AbortError'?'解锁已取消':e instanceof TypeError?'Vault 网络或配置错误':e.message,true);}}
      finally {password = null;if(attempt===generation){job=null;cached=null;fetchJob=null;$('unlock-vault').disabled=false;}}
    });
    $('refresh-vault').addEventListener('click',async () => {
      if (!state || job) return;
      const prior = state, url = openedURL, attempt = ++generation, controller = new AbortController();job = controller;
      actions.stop();$('vault-files').replaceChildren();$('refresh-vault').disabled=true;status('正在认证最新 Vault…');
      try {
        const raw = await C.fetchVault(url,controller.signal), candidate = await C.open(raw,prior.kek,controller.signal);
        if(attempt===generation)show(candidate,url);
      } catch(e) {if(attempt===generation){lock();status(e instanceof TypeError?'刷新失败，请检查网络后重新解锁。':e.message+'；请重新解锁。',true);}}
      finally {if(attempt===generation)job=null;$('refresh-vault').disabled=false;}
    });
    $('lock-vault').addEventListener('click',lock);$('vault-search').addEventListener('input',render);
    $('vault-mode').addEventListener('click',defaultMode);
    $('manual-mode').addEventListener('click',() => {shareMode();mode='manual';$('heading').textContent='手动播放';});
    window.addEventListener('pagehide',clear);
    return {defaultMode,shareMode,lock};
  }
  return {setup};
})();
