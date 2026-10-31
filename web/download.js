'use strict';
globalThis.ES3Download = (() => {
  function filename(url) {
    try {
      let name = decodeURIComponent(new URL(url).pathname.split('/').pop()).normalize('NFKC');
      if (!/\.enc$/i.test(name)) return 'video.mp4';
      name = name.slice(0, -4).replace(/[<>:"/\\|?*\x00-\x1f\x7f\u200e-\u200f\u202a-\u202e\u2066-\u2069]/g, '_').replace(/^[ .]+|[ .]+$/g, '');
      if (!name) return 'video.mp4';
      if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)) name = '_' + name;
      name = Array.from(name.replace(/\.mp4$/i, '')).slice(0, 60).join('');
      return name + '.mp4';
    } catch { return 'video.mp4'; }
  }
  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KiB', 'MiB', 'GiB', 'TiB'];
    const index = Math.min(units.length - 1, Math.floor(Math.log2(bytes) / 10) - 1);
    return `${(bytes / 1024 ** (index + 1)).toFixed(1)} ${units[index]}`;
  }
  // One block in flight. Await disk writes for backpressure; never collect chunks.
  async function save(session, writable, {signal, onProgress = () => {}}) {
    let written = 0;
    try {
      signal.throwIfAborted();
      onProgress({written, total: session.meta.size, phase: 'downloading'});
      for (let index = 0; index < session.meta.count; index++) {
        signal.throwIfAborted();
        const plain = await ES3.decryptBlock(session, index, signal);
        signal.throwIfAborted();
        await writable.write(plain);
        signal.throwIfAborted();
        written += plain.byteLength;
        onProgress({written, total: session.meta.size, phase: 'downloading'});
      }
      if (written !== session.meta.size) throw Error('下载文件长度不正确');
      signal.throwIfAborted();
      onProgress({written, total: session.meta.size, phase: 'saving'});
      await writable.close(); // Success is reported only after the file is committed.
      return written;
    } catch (error) {
      // File System Access uses a temporary file; abort preserves an existing target.
      await writable.abort().catch(() => {});
      throw error;
    }
  }
  function setup() {
    const button = document.getElementById('download');
    const cancelButton = document.getElementById('cancel-download');
    const progress = document.getElementById('download-progress');
    const size = document.getElementById('download-size');
    const message = document.getElementById('download-status');
    const supported = isSecureContext && typeof window.showSaveFilePicker === 'function';
    const unsupported = '当前浏览器不支持大文件直接保存。请使用 HTTPS 或 localhost 下的最新版桌面 Chrome / Edge。';
    let session = null, task = null, boundToPlayer = true;
    const status = (text, error = false) => { message.textContent = text; message.classList.toggle('error', error); };
    const updateButton = () => { button.disabled = !supported || !session || !!task; };
    const report = ({written, total, phase}) => {
      const percent = total ? written / total * 100 : (phase === 'saving' ? 100 : 0);
      progress.value = percent;
      size.textContent = `下载进度：${percent.toFixed(1)}% · ${formatBytes(written)} / ${formatBytes(total)}`;
      status(phase === 'saving' ? '正在完成本地保存…' : '正在下载并解密…');
      if (phase === 'saving') cancelButton.disabled = true;
    };
    async function start(selected = session) {
      if (!supported) { status(unsupported); return; }
      if (!selected || task) return;
      boundToPlayer = selected === session; // Inputs/session changes must never mix files or keys.
      const controller = new AbortController();
      task = controller; updateButton(); cancelButton.disabled = false;
      status('请选择 MP4 保存位置…');
      let writable;
      try {
        // Call within the click's user activation, before any await or network request.
        const handle = await window.showSaveFilePicker({suggestedName: filename(selected.url),
          types: [{description: 'MP4 Video', accept: {'video/mp4': ['.mp4']}}]});
        controller.signal.throwIfAborted();
        let verified = selected;
        if (!selected.meta) {
          // A library row opens the picker in its click, then validates this one file.
          // It neither switches the playing video nor sends Vault keys to the Worker.
          const url = ES3.validateURL(selected.url);
          const key = await crypto.subtle.importKey('raw', ES3.decode64(selected.key), 'AES-GCM', false, ['decrypt']);
          const header = await ES3.fetchBytes(url, 0, ES3.HEADER - 1, null, controller.signal);
          const meta = ES3.parseHeader(header.bytes);
          if (meta.total !== header.total) throw Error('加密文件总长度不正确');
          verified = {url, key, meta};
          await ES3.decryptBlock(verified, 0, controller.signal);
        }
        controller.signal.throwIfAborted();
        writable = await handle.createWritable({keepExistingData: false});
        await save(verified, writable, {signal: controller.signal, onProgress: report});
        status('下载完成');
      } catch (error) {
        if (error.name === 'AbortError' || controller.signal.aborted) status('下载已取消，未完成的写入已中止。');
        else status(error instanceof TypeError ? '下载失败：请检查网络、CORS 或磁盘可用空间。' : '下载失败：' + error.message, true);
      } finally {
        task = null; cancelButton.disabled = true; updateButton();
      }
    }
    button.addEventListener('click', () => start());
    function cancel() { task?.abort(); }
    cancelButton.addEventListener('click', () => { cancel(); status('正在取消下载…'); cancelButton.disabled = true; });
    if (!supported) status(unsupported);
    return {
      cancel, supported, startFile: start,
      setSession(value) {
        if (session !== value && boundToPlayer) cancel();
        session = value; updateButton();
        if (!task) {
          progress.value = 0;
          size.textContent = `下载进度：0% · 0 B / ${formatBytes(value?.meta.size || 0)}`;
          status(!supported ? unsupported : value ? '视频已验证，可以下载原视频。' : '验证视频后即可下载。');
        }
      }
    };
  }
  return {save, filename, setup};
})();
