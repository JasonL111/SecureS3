# Encrypted S3 Video Player

一个无需后端的 MP4 加密在线播放器。NAS 用 Python 按 4 MiB 分块加密；S3 保存单个密文文件；浏览器通过 Service Worker、HTTP Range 和 Web Crypto 按需解密。原生 `<video controls playsinline>` 支持暂停、音量、全屏和拖动，不生成完整明文 Blob，不使用第三方脚本。

## 快速开始

Python 3.10+，已有 rclone 配置。NAS 加密不需要运行 Web 服务。

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python encrypt.py movie.mp4 -o movie.enc --key-out movie.key
sh upload.sh movie.enc remote:bucket/videos/movie.enc
# 等价命令：rclone copyto movie.enc remote:bucket/videos/movie.enc --progress
```

输出路径必须不存在，避免覆盖数据。源文件不变；错误时删除本次创建的不完整输出。密钥为不带填充的 Base64URL，`.key` 权限为 0600。**只上传 `.enc`，不要上传 `.key`、原始 MP4 或含密钥的目录。** 输入文件在加密期间必须保持不变；不要对正在录制或修改的文件加密。

将 `web/` 的内容部署到 HTTPS 静态网站，在网页输入公开密文 HTTPS URL 和 `.key` 中的内容，点击「加载视频」。点击「复制分享链接」，即可私下分享给观看者。观看者打开链接后自动加载并验证视频，点击原生播放按钮播放；不强制自动播放。

本地开发可执行（仅供本机验证，不能以 file:// 打开）：

```sh
python -m http.server 8000 --bind 127.0.0.1 --directory web
```

localhost 是浏览器允许 Service Worker 的安全上下文例外。生产必须 HTTPS。浏览器直接连接 S3；静态服务器不处理视频、不接收密钥。播放器允许手动粘贴已有 Presigned URL，但不签发、不续期；过期时请替换 URL，保留同一密钥并重新加载。

## 下载原视频

播放器下方的「下载原视频」在视频文件头和密钥验证成功后启用。分享链接进入后同样可直接使用，无需再次输入密钥。点击后选择保存位置，默认从对象 URL 的文件名推断：`movie.mp4.enc` → `movie.mp4`、`test.enc` → `test.mp4`，无法安全推断时用 `video.mp4`；会剔除路径/非法字符及保留名称，保存对话框中仍可改名。

下载要求 **HTTPS（或 localhost）下支持 File System Access API 的桌面 Chrome / Edge**。不支持 `showSaveFilePicker` 的浏览器会显示明确提示并禁用下载，不会回退到整文件 Blob、`a.download` 或第三方下载库。Safari、Firefox、移动端可能仍可在线播放，但不支持本功能所需的直接文件保存。嵌入 iframe 或受浏览器/企业策略限制时，保存对话框也可能被拒绝。

处理流程：用户选择文件 → 打开 `createWritable({keepExistingData:false})` 临时写入流 → 使用当前会话已认证的文件头、不可导出 CryptoKey → 顺序请求每个密文块的精确 HTTP Range → 检查 206、Content-Range 和长度 → 验证 AES-GCM 并解密 → `await writable.write()` → 下一块 → 全部成功且 `close()` 完成后才显示「下载完成」。空文件也会验证其认证标签。保存内容就是原始字节，不转码；名称为 `.mp4` 不代表可以把非 MP4 内容转换为视频。

下载沿用同一 4 MiB 协议，与播放共享 Range 验证和解密函数。一次只处理一个块，不收集分块、不保留整个密文或明文；显式缓冲为一块约 4 MiB 密文及一块约 4 MiB 明文，另有浏览器网络、密码库和文件写入的临时复制。内存复杂度为 **O(4 MiB)**，而不是 O(文件大小)；不能把约 8 MiB 的应用缓冲误认为整个浏览器进程的内存上限。下载与播放的请求/取消控制独立，Seek 和分享功能不变；并行使用仍会竞争网络带宽。

进度以已成功写入的明文字节计算，显示百分比和已写入大小/总大小；完成最后一块后显示「正在完成本地保存」，仅文件流关闭成功才报告完成。点击「取消下载」会中断网络请求，并调用文件流 `abort()`。网络中断、URL 过期、Range 异常、认证失败或磁盘错误同样中止，绝不报告下载完成。修改/重新加载会话或离开页面会请求取消当前下载。取消不能撤回已完成的文件提交；最终提交阶段会禁用取消按钮。

File System Access API 使用临时文件，失败/取消时尽力 `abort()` 丢弃未提交内容，保留目标路径原有文件。浏览器可能保留一个新建的空文件条目；请按需手动删除。不会直接删除用户选择的路径，以免误删已有文件。浏览器崩溃、系统断电和磁盘故障下的清理最终由浏览器/操作系统决定。取消保存对话框不会启动下载；已经打开的系统对话框需要用户自行关闭。

文件写入期间可能需要额外临时磁盘空间；请留足可用容量。第一版不支持断点续传，失败后需重新下载；外部 Presigned URL 需要覆盖整个下载过程的有效期。所有解密和文件写入均发生在观看者设备中，不向服务器上传密钥或明文，不持久化密钥。

## 文件与协议 v1

```
encrypt.py                流式加密 CLI
upload.sh                 调用已有 rclone 配置，仅接收 .enc
requirements.txt          运行依赖
requirements-dev.txt      可选浏览器测试依赖
web/index.html            简洁中文界面、CSP、原生 video
web/style.css             响应式样式
web/app.js                分享链接、页面会话、Worker 生命周期
web/download.js           分块解密下载、原生文件流写入、进度与取消
web/protocol.js           文件头、整数校验、Range 和 AES 参数
web/sw.js                 按需读取/解密、流式响应
web/_headers              Cloudflare Pages 安全响应头
 tests/test_encrypt.py    Python 加密/认证/内存测试
 tests/test_browser.py    本地双源 S3 模拟、真实 Chromium 测试
 tests/test_download.py   下载校验、原生文件流、失败清理与大文件测试
```

所有整数为**无符号、大端序**。文件头固定 48 字节：

| 偏移 | 长度 | 内容 |
|---|---:|---|
| 0 | 8 | ASCII `ES3VID01` |
| 8 | 4 | 版本，固定 1 |
| 12 | 4 | 明文分块大小，固定 4194304 |
| 16 | 8 | 原始明文长度 N |
| 24 | 16 | 每文件随机 file_id（非秘密） |
| 40 | 8 | 保留，必须为 0 |

每文件独立随机 AES-256 密钥。令 `C=4194304`，块数 `B=max(1,ceil(N/C))`，块编号 `i=0..B-1`：

- `nonce = file_id[0:8] || uint32_be(i)`（12 字节）；同一文件内唯一。同一密钥不得重新用于另一个文件，本工具每次重新生成密钥。
- `AAD = 原始48字节文件头 || uint32_be(i)`（52 字节），认证版本、长度、完整 file_id、块大小和块序号。
- 每块为 `AESGCM.encrypt(nonce, plaintext_chunk, AAD)`，末尾附 16 字节认证标签。
- 第 i 块密文起点 `48 + i*(C+16)`；明文长度 `min(C,N-i*C)`。
- 密文总长度 `48+N+16*B`。空文件也有一块：0 字节明文 + 16 字节认证标签，保证文件头和密钥仍可验证。

解析器拒绝未知版本/块大小、非零保留字、超出 JS 精确整数范围的长度/总长及超过 `2^32` 的块数。读取头时验证对象总长；加载时认证第 0 块；其余块在输出任何明文字节前各自认证。密钥从不出现在文件头。格式无隐式填充；Python 与 JS 通过真实浏览器测试交叉验证。

## HTTP Range 与内存

虚拟路径是相对当前部署目录的 `__video__/<随机会话ID>`，不包含密钥或对象 URL。只允许创建会话的页面访问。Worker 的 scope 是当前目录，支持 `/repo/` 子路径；请使用以 `/` 结尾的站点入口或 `index.html`。

支持单段 `bytes=a-b`、`bytes=a-`、`bytes=-n`，跨块及任意位置读取。无 Range 的 GET 返回 200 的 `ReadableStream`，按拉取逐块解密；合法 Range 返回 206 与精确 Content-Range/Content-Length；无效、越界、多段 Range 返回 416 与 `bytes */N`。HEAD 忽略 Range、返回 200 元数据且无正文。空文件 GET 返回空 200，有 Range 返回 416。其他方法返回 405。

S3 每次必须返回**精确匹配**的 206 和 Content-Range（包括总长度）。忽略 Range 的 200、异常范围、长度不符、压缩、截断、网络中断、认证失败都会报错，不回退到整文件下载。加载后中途的失败会终止响应并通知页面；请修复网络/URL 后重新加载，不自动无限重试。

不保留块级缓存，不做全片预取；最多同时进行 3 个块的读取/解密，流通过背压按块输出并支持取消。活动响应还可能各持有一个至多 4 MiB 的块，浏览器自身的媒体缓冲由浏览器管理。内存随并发请求数变化，不随视频时长累积。原生浏览器可能在持续播放时最终读取所有实际视频字节，这与开始前整片下载不同。

Service Worker 可随时被终止。页面保留不可导出的 CryptoKey 和会话信息；Worker 丢失会话后通过 MessageChannel 向**发起请求的页面**索取并重新验证，不依赖 Worker 永久驻留。首次注册等待 controller 接管；不需要手动刷新。页面关闭或刷新后需重新打开分享链接/输入密钥，不将密钥写入 IndexedDB、Cache Storage、localStorage 或日志。只播放当前页面的一个会话。

## S3 配置

允许密文对象被 HTTPS GET/HEAD 访问（仅对象或指定前缀，不必公开列举存储桶）。S3 CORS 示例，将 Origin 替换为实际播放器域名；Origin 不含路径：

```json
[
  {
    "AllowedOrigins": ["https://viewer.example.com"],
    "AllowedMethods": ["GET", "HEAD"],
    "AllowedHeaders": ["Range"],
    "ExposeHeaders": ["Content-Length", "Content-Range", "Accept-Ranges", "ETag"],
    "MaxAgeSeconds": 3600
  }
]
```

GitHub Pages 对应 `https://用户名.github.io`。由存储服务处理 OPTIONS 预检，不把 OPTIONS 写入 AWS 的 AllowedMethods。请保留 Range 和相关响应头；禁用 CDN 对 `.enc` 的自动压缩/内容改写，勿设置 Content-Encoding。用浏览器网络面板确认 206、正确 Content-Range 和 CORS 头。不要通过公开跨域代理绕过 CORS。整个对象必须不可变；重新加密请使用新的对象名和密钥，避免播放期间替换对象。ETag 只供排查，本格式依赖逐块 AEAD 验证完整性。

## 静态部署

**GitHub Pages**：将 `web/` 内容复制到独立 Pages 发布分支的根目录，或用自有 Pages workflow 上传 `web/` artifact，选择 Pages 对应来源。无需构建，不要将 NAS 文件和密钥放入发布目录。项目站点 `/SecureS3/` 可用，脚本和 Worker 使用相对路径。GitHub Pages 不读取 `_headers`；HTML meta 已设置 CSP 和 no-referrer，但 frame-ancestors 需要托管平台响应头支持。

**Cloudflare Pages**：无构建命令，输出目录 `web`；无需 Functions。`web/_headers` 提供 CSP、Referrer-Policy 和 nosniff。默认根目录部署可直接使用；子路径部署需确保同目录静态文件正确映射，并相应调整 `_headers` 的 `/sw.js` 路径。

**Nginx**：将 `web/` 内容放到单独的 HTTPS 站点根目录，示例片段（TLS 证书按现有配置）：

```nginx
root /srv/encrypted-s3-player;
index index.html;
add_header Referrer-Policy "no-referrer" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'; connect-src 'self' https:; media-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'" always;
location / { try_files $uri $uri/ =404; }
```

请不要对不存在的虚拟视频路径做 SPA 重写；由 Worker 拦截它。确保 `.js` 是有效的 JavaScript MIME 类型；不要对 sw.js 配置长时间 immutable 缓存。无需 Service-Worker-Allowed 扩大作用域。子目录部署时把上述目录和路径映射到同一前缀。若自定义 CSP，请同时给 Worker 响应设置允许目标 S3 的 connect-src；有固定对象域名时可将 `https:` 收紧为该域名。不要开启 unsafe-inline 或 unsafe-eval。

## 分享与安全边界

分享格式 `https://viewer.example.com/#<Base64URL(UTF-8 JSON)>`：

```json
{"v":1,"url":"https://storage.example.com/movie.enc","key":"BASE64URL_AES_256_KEY"}
```

fragment 默认不会在页面 HTTP 请求中发送给服务器，密钥不在 query 或虚拟视频路径中。页面解析后从当前地址条移除 fragment，减少暴露；此前的浏览器同步、剪贴板、消息服务或历史记录仍可能保留完整链接。复制按钮可重新生成链接。**持有完整链接即拥有解密能力**；链接没有撤销和访问控制，不是 DRM。

静态页面及其 JavaScript、Worker、托管账户必须可信；恶意代码或浏览器扩展仍能窃取密钥。不要嵌入第三方分析/脚本，不要在 URL query 中放密钥，不要公开记录链接。HTTPS、CSP 和 no-referrer 不能防止被攻陷的同源代码读取页面内密钥。公开密文仍泄露近似原文件大小、访问时间/IP 和分块访问模式。明文在观看者设备中存在，无法禁止保存或录屏。其他同源应用同样需要可信，建议使用独立播放器域名。

## 测试

```sh
python -m pip install -r requirements-dev.txt
# 安装系统 Chromium 和 ffmpeg，或按 Playwright 官方方式安装浏览器并调整可执行路径
python -m unittest discover -s tests -v
# 可选：实际 3 GiB 文件（需至少 8 GiB 临时可用空间，可能需要几分钟）
SECURES3_LARGE_DOWNLOAD_TEST=1 python -m unittest discover -s tests -p test_download.py -v
# 仅 NAS 加密测试，不需要浏览器依赖
python -m unittest discover -s tests -p test_encrypt.py -v
```

浏览器测试使用系统 `chromium`（PATH），FFmpeg 生成 H.264 测试片，两个本地 HTTP 源模拟静态托管和 S3。测试保留严格 CSP，不设置 bypass_csp；测试运行需要本地端口和 Chromium 子进程权限。生产运行仅需 cryptography，Playwright/FFmpeg 仅测试使用，不是转码服务。

验证结果与限制见下方当前执行记录。真实 S3、实际 NAS、多 GB 连续播放、Edge/Safari/Firefox、移动端和公网 HTTPS 托管需在目标环境验收，不能由本地 Chromium 测试代替。只支持浏览器原生解码的 MP4（建议 H.264/AAC）；非 faststart MP4 也能通过末尾 Range 读取 moov；不提供转码。

### 初版执行记录（2026-10-30）

- 独立 `.venv` 中全套 10 个测试通过；系统 Chromium 154、Playwright 1.62、FFmpeg 7.1、Python 3.12、cryptography 50。
- 真实 90 秒 H.264 MP4 播放、跳转到 72 秒/40 秒后继续播放、复制分享链接，以及通过 CDP **真正停止 Worker** 后恢复读取/继续播放通过。
- 测试 MP4 在尾部保留 moov，前面含 64 MiB free atom：只访问密文块 0、1、2、3、16，未在播放前读取完整文件。双源服务验证了跨域读取，播放器部署在 `/viewer/` 子路径。
- Python/JS 交叉验证开头、中间、末尾及跨多个块字节与原文一致；空文件、200/206/416、HEAD、取消、畸形文件头、错误 Range、断网、403 过期、密文篡改和错误密钥均已覆盖。
- Linux 子进程设 96 MiB 地址空间上限，8 MiB/128 MiB 输入均完成；本次实际峰值 RSS 约 26/30 MiB（`/proc/self/status` VmHWM）。这验证加密内存受分块约束；浏览器内存由流背压/无缓存/并发上限约束，未进行数小时内存压力测试。
- 未实测真实云存储、NAS、多 GB 视频、移动设备及 Edge/Safari/Firefox；不宣称这些已验收。真实上传需要你已有的 rclone remote 和可访问对象；本地模拟不需要云账号。

### 下载功能验证记录（2026-10-30）

- `.venv/bin/python -m unittest discover -s tests -v`：21 项中 20 项通过，默认跳过 1 项显式启用的大文件测试。包含全部原有 10 项回归测试及普通下载测试。
- `SECURES3_LARGE_DOWNLOAD_TEST=1 .venv/bin/python -m unittest discover -s tests -p test_download.py -k three_gib -v`：大文件测试单独执行通过，**未跳过**。真实生成并加密 3 GiB + 137 字节数据，使用本地 HTTP Range → 浏览器 Web Crypto → 原生文件流写入磁盘，验证输出长度及全部 769 个分块的 SHA-256。约 71 秒完成该测试；渲染进程合计 RSS 基线约 304 MiB、下载峰值约 596 MiB，非整文件内存缓存。该测试使用多 GB 合成数据，不是数小时的真实影片。
- 小文件、空文件、非整块数据及真实 H.264 MP4 下载后的完整 SHA-256 与原文件一致；分享链接进入后下载可用，下载同时播放并跳到 72 秒后继续播放通过。
- 验证了写入背压和进度、取消后重新下载、会话切换取消、错误密钥、后续块篡改、网络关闭/响应截断、403 过期、非法 Range、磁盘写入/关闭失败，均不会误报完成。取消和失败时预先存在的目标文件保持原样。
- 验证了不支持 File System Access API 的明确提示、取消保存对话框及旧版 Worker 更新后下载可用。没有新增依赖、后端或协议版本；`encrypt.py` 未修改。
- 自动化仅替换系统保存对话框，返回浏览器真实的 FileSystemFileHandle / FileSystemWritableFileStream；文件写入实际落盘。大文件使用独立持久测试配置以避开无痕 OPFS 配额限制。生产调用 `showSaveFilePicker` 保存到用户选择的文件位置，不使用 OPFS。未人工验证桌面操作系统的保存对话框，也未实测 Edge、真实 R2 网络、多小时下载或低内存设备；这些仍需在目标设备验收。
