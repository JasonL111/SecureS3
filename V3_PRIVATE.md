# SecureS3 V3：手动预签名与 Private Bucket

开发分支 feature/private-presigned-vault，基于 main `9b91d7b`（已合并 V2）。ES3VID01、ES3VLT01 外层、每文件 AES Key、Vault Key、Argon2id、nonce/AAD/tag 和 4 MiB 视频分块均不变。无新生产依赖、后端、账户、定时任务、Cloudflare Workers 或浏览器签名服务。

## 存储隔离与使用

- **Private 视频 Bucket**：objects/<随机 file_id>.enc，匿名不可读取，NAS 通过既有 rclone 配置签名。签名操作不改变 Bucket ACL，不使其公开。
- **公开 Vault 发布位置**：只有加密 vault.enc，稳定 HTTPS，可由独立公开 Bucket/可信静态托管提供。客户端不需要云端管理凭据，但需要主密码本地解锁。不要依赖 Private 视频 Bucket 的匿名读取。
- **Cloudflare Pages**：同一纯静态前端；storageSources 中 Private 项为 `{id:'r2',name:'R2 Private',type:'presigned'}`，无 baseUrl。公开旧项仍为 id/name/baseUrl。配置 URL 和 Source ID 由用户明确提供，绝不从 remote 猜公开域名。

完整首次准备和可复制命令见 README 的 V3 部分。核心命令：

```sh
python vault.py presign --vault private-vault/vault.enc \
  --source r2 --remote r2:private-bucket --expires 6d \
  --vault-remote public:public-bucket/vault.enc --publish
```

--source 对应前端 ID；--remote 是直接配置的 rclone 视频根。--publish 必须显式指定完整 --vault-remote，且拒绝明显相同 remote 名+bucket 的目标。不同别名是否指向同一物理 Bucket、目标能否匿名读取/CORS 是否正确，程序不能仅从名称证明，必须由部署者验证。无 --publish 只提交本地；--dry-run 解锁并读取本地 rclone 版本/remote 类型、列出 ID/名称与容量估算，不签名、不更新、不上传。

## 加密目录 schema 3

外层仍 ES3VLT01 v1，内部认证 JSON 升至 3。保留 V1 url 记录、V2 objectKey 记录；只有 objectKey 记录可有 access。示例为结构占位，不是有效授权：

```json
{"version":3,"revision":12,"files":[
  {"id":"a83c9f2e71d045b6a92d4c18f0e567ab","name":"Movies/Avatar.mp4","objectKey":"objects/a83c9f2e71d045b6a92d4c18f0e567ab.enc","key":"BASE64URL_FILE_KEY","access":{
    "r2":{"type":"presigned","url":"https://example.invalid/private-bucket/objects/a83c9f2e71d045b6a92d4c18f0e567ab.enc?SIGNED_QUERY","expiresAt":1790000000}
  }}
]}
```

wire 编码仍为无空白 UTF-8 canonical JSON。根固定 version/revision/files；条目固定 id/name/objectKey或url/key，最后可选 access；access 的 Source ID 按 ASCII 字典序，grant 固定 type/url/expiresAt。Python 和浏览器都检查相同字段集合、URL/对象后缀、类型、整数/长度/数量，再比对 canonical 字节表示；拒绝未知/重复/歧义字段与未认证目录。

Source ID 大小写敏感、字母开头、最长 32 位，仅字母/数字/_/-，拒绝保留属性名称；最多 32 个授权来源/文件。expiresAt 为整数 Unix 秒，结构上限为 9999 年末；实际签名只接受 1–604800 秒，默认 6d。URL 最大 8192 字符、ASCII 编码；只有 loopback HTTP 可用于本地协议测试，**NAS presign 返回链接必须 HTTPS**。

根升级不重新生成任何 key；每次只更换指定 Source 的 grant，其他来源、身份、名称、路径和文件 key 保持。更换主密码仍只 rewrap，整个目录密文保持不变。batch-add 重复导入及同一对象的幂等 migrate 会保留已有 access。旧 url 条目只计为 legacy_skipped，不凭 URL 猜 ID/自动迁移。

## 签名、容量与发布事务

1. 交互 getpass 一次，验证并解锁现有 Vault；源/目标参数严格验证，不接受本地路径、内联凭据/选项或路径遍历。
2. `rclone version` / `listremotes --long` 确认实际直接 backend，不读取/打印配置中的 Secret。只支持 rclone 1.60.1+、2.0 之前的 1.x，以及 s3/b2 类型；alias/crypt/union/普通公开链接后端拒绝。
3. 在发出任何 link 请求前估算目录增长。每个对象顺序调用 rclone link，所有输出只在受限内存捕获；临时 URL 不进入明文 Manifest、文件日志或公开 config。
4. 校验 HTTPS、userinfo/fragment/控制字符、长度/编码、bucket/精确对象路径、授权格式/到期范围；批次内 origin 必须一致。不同对象不能复用错误的签名 URL。
5. 按 canonical 记录字节长度跟踪真实增长，最终 encode/validate/seal 并重新认证。保持 4 MiB 明文上限，超限不截断、不丢条目、不扩大协议限制。
6. 全批成功才通过原 VaultFile 的备份、fsync、原子提交更新本地 Vault。签名中途失败旧 Vault/备份不变，不发布半批。
7. 若 --publish，则上传已提交的加密文件。成功意味着 rclone 返回成功，不是已证明公网匿名可读。失败保留新版/旧备份，用 `vault.py upload --vault ... --remote public:public-bucket/vault.enc` 重试，不需要重新签名。

输出只含来源/后端、数量、requested_seconds、expiresAtMin/Max、容量、revision、published 等非 URL 信息；失败只附对象 ID 和受控原因。dry-run 的 files 仅含 ID/名称，不含 key/url/access。估算采用每 URL 约 2 KiB 的保守参考，不是保证；最终以真实编码字节为准。500 个模拟对象实测约 289 KiB，长 STS token/多个来源仍可能超过 4 MiB，必须安全拒绝。

本地提交和远端发布不是分布式原子事务；已经生成但尚未提交的链接不自动撤销。重新签名可生成新期限，不会使旧 URL 或旧分享立即失效。无自动重签/定时刷新/每天提醒/后台队列。

### 子进程边界

参数数组、无 shell，`--` 分隔路径；每次签名默认 45 秒、Vault 上传 120 秒，结束时最多额外 5 秒清理，进程组终止。原有 publish 的大视频传输保留较长的 24 小时有界预算，不套用小 Vault 的期限；原 upload.sh/rclone 手动上传不变。stdout 默认最多 64 KiB、link 最多 8194 字节、stderr 最多 16 KiB；stderr 只计数丢弃，失败不回显第三方诊断。超限/超时/非法编码失败。子进程 stdin 为 DEVNULL，不能额外提示 rclone 密码。

关闭继承的 log_file/log_level/dump/syslog 和 RC 环境设置，显式 ERROR/空 log_file/rc=false，保留既有代理、CA 信任、rclone 认证配置。不会开 rclone RC/常驻服务。NAS 与本地 rclone 二进制/config/PATH 必须可信；不能防恶意二进制主动泄露秘密。若配置加密，应先安全配置 rclone 的非交互读取；Vault 主密码绝不作为 rclone 密码、argv 或环境变量。

## 后端核对与支持范围

核对了当前安装 **rclone v1.60.1-DEV** 的 help/version/listremotes 行为，以及官方仓库的固定 v1.60.1 源码和当前文档/源码。rclone.org 页面在本环境返回 403，改读同一官方仓库的文档镜像，没有跳过 TLS 验证：

- [rclone link 官方实现/命令文档](https://github.com/rclone/rclone/blob/master/cmd/link/link.go)：--expire 并非所有后端都支持，默认可能永久公开。
- [S3 v1.60.1 PublicLink](https://github.com/rclone/rclone/blob/v1.60.1/backend/s3/s3.go#L4014)：先 NewObject（可能 HEAD），GetObjectRequest.Presign，最大一周；当前实现使用 PresignGetObject，语义相同。
- [B2 v1.60.1 getDownloadAuthorization/PublicLink](https://github.com/rclone/rclone/blob/v1.60.1/backend/b2/b2.go#L1367) 和 [官方 B2 文档](https://github.com/rclone/rclone/blob/master/docs/content/b2.md)：PublicLink 未使用传入 expire，实际采用 download_auth_duration，范围 1 秒至一周，要求 shareFiles。

**S3 / R2 / B2 S3**：执行 `rclone link --expire <秒>s -- remote:bucket/objects/<id>.enc`。要求 SigV4 AWS4-HMAC-SHA256、s3/aws4_request scope、请求期限精确一致、合理签发时间、64 hex signature、SignedHeaders 仅 host；允许额外签名 query（如 versionId），不重写参数。返回路径必须匹配请求 bucket/object 的 path-style 或 bucket virtual-host 形式；复杂 endpoint 路径前缀/签名版本不匹配会明确拒绝。验证语法/目标/时限不等于独立密码学验签或证明服务端一定接受。

R2 通常使用其 S3 API endpoint，不能把生成链接替换成 r2.dev/自定义域名。B2 S3 使用同类 SigV4 验证；真实 B2 S3 账户未实测，不保证账户权限、区域和服务商行为。

**B2 Native**：同时显式给 --expire 与 **--b2-download-auth-duration <秒>s**；只接受 `/file/<bucket>/<完整对象路径>?Authorization=...`，无 token 的公开永久链接拒绝。expiresAt 保守取调用前 NAS 时间+请求时长，不从不透明 token 猜测。当前实际 rclone+TLS 模拟已捕获并验证 API 中 fileNamePrefix 为完整 `archive/objects/<id>.enc`、validDurationInSeconds 与请求一致。

B2 Native token 是**前缀**授权：能够访问名称以完整 `<id>.enc` 继续开头的对象，不是严格 exact-file scope。规范固定 objects/<32hex>.enc 之间互不为这种前缀，故不授权其他规范视频；但不得手工创建 `<id>.enc.extra` 等后缀对象或将目录 token 代入 Vault。无法把 B2 原生 API 的前缀能力宣称为精确单对象授权；需要严格 exact scope 时选择已确认兼容的 B2 S3 模式。Opaque token 的约束依赖可信 rclone/API 行为，不可能只根据 token 文本验证实际权限。

S3 本地计算签名没有单独的“签名 API”费用，但实际 rclone 可能先 HEAD，后续 Range GET 正常计费。B2 Native 的认证/列举/签发可能产生正常 API 请求；不假设离线/免费。每对象调用一次 rclone，简单且有限制；没有重做 S3 客户端或引入另一套凭据。

## 浏览器、分享和过期

Private 配置来源无 baseUrl；选中该来源时必须有有效 access。选中公开来源时可继续按 V2 拼接；若同一 Source 已有 access，则优先使用该授权，过期不退回公开地址。缺失、过期或 403 不会自动更换来源、猜路径或请求新签名。

所有操作前检查已认证 expiresAt，下载每块、SW 配置/恢复/解密也检查。到期阻止请求，临近一小时内提示风险；HTTP 401/403 明确为可能过期/撤销/权限不足，不称 AES-GCM 损坏。NAS/浏览器时钟偏差、凭据提前撤销、临时凭据期限较短、服务中断仍可让未到期链接失败。

URL 通过解析校验但使用原始字符串，不使用 searchParams.set/sort 或重组签名。保留百分号大小写/参数顺序；仅 GET+Range，无远端 HEAD；虚拟视频 HEAD 仍由 SW 响应。严格 206/Content-Range/长度和逐块 tag 校验不变，不退回整文件读取/Blob/代理。

签名 URL 不放网页列表、HTML 属性或 input value；播放只用内存选中项/SW，video.src 仍随机会话路径。已知过期下载 abort 原生临时写入，不宣布完成。锁定/来源切换仍停止活动播放/下载，清除引用而不声称物理零化 JS 全部副本。

分享仍精确 `{v:1,url,key}` fragment，只含当前视频。S3 链接自带可读签发时间/期限，接收端可作本地时钟检查；B2 Native 旧分享格式不携带 expiresAt，token 不透明，只能提示临时性并依赖服务端 403，不能伪造确切到期时间。若需要传递 B2 精确到期时间就必须改变分享协议，本次选择保留兼容性。旧分享不会随 Vault 重新签名而更新。

应用不 console/log/持久化授权。但网络请求本身必须把 bearer query 交给对象存储，浏览器网络面板/自动 CORS 诊断、服务端访问日志、接收者设备/扩展可能看到 URL，不能承诺对它们隐藏。生产应避免将 query 写入可公开访问的日志，保持 no-referrer、可信静态代码和无第三方分析脚本。

## CORS、发布和兼容顺序

视频 Private Bucket 的示例 CORS（不是认证，需在真实域名验证）：

```json
[{"AllowedOrigins":["https://secures3.pages.dev"],"AllowedMethods":["GET"],"AllowedHeaders":["Range"],"ExposeHeaders":["Content-Range","Content-Length","Accept-Ranges","Content-Type","Content-Encoding","ETag"],"MaxAgeSeconds":3600}]
```

NAS rclone 的 API/HEAD 不依赖浏览器 CORS。公网 GET 签名不能用于远端 HEAD；这里的 GET 规则不会把 Bucket 改成公开。对 .enc 禁用压缩/内容改写，验证正确 206。公开 Vault 也需允许 Pages GET，响应 no-store，避免 CDN 长期缓存旧授权；上传会请求 Cache-Control:no-store，但实际持久化/边缘规则仍需实测。

先部署新版 Web → NAS presign → 上传加密 Vault → 浏览器刷新库。V1/V2 仍可读，原公开模式不强制升级；旧 Web 无法读 schema 3。升级自动保留旧 Vault 备份，不重建 key。回退应先保留当前/备份，使用 list 验证可信旧副本并确认其授权仍可用后再决定发布；不盲目覆盖唯一最新版本，不删除云对象/原视频。

## 剩余风险

公开 Vault 可离线猜弱密码；主密码/既有 Vault Key 泄露影响全库。旧 Vault+旧密码可恢复同一 Vault Key，密码 rewrap 不能阻止其读取将来仍用该 key 加密的新授权/目录。已发 key/明文或仍有效的旧 URL 无法仅靠重签撤回。需要按实际泄露情况重建独立 Vault/Key，不能假装重新签名就恢复保密。

托管恶意 JS/同源脚本、NAS/rclone 或终端失陷仍可窃密。私有 Bucket 不防服务商看列表、文件大小、访问模式；不透明名称不是权限认证。临时 URL 泄露可导致密文获取/流量费用；含 AES key 的分享可解密已取得数据。无 DRM、登录、中心撤销、后台可用性保证或企业认证。

私有 ACL 与授权到期由服务商执行，恶意服务商本身仍能获取/散布密文；AES 才保护视频内容，不能把到期控制宣称为对服务商本身的密码学撤销。

## 实际测试与扫描

2026-10-31 最终源码全套执行 **114 项通过，0 失败、0 跳过，298.642 秒**。包含原有 90 项、新增签名/CLI/进程 12 项、实际 rclone 本地 TLS 后端 3 项、真实浏览器 V3 集成 9 项；既有安全包装还实际调用 14 个 Node 协议/Worker 攻击测试。

环境：Linux x86_64、Python 3.12.14、cryptography 50.0.0、Playwright 1.62.0、Chromium 154、Node 24.19.0、FFmpeg 7.1.5、rclone v1.60.1-DEV。真实 3 GiB + 137 字节批量处理仍通过 96 MiB RLIMIT_AS，峰值 RSS 34200 KiB；独立浏览器 3 GiB 原生保存验证全部 769 块 SHA-256，渲染进程 RSS 基线/峰值约 308.6/606.0 MiB。两项大文件测试明确执行，不能把 NAS 进程内存观测混同整个浏览器的上限。

```sh
python -m unittest discover -s tests -p test_presign.py -v
python -m unittest discover -s tests -p test_rclone_backend.py -v
python -m unittest discover -s tests -p test_presign_ui.py -v
SECURES3_LARGE_DOWNLOAD_TEST=1 python -m unittest discover -s tests -v
```

| 测试范围 | 已实际运行的验证 |
|---|---|
| 批量签名 | 10/500 对象，匹配完整 objectKey；独立子进程输出；名称/ID/AES Key/Vault Key 不变；重复签名无重复记录；另一来源不覆盖旧 grant；旧 URL 保留 |
| 主密码/CLI | mock 计数一次及真实 PTY 执行 vault.py presign，一次 getpass、无密码回显/argv/URL 输出；schema 3 真实 CLI 路径可解锁；更换密码只 rewrap，主体/文件 key 不变 |
| 事务/容量 | 第 287 个失败后原 Vault/备份不变、不上传部分结果；签名成功后发布失败保留新版，upload 单独重试不再 link；实际接近 4 MiB 的合法目录扩展超限时拒绝、不截断；估算/最终字节均检查 |
| 恶意返回 | HTTP/永久 URL、错对象/错 bucket/中途 origin 变化、fragment、重复 Query、坏编码、过长/多行输出、错误 TTL/签发时间/签名头、未知后端/remote/Source ID、非法发布目标均拒绝 |
| 进程边界 | stdout/stderr 洪泛、timeout、调试 env/RC 设置，子进程被终止、诊断不回显；路径使用参数数组/--；小 Vault 与原大视频 publish 保留不同有限传输预算 |
| 实际 rclone S3 | 当前安装 rclone 连接本地 HTTPS S3 模拟 API，校验 CA 开启；真实元数据 HEAD 后生成 SigV4 GET，target/TTL/SignedHeaders:host 验证 |
| 实际 rclone B2 Native | 本地 HTTPS B2 API 模拟，验证 7200 秒 API 字段及完整 archive/objects/<id>.enc 前缀；allPublic 返回无 token 永久链接被拒绝；不使用真实账户 |
| 浏览器 | 真实 Chromium + 本地 HTTP loopback Range 授权模拟；原始 Query 顺序/百分号大小写保留、跨 origin、视频播放/72 秒 Seek、虚拟 HEAD 不触发远端 HEAD、原生流式保存 SHA-256 相同 |
| 期限/分享 | 缺失/过期在动作前拒绝，403 不误报 AES且不自动重试；下载中途过期 abort 保留旧目标；R2/B2 切换；精确单文件 v1 分享、无痕免主密码、不获取 Vault、旧链接不自动更新 |
| 客户端隔离 | actual SW.stopWorker 后恢复正确 URL/key/期限；其他标签页不能取该会话；过期恢复不发远端请求；signature 不进入 HTML/输入值/虚拟路径/应用 console |
| schema/原功能 | Python/JS canonical access 排序、字段拒绝一致；batch-add/migrate 幂等保留 access；旧公开/legacy 模式继续播放；全部既有 Range/AES/CSP/WASM/Seek/分享/下载测试 |

500 对象的 CLI 使用独立 **rclone 子进程模拟器**，只产生不可用于真实云的合成凭据；生成目录实测 **295426 字节**，不能代表所有真实 STS URL 的长度。真实已安装的 rclone 另连接本地 TLS S3/B2 API，API 调用、scope、期限、CA 验证确实执行，但没有证明任何公网账号策略。浏览器使用真实 Chromium/SW/Web Crypto/媒体解码，HTTP loopback 是安全上下文测试例外，精确 Query 授权为模拟；不声称已验证公网 TLS/CORS 或真实服务端验签。

OS 保存对话框被测试替换为原生 OPFS FileSystemFileHandle，文件流和落盘真实；生产仍使用 showSaveFilePicker。两项 3 GiB 回归明确启用，均为合成数据，不是长时间真实电影/低内存设备压力保证。所有测试凭据只对应模拟环境，配置/证书/捕获管道在临时目录或内存，无真实 Secret/URL 被提交。

补充扫描工具只在临时审计环境安装：

```sh
bandit -q -f json -o /tmp/secures3-v3-bandit.json vault.py batch.py presign.py
semgrep scan --config security/semgrep.yml --metrics off --disable-version-check \
  --exclude web/vendor --json --output /tmp/secures3-v3-semgrep.json \
  vault.py batch.py presign.py web/app.js web/config.js web/download.js \
  web/protocol.js web/sw.js web/vault-crypto.js web/vault.js web/vault-kdf.js
detect-secrets scan --all-files --no-verify vault.py presign.py batch.py \
  web/app.js web/config.js web/download.js web/protocol.js web/sw.js \
  web/vault-crypto.js web/vault.js tests/test_presign.py tests/test_presign_ui.py \
  tests/test_rclone_backend.py tests/rclone_stub.py
```

- Bandit **1.9.4**：2 个 Low（presign.py 的 B404 导入 subprocess / B603 Popen），退出码为 1。人工复核为所需的参数数组、无 shell、受限管道与进程预算，未发现可复现命令注入；保留提示而不隐藏。
- Semgrep **1.183.0**：5 条仓库本地规则、11 个生产目标，0 发现/0 解析错误。不是完整 ASVS 或密码学审计。
- detect-secrets **1.5.0**：3 个候选均人工确认为公开测试密码、模拟器非生产测试 Secret、JS typeof password 检查。关闭在线凭据验证；不等于完整 Git 历史或 NAS 私有资料扫描。
- Python/JS 语法及 diff 检查；生产依赖、encrypt.py、upload.sh、KDF Worker、WASM/CSP 配置保持不变。本次未另查漏洞数据库，不宣称不存在所有已知依赖漏洞；历史审计不自动覆盖 V3。

**Not Verified**：真实 R2、B2 Native、B2 S3 账户和 Private Bucket 的匿名拒绝/列表/写权限/最小凭据、实际签名接受/撤销/7 天到期执行、CORS/Range/redirect/缓存/域名/TLS/费用；公开 Vault 真正匿名可读与 Cache-Control 持久化；500 个真实云对象全链路；NAS 真实硬件断电；人工 OS 文件保存框；Edge/Firefox/Safari/移动端/低内存与长时间压力；独立第三方审计、恶意托管/失陷 NAS 或终端的防护。没有生产部署或修改云账号。
