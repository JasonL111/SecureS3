# SecureS3 Vault v1：格式、密钥和操作边界

本格式用于小型加密目录，**不改变 ES3VID01 视频格式**。NAS 是唯一写入端，浏览器只读。版本化 envelope 不是账户、DRM 或中心化撤销服务。

V2 不透明对象升级保留本文的二进制 envelope/密码学设计，增加兼容旧 url 记录的内部 JSON schema 2；新增 objectKey、批量 Manifest 和迁移规则见 [V2_STORAGE.md](V2_STORAGE.md)。下方 schema 1 及既有验证记录继续作为历史兼容规范。

V3 同样保持此外层与主密码设计，仅扩展认证 JSON 至 schema 3 的 access；手动 rclone 预签名、期限和公开 Vault/私有视频隔离见 [V3_PRIVATE.md](V3_PRIVATE.md)。

## 密钥结构与密码编码

```
主密码 --Argon2id--> KEK --AES-256-GCM--> 随机 Vault Key
                                          |
                                      AES-256-GCM
                                          |
                                  目录 + 各文件独立 key
```

主密码原样 UTF-8 编码，**不 trim、不做 NFC/NFKC 或大小写变换**；拒绝孤立 surrogate。新密码至少 12 个 Unicode 码点，最多 1024 UTF-8 字节。建议密码管理器生成的长随机密码/多词口令；12 字符长度本身不保证熵。浏览器解锁接受旧密码的精确 UTF-8 字节，不把较短输入截断或补全。

Argon2id 为 v1.3（0x13 / 19），输出 32 字节。默认 `m=65536 KiB, t=3, p=1`，每 Vault 随机 16 字节 salt。接受范围：m 为 65536–262144 KiB、t 为 3–6、p 为 1–4，并且 m 可被 4p 整除。所有界限在 KDF 前检查；这是安全/资源预算，不支持任意远程参数。可通过 NAS 更换密码时的 `--memory-kib` / `--iterations` 升级。未来算法/KDF 版本需要显式格式升级，未知版本不降级处理。

每个 Vault 生成独立随机 32 字节 Vault Key；每个视频仍用 encrypt.py 已生成的独立随机 AES key。Master Password/KEK/Vault Key 不是视频 key。不得把单个文件 key 当作 Vault Key，也不得把密码直接当 AES key。

## 二进制布局

所有整数为无符号大端。头固定 128 字节：

| 偏移 | 字节 | 内容 |
|---|---:|---|
| 0 | 8 | ASCII `ES3VLT01` |
| 8 | 4 | 格式版本，1 |
| 12 | 4 | KDF ID，1 = Argon2id |
| 16 | 4 | Argon2 版本，19 |
| 20 | 4 | m，KiB |
| 24 | 4 | t，迭代次数 |
| 28 | 4 | p，lanes |
| 32 | 16 | 随机 Vault ID，非秘密 |
| 48 | 16 | KDF salt，非秘密 |
| 64 | 12 | KEK 包装 nonce |
| 76 | 12 | 目录 nonce |
| 88 | 8 | envelope revision，包含密码轮换 |
| 96 | 8 | data revision，最后一次目录修改的 revision |
| 104 | 8 | 目录密文长度 L，含 16 字节 tag |
| 112 | 16 | 保留，必须为零 |
| 128 | 48 | 被包装的 32 字节 Vault Key + 16 字节 tag |
| 176 | L | 目录密文 + 16 字节 tag |

限制：`1 <= data_revision <= revision <= 2^32-1`，目录明文最多 4 MiB，整体最多 **4,194,496 字节**。头不含名称、URL 或文件 key。公开头仍泄露大小、KDF 成本及版本活动，目录加密也不隐藏存储服务自己已知的对象名/访问记录。

### 认证域

标签均为完整 128 位，Web Crypto 显式设置 `tagLength:128`。

- 包装 key：`AESGCM(KEK, wrap_nonce, VaultKey, WRAP_AAD)`。
- `WRAP_AAD = ASCII("SecureS3 Vault wrap v1") || 0x00 || 原始128字节头`。所有 KDF 参数、salt、两种 nonce、ID、长度、两种 revision、保留字段均在此认证。
- 加密目录：`AESGCM(VaultKey, data_nonce, canonical_JSON, DATA_AAD)`。
- `DATA_AAD = ASCII("SecureS3 Vault data v1") || 0x00 || vault_id[16] || uint64_be(data_revision) || uint64_be(L)`。目录 nonce 作为 GCM IV 也受到认证。

解锁先认证整个包装层，再认证整个目录，最后才解析/使用名称、URL、key。浏览器刷新保留的是不可导出 KEK，重新验证完整包装及目录，不用未认证的新包装元数据更新状态。Vault Key 仅临时导入用于目录解密；可变原始缓冲尽力清零，不能保证 JS 字符串、引擎副本或系统内存被物理擦除。

每次目录更新生成新的目录 nonce 和包装 nonce；每次密码轮换使用新 salt、新 KEK 和新包装 nonce。nonce 使用 CSPRNG 的新 96 位值，并拒绝与当前同 key 的 nonce 相同；RNG 故障重复时失败，不复用。随机 IV 的碰撞风险不是数学上的零，约为 q(q-1)/2^97；不得手工复用 IV、替换 RNG 或无限量复用 Vault Key。单调计数不被直接用作 IV，避免恢复旧备份后确定性重复 nonce。修复/恢复时仍需可信最新版本和合理密钥使用期限。

### 为什么需要两种 revision

添加/删除目录：envelope revision 加 1，data revision 取该新 revision，重新加密目录并重新包装 Vault Key。

密码轮换：只递增 envelope revision，data revision 和整个目录密文（包括 tag/nonce）不变；新 salt 派生新 KEK，只重新包装同一 Vault Key。所有视频 `.enc`、单文件 AES key、URL 和分享链接不变。NAS 会重新解密验证新 envelope，但这不是重新加密目录。

浏览器在当前页面保留已认证的 `Vault ID + envelope revision + SHA-256(整个密文文件)` 检查点。更低 revision 或同 revision 不同摘要会拒绝并锁定；可选 config.vaultId 提供受信身份 pin。**页面重载/新设备没有可信历史时，不能检测所有旧版本。**恢复旧 NAS 备份可能造成版本分叉，需要所有者比较可信最新文件和散列；这不是中心化 freshness 协议。

## 目录 JSON

UTF-8、无 BOM，`JSON.stringify` 等价紧凑编码，无多余空白；固定字段顺序如下（每个条目也按示例顺序）。Python 使用 ensure_ascii=False，不转义非 ASCII 字符。只允许这些字段，严格类型；版本和 revision 必须为整数。

```json
{"version":1,"revision":2,"files":[{"id":"0123456789abcdef0123456789abcdef","name":"Movie A.mp4","url":"https://storage.example.com/a.enc","key":"BASE64URL_FILE_KEY"}]}
```

这里 `revision` 等于头部 data revision；不是 envelope revision 的替代。files 最多 10000 项且总明文仍不超过 4 MiB。ID 为 32 个小写 hex 字符；名称为非空 Unicode、最多 1024 UTF-8 字节、无 C0/DEL 控制符。URL 使用 HTTPS（仅 localhost 测试允许 HTTP），ASCII/Punycode host，无 userinfo、fragment、反斜杠/空白控制符；URL 原文及规范化形式受 8192 字符界限限制，路径空格需百分号编码。key 为规范未填充 Base64URL 43 字符（32 字节）。ID、原始 URL 和文件 key 不允许重复。

认证后还会验证 canonical JSON，拒绝重复键、未知字段、歧义类型、非规范表示。仅经过全量认证/校验的目录才能进入 UI。空 files 合法。目录可以包含所有者信任的特殊名称；页面只用 textContent，绝不当 HTML 执行。

## NAS 事务与恢复

VaultFile 使用可信私有 POSIX 目录、固定目录 fd、O_NOFOLLOW、协作 flock 单写者锁。先在同目录写入加密临时文件并 fsync，再原子替换 `.bak` 旧版并 fsync，最后原子替换当前 Vault 并 fsync 目录。init 用不覆盖的原子 link。所有临时/备份都是密文，权限 0600；不产生含 key 的明文目录 JSON。

原子性针对本地一个目录中的文件提交，依赖操作系统/文件系统的 fsync/rename 语义；不是跨 NAS/R2 的分布式事务，也不能保证所有硬件在断电时的行为。失败可能留下一个可验证的新版本或旧版本；不要盲目覆盖唯一备份。`.bak` 可复制到一个新文件名并用 list 验证。NAS 当前受信 vault.enc、其 revision 和 CLI 打印的密文散列是最新版本依据；`.bak` 只是上一版本，不应冒充最新版本。

publish 顺序为：验证/解锁本地 Vault → 加密或验证已有视频 → 预先校验新目录 → 上传视频 → 原子提交本地 Vault → 上传同一份 Vault。视频上传失败时不提交目录；Vault 上传失败时保留已提交本地新版本和视频/key，用 upload 重试，不回滚以免覆盖可能已经成功的云提交。相同输入的 publish 重试不再次追加记录。只上传明确的密文源文件，绝不自动上传原视频、.key、.bak 或整个目录。

## 浏览器与供应链

hash-wasm **4.12.0** 的 Argon2id v1.3 在专用 Worker 中执行，内嵌 WASM 的本地 JS 约 29 KiB。分发包 npm SHA-512 和资产 SHA-256、MIT 许可见 web/vendor/。运行时没有第三方 CDN、动态 JS eval 或远端 WASM 下载。只给 script-src 增加 `wasm-unsafe-eval`，没有 `unsafe-eval`；已用实际响应 CSP 测试 WASM 可运行、JS eval 仍受阻。

我们检查了发布包中的 Argon2 C/TypeScript 参数、编码、内存分配路径和 loader，并通过独立 cryptography/OpenSSL 与浏览器实现的 Unicode/lanes/AES-GCM 交叉向量验证。**没有取得或声称该具体 WASM 构建的独立第三方审计/可重复构建证明**；npm 完整性不是作者/构建机未被攻陷的证明。新的库级权限范围比单视频大，企业敏感数据仍需补充独立评审。

KDF 一次只运行一个 Worker、总超时 30 秒；锁定/切换模式会终止 Worker。Vault 取回最多 4 MiB 元数据、60 秒超时、credentials:omit、cache:no-store；对文件长度、编码、状态和头严格校验，不接受部分 Vault。不要误把这项小元数据的有界整体解密与 GB 视频的逐块流式解密混淆。

## 必须接受的剩余风险

- Master Password 泄露可能暴露全库；公开 Vault 允许离线猜测弱密码，UI 不是服务端限速器。
- 旧 Vault + 旧密码可以恢复同一 Vault Key；密码轮换不能撤销该 key，**也不能阻止其解密未来仍使用同一 Vault Key 的目录**。泄露后需新建独立 Vault/Key；已经泄露的旧视频 key/明文无法撤回。
- 分享链接只含单文件 key，但接收者可复制/另行分享和长期保存；URL 过期只影响后续下载，不撤回 key。
- 托管代码/同源脚本/浏览器扩展或终端失陷仍可窃取密码、KEK、Vault Key 或文件 key。锁定仅释放引用，不保证物理零化所有副本。
- R2/CDN 可删除、拒绝或回滚文件；Cache-Control 和受信内存检查点都不是全球防回滚系统。首次解锁应核对 NAS 的 Vault ID/最新 revision。
- 忘记主密码不能直接解锁 Vault；若 NAS 仍保留各 `.key` 与 URL 映射可重建新库。主密码及单文件 key 都丢失时无法恢复；请备份，不自动删除源视频。

## 实际验证记录（2026-10-31 UTC）

开发分支为 `feature/vault`，基于稳定版 `bbbb451e0d82de0a279bb455f361cad8fa23ee18`。未修改 encrypt.py、upload.sh、web/protocol.js、web/sw.js 或生产依赖锁。开发分核心 Vault、浏览器集成两个阶段；各阶段分别执行对应测试，完成后执行以下全量回归：

```sh
# 在已安装 requirements.lock / requirements-dev.txt 的环境中
python -m unittest discover -s tests -p test_vault.py -v
python -m unittest discover -s tests -p test_vault_ui.py -v
SECURES3_LARGE_DOWNLOAD_TEST=1 python -m unittest discover -s tests -v
```

最终全量结果：**65 项通过，0 失败，0 跳过，132.886 秒**。其中原有 40 项、Vault 核心/跨实现 14 项、Vault UI 11 项；原有安全测试还实际调用了 14 个 Node 协议/Worker 测试。环境为 Linux x86_64、Python 3.12.14、cryptography 50.0.0、Playwright 1.62.0、Chromium 154、Node 24.19.0、FFmpeg 7.1.5、rclone 1.60.1-DEV。

| 范围 | 实际验证 |
|---|---|
| 密码学 | 空库、精确 Unicode/组合字符/p=2 跨实现 Argon2id 和 AES-GCM、错误密码、128 个头字节逐一篡改、包装/目录/tag 篡改、截断、超长、恶意 KDF 参数先拒绝 |
| 密码轮换 | 新密码成功、旧密码对当前版本失败；原 Vault Key、全部文件 key/URL、目录密文字节及 data nonce 均不变 |
| NAS | init/add/list/remove/change-password、真实 PTY getpass 无回显、重复记录、0600、备份认证、替换失败恢复、外部写冲突、随机数失败、非交互密码拒绝 |
| 发布恢复 | 使用真实加密视频、模拟 rclone 成功/失败，验证上传次序、视频失败不更新目录、Vault 上传失败保留本地新版本、重试幂等、原视频不变；检查命令只指向密文且无 shell |
| 私人库 | 100 条已认证记录（2 个真实本地对象，98 个目录规模占位项）、搜索、数量、H.264 播放、跳转 72 秒、库内直接下载且不切换播放、输出 SHA-256 相同 |
| 分享隔离 | 单文件 fragment 精确为 v/url/key；新的无痕上下文无需主密码即可播放，不请求 Vault/Argon2 Worker/vendor；不包含 Vault Key 或其他文件 key |
| 生命周期 | 锁定停止播放/取消下载/释放 UI 引用、解锁中锁定不能晚到重开、其他标签页不能访问会话、实际停止并重启 Service Worker 后原页面恢复 |
| 刷新与前端 | 新 revision、旧 revision 和同 revision 分叉、错误 pin、密码轮换后重新解锁、损坏/空库、无秘密进入 HTTP/console/storage、无效 fragment 回到锁定库、不安全上下文禁用主密码输入 |
| CSP | 实际 HTTP 响应应用 Pages _headers 中的策略；本地 WASM 成功，页面中实际尝试的 JS eval 仍被拦截，未启用 bypass_csp |
| 大文件与原有功能 | 真实 3 GiB + 137 字节经 HTTP Range → Web Crypto → 原生文件流落盘，验证长度与全部 769 个块的 SHA-256；下载渲染进程 RSS 基线/峰值约 298.0/603.9 MiB；原有播放/Seek/下载/攻击回归全部通过 |

浏览器测试仅注入公开 config 和替换系统保存对话框，返回原生 OPFS FileSystemFileHandle / FileSystemWritableFileStream；真实写盘、Range、Web Crypto、Service Worker、CSP、媒体解码均运行于 Chromium，不是用模拟函数宣称端到端成功。生产仍调用 showSaveFilePicker 写入用户选择的位置。3 GiB 是合成数据；内存观测支持有界流式处理，不等于对浏览器所有设备的内存保证。

### 补充扫描及限制

扫描工具只安装在临时审计环境，不加入生产依赖：

```sh
bandit -q -f json -o /tmp/secures3-vault-bandit.json vault.py
semgrep scan --config security/semgrep.yml --metrics off --disable-version-check \
  --exclude web/vendor --json --output /tmp/secures3-vault-semgrep.json \
  vault.py web/app.js web/config.js web/download.js web/protocol.js web/sw.js \
  web/vault-crypto.js web/vault-kdf.js web/vault.js
detect-secrets scan --all-files --no-verify vault.py web/app.js web/config.js \
  web/download.js web/vault-crypto.js web/vault-kdf.js web/vault.js \
  tests/test_vault.py tests/test_vault_ui.py
# 临时目录创建仅包含精确 hash-wasm@4.12.0 的 npm lock 后执行
npm audit --json
```

- **Bandit 1.9.4**：2 个 Low 提示（B404 导入 subprocess，B603 调用 rclone），因此退出码为 1。已人工复核：可信 NAS 上的显式上传命令采用参数数组、无 shell、无密码参数，并用 `--` 结束选项；没有把它们隐藏或当作两项已确认命令注入漏洞。
- **Semgrep 1.183.0**：仓库 5 条本地规则覆盖 9 个生产源码文件，0 发现、0 解析错误；不是完整 OWASP/密码学形式化审计，也不扫描嵌入 WASM 的机器码。
- **detect-secrets 1.5.0**：3 个候选均已人工确认为误报：两条公开 Unicode 测试密码及一条 `typeof password !== 'string'` 类型检查。关闭在线凭据验证，不向第三方发送可能的秘密；未扫描被忽略的 NAS 私有文件，也不能证明不存在所有形式的秘密。
- **npm audit**：对精确 hash-wasm 4.12.0 的漏洞数据库查询成功，返回 0 个已知漏洞（所有严重度均为 0）。这只代表该次数据库查询结果，不是该加密构建无漏洞的证明。Python 生产依赖未变更，原安全审计的结论与范围仍见 SECURITY_AUDIT.md，不将其冒充新 Vault 的独立审计。

**Not Verified**：真实 R2/S3 上传、账户权限、CORS/缓存/上传头在云端的最终持久化效果；真实 NAS 硬件断电；人工操作 OS 保存对话框；Edge/Safari/Firefox/移动端及低内存设备；100 个真实 R2 视频的逐一播放；WASM 独立第三方审计/可重复构建证明；恶意托管代码或已失陷终端的防护。没有部署生产站点或改动 R2 账户。
