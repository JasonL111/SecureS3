# SecureS3 V2：对象、Manifest 和兼容性

V2 的公开对象模式继续支持；新增 Private Bucket 手动预签名与 schema 3 见 [V3_PRIVATE.md](V3_PRIVATE.md)。本文不声称 V2 的公开地址本身提供授权。

本升级不改变 ES3VID01 的字节布局、nonce、AAD、分块大小或独立文件 AES Key，也不改变 ES3VLT01 的 128 字节头、Argon2id、包装 AAD、Vault Key 或密码轮换流程。没有后端、新生产依赖或云厂商 API。开发分支为 `feature/opaque-object-storage`，基于已合并 Vault 的 main `5e2dde0`；其代码树与已验证的 `feature/vault` 提交 `2b3caf6` 相同。

## 对象名与公开边界

唯一规则：`objects/<32位小写hex file_id>.enc`，直接读取实际容器头第 24–39 字节。encrypt.py 的 CSPRNG 为每次加密生成随机 128 位 file_id 和独立随机 256 位 AES Key；批量命令不接受 File ID 参数。重新加密同一输入也产生新的 ID/key。同一密文的不同云端副本应使用完全相同的相对路径和字节。

ID 是公开标识而非密钥或令牌。不从文件名、时间或内容摘要派生 ID。新生成的任何已占用 ID/目标路径均拒绝，不能覆盖已有密文或 key。恢复/显式迁移仅允许复用经过哈希、File ID、AES-GCM 验证的完全相同密文，不进行覆盖。

文件名不能替代 AEAD：批量工具完整认证所有块；浏览器原有 Range 验证/逐块 AES-GCM 不变，且新对象在播放/下载前核对已认证的头与目录 ID。不会只根据路径接受内容。

128 位随机命名可阻止现实可行的随机路径穷举并隐藏原始名称/目录，不能阻止已知 URL 的下载、云端列举、内容删除/拒绝/回滚、保存公开密文，也不隐藏文件大小、时间、公开头或访问模式。没有真实访问控制或完全元数据隐藏。CORS 只约束浏览器跨域读取，不是认证。

## 私有 Manifest v2

由 batch-encrypt 生成，顶层只允许 version/files；条目固定如下（散列/时间/ID 均为说明占位）：

```json
{
  "version": 2,
  "files": [{
    "id": "a83c9f2e71d045b6a92d4c18f0e567ab",
    "name": "Movies/Avatar.mp4",
    "object_key": "objects/a83c9f2e71d045b6a92d4c18f0e567ab.enc",
    "key_file": "keys/a83c9f2e71d045b6a92d4c18f0e567ab.key",
    "source": {"dev": 1,"ino": 2,"size": 100,"mtime_ns": 3,"ctime_ns": 4,"sha256": "64位小写hex"},
    "cipher_sha256": "64位小写hex"
  }]
}
```

- 无完整云 URL、无直接 AES Key。名称原样保存安全相对 POSIX 路径，保留 Unicode/空格/目录；不做名称 Unicode 规范化，不允许绝对路径、空段、`.`/`..`、反斜杠、盘符前缀或 C0/DEL。不同文件夹的同名文件合法。
- ID/object_key/key_file 必须严格互相对应；不允许任意文件引用、重复 ID/名称、未知/重复 JSON 字段、错误类型或格式。最多 10000 条、JSON 最多 16 MiB；Vault 仍受其 4 MiB 明文总上限约束。
- source 记录输入快照与 SHA-256，cipher_sha256 记录完整容器散列。它们是私有一致性检查，不是抗恶意 NAS 的签名；可信 NAS 是写入端。Manifest 可泄露名称/内容指纹，不能上传。
- 私有目录还保存 `.batch.json`（版本、可信本地 input_dir/output_dir）、`.pending.json`（当前事务，无明文 key）、`.staging/`（本工具临时材料）、Manifest 备份与协作锁。**目录绑定是用户在可信 NAS 上建立的本地配置，不从不可信 Manifest 接受输入/输出根目录。**导入只接受生成的 manifest.json 及完整本地私有目录；不要导入他人构造的 `.batch.json`。
- key_file 只从受控私有 keys/ 读取；cipher 路径只从本地绑定的密文根目录及固定 object_key 读取。每层目录/文件使用 O_NOFOLLOW、固定目录 fd、普通文件及长度检查，拒绝符号链接逃逸、设备/FIFO、路径遍历；Manifest 自身不能指定系统任意文件。私有目录需当前用户所有、0700，key/元数据为 0600。

## 批量事务与恢复

batch-encrypt 递归由 --recursive 控制，默认只处理本层 `.mp4`（大小写不敏感）。不跟随目录符号链接，遇到文件符号链接报错。三个根目录不得互相包含；受管目录不接受符号链接。--dry-run 只列出计划，不创建输出、不派生密码，也不代表已经完成认证验证。

上传目录有额外布局检查：根只允许 objects/，其下只允许规范的 `<id>.enc` 及本工具保留的临时复制名称，且必须为普通文件。混入 `.key`/JSON/原视频/链接会拒绝，不删除这些文件。该检查防误上传，不能认证手工放入的未知对象；受本批次管理/导入/迁移的对象仍逐一验证 AEAD。

逐文件顺序执行：

1. 从固定输入目录安全打开源文件，计算稳定 stat 快照与流式 SHA-256。
2. 在私有 staging 中调用现有 encrypt.encrypt，生成密文和私钥文件。
3. 完整流式认证密文，将解密字节 SHA-256 与源指纹比对；再次核对源快照。
4. 检查 ID/目标不存在；fsync 临时材料及目录，然后原子记录 pending。
5. 在私有 keys/ 和公开 objects/ 内写完整临时副本、校验散列、fsync，以不覆盖的 link 原子发布；再次认证标准路径的结果。
6. 原子写 Manifest 备份与新 Manifest、fsync，最后删除 pending 并清理私有 staging。

加密、散列、认证、复制均按 4 MiB 处理，显式视频缓冲不随文件长度增长。没有整文件读入/Blob，也不把多个视频并行装进内存。目录数据/进度信息随记录数增长，有上述数量/字节上限。大文件需要 staging+公开副本的额外磁盘空间；加密/确认过程中会多次顺序读文件。

重复执行会完整验证已完成的源快照、密文认证、密钥和摘要后跳过。修改/删除源文件、密文损坏、错误 key 均报错，已有材料不覆盖/删除。未被本次非递归扫描选中的旧记录仍被核验并保留。不要把需要修改的媒体混入一个不可变归档批次；源有新版本时使用新的独立批次目录，产生新 ID/key。

崩溃恢复使用同一条命令、同一输入/输出/私有目录。pending 中的材料必须重新验证，完成提交后再处理其他文件；绝不把只有目标文件存在当作成功。中断前还未写 pending 的私有临时材料可清理后重新加密。Manifest 已提交但日志未删的中断不会重复追加。正式对象不会因清理临时 `.copy-<随机值>.tmp` 而删除。

无法验证 pending 时拒绝继续，保留源/日志/临时材料供检查。不要通过盲删日志来“修复”认证错误；从可信备份恢复私有目录，或保留当前证据并使用新批次重新加密。Manifest.bak 是上一完整版本，不一定是最新版本。同步备份整个私有目录及 Vault，而非只备份一个 JSON。

如果现有私有材料存在而 Manifest/目录绑定丢失，拒绝静默初始化空批次覆盖关系。只有初始化刚写入绑定、尚未产生 Manifest/密钥/暂存材料的状态可自动完成初始化。短于 48 字节的坏容器头正常报错；合法的早于 1970 年源文件时间戳可记录并续跑。

依赖 POSIX flock/link/rename/fsync 语义及可信 NAS 文件系统；不是跨文件系统的整体分布式事务，不能保证硬件、控制器或文件系统在真实断电时的全部行为。用户应在批量任务完成后再上传，不能同时把尚在写入的目录同步到云端。

batch-add 一次解锁，先完整验证每个 Manifest 记录/私钥/实际标准密文容器，再统一 seal 并原子提交一次 Vault，保留旧版备份。相同记录跳过，ID/key/名称映射冲突则整批拒绝。不会出现前半批提交而后半批失败的 Vault。导入不需要原视频继续存在，只验证完成时的密文/指纹；后续重复 batch-encrypt 则要求原源快照仍匹配。

## Vault 目录 schema 兼容

加密 envelope 仍是 ES3VLT01 v1；**只升级已认证的内部 JSON schema**。空新库仍可为 schema 1；首次添加不透明对象后成为 schema 2，后续不降级。canonical JSON/AES-GCM、大小上限与 revision 规则保持不变。

```json
{"version":2,"revision":12,"files":[
  {"id":"a83c9f2e71d045b6a92d4c18f0e567ab","name":"Movies/Avatar.mp4","objectKey":"objects/a83c9f2e71d045b6a92d4c18f0e567ab.enc","key":"BASE64URL_FILE_KEY"},
  {"id":"11111111111111111111111111111111","name":"Old movie.mp4","url":"https://old.example/movie.enc","key":"OTHER_BASE64URL_FILE_KEY"}
]}
```

实际编码为无空白 UTF-8，字段顺序如示例；revision 等于原头 data_revision。schema 1 仍严格只接受原 url 记录，schema 2 可混合两类，每个条目只能有 objectKey 或 url 其中之一。字段、重复 ID/key/地址、名称、路径、key 等均在认证成功后严格验证，未认证/不规范目录不进入 UI。

新版 Python/网页完整读取旧 Vault 和旧视频；旧版网页不能读取 schema 2，故需先部署新版客户端再发布升级后的 Vault。没有修改旧分享 `{v:1,url,key}` 格式。密码轮换仍只重新包装原 Vault Key，schema 2 数据主体和全部文件 key 不变。

## 存储源和迁移

storageSources 最多 32 项，公开配置中每项只有 id/name/baseUrl。HTTPS 前缀必须由部署者明确提供，不从 rclone remote 或对象厂商猜测。默认选择第一项；手动切换后所有新操作用当前项，停止此前播放/下载，保留已解锁库。无自动故障转移、域名发现或 Presigned URL 管理。

拼接只使用已验证的 `objects/<ID>.enc`，不使用原始名称作为 URL 路径。前缀禁止用户信息、query/fragment、点段、编码分隔符及控制符，尾部自动补斜杠，Unicode 前缀使用 URL 编码。B2 的 `/file/<bucket>/` 等完整前缀由用户填写。localhost HTTP 是测试例外，不允许普通远端 HTTP。配置错误/无来源时禁用不透明记录操作，但旧 URL 记录仍可使用。

旧记录不自动丢弃或猜测 ID。migrate 接收明确 record ID 与实际本地 `.enc`，使用记录已有 key 完整认证、读取真实头，复制相同字节至标准对象名，替换这一条元数据。未匹配记录保留 url 模式。原 NAS 密文/源视频/单文件 key/旧云对象不删除，旧 Vault 被备份。迁移后先上传标准对象并验证，再上传新版 Vault；旧分享 URL 是否继续有效由旧对象是否保留决定。只有完全相同的已验证目标才可幂等复用，冲突拒绝。

上传仍由用户执行 rclone，建议对象复制带 --immutable 避免修改已有远端对象；Vault 是可更新的单独对象，不用该标记。批量代码不调用网络、rclone、云厂商 API 或同步任务。真实 Bucket 公共读取、匿名列表权限、HTTPS、自定义域名、CORS、Range、缓存和访问费用均由部署者负责；没有远端冲突自动探测。以后私有 Bucket 需要独立合法访问授权机制。

## 剩余风险

Master Password/Vault Key 泄露会影响全库，旧 Vault+旧密码仍可恢复同一 Vault Key，重新包装密码不能撤销旧能力或阻止其读取未来使用同一 Key 的目录。完整分享链接只交付一个独立文件 key，但接收者可长期保存/再分享；更换源不会自动修复已发链接。托管代码、同源脚本或终端失陷仍可窃取秘密。详见 VAULT_FORMAT.md，锁定不保证物理擦除 JS 的全部历史内存。

公开对象的可获取性、长期保留密文、离线弱密码猜测、云服务商可知的元数据、大文件带宽/内存/磁盘压力、浏览器文件保存兼容性均未被不透明命名消除。没有宣称访问控制、DRM、认证合规或“完全零知识元数据”。

## 验证范围与执行方式

2026-10-31 最终全量执行：**90 项全部通过，0 失败、0 跳过，193.906 秒**。包括既有 65 项、新增批量 19 项、新增多云浏览器 6 项；既有 Python 安全测试还实际调用了 14 个 Node 协议/Worker 测试。环境为 Linux x86_64、Python 3.12.14、cryptography 50.0.0、Playwright 1.62.0、Chromium 154、Node 24.19.0、FFmpeg 7.1.5。

真实 **3 GiB + 137 字节**批量处理在子进程 **96 MiB RLIMIT_AS** 下完成，/proc/self/status 的峰值 RSS 为 **34744 KiB**（128 MiB + 137 字节用例为 34904 KiB），包含源指纹、原 encrypt.py、全块认证、标准对象复制及 Manifest 提交。另一个独立的 3 GiB 浏览器原生流式保存用例验证全部 **769 块 SHA-256** 和文件长度，渲染进程 RSS 基线/峰值约 **308.3/607.5 MiB**。两项大文件测试均未跳过；这些是合成数据及本次环境的观测，不是所有设备的进程内存上限或数小时影片测试。

```sh
python -m unittest discover -s tests -p test_batch.py -v
python -m unittest discover -s tests -p test_storage_ui.py -v
# 显式启用批量加密和浏览器保存两项真实 3 GiB 测试
SECURES3_LARGE_DOWNLOAD_TEST=1 python -m unittest discover -s tests -v
```

| 范围 | 实际验证内容 |
|---|---|
| 命名/保密 | 从实际头核对 ID；规范对象/key 路径；独立 key/ID；同一原视频重新加密产生新值；公开目录不含真实名/原目录；拒绝 ID 冲突、半成品目标及混入私有材料/链接 |
| 批量 | 实际加密并导入 500 个小型合成 `.mp4` 后缀输入；空文件、非整块、Unicode、中文/空格/emoji、同名不同文件夹、递归/默认范围、dry-run、验证后续跑 |
| 数据变化 | 源修改/删除、加密期间变化、pre-epoch 时间戳、错 key、空/短头/截断/篡改密文均按实际状态处理，不误判完成 |
| 恢复 | 在 Manifest 提交前及提交后注入 OSError，保留日志并复用相同密文恢复、不重加密/不重复追加；清理自有临时材料；缺失 Manifest/目录绑定时拒绝覆盖旧状态 |
| 私有输入 | 路径遍历、绝对路径、伪造 key/object 路径、重复字段/ID/名称、文件/目录符号链接、输入/输出/私有目录重叠均拒绝 |
| Vault | 一次主密码批量提交及备份、完整验证后提交、相同输入幂等、冲突/坏 key 不改变 Vault、schema 1 和混合 schema 2、密码轮换后 key 与主体不变 |
| 迁移 | 使用实际旧容器及原 key、认证后读 ID；字节相同的标准路径副本；原文件/旧 key/未映射 URL 保留、原 Vault 备份；错 key/目标冲突拒绝 |
| 浏览器 | Chromium 500 条目录，2 个新对象与 1 个旧 URL 实际对象，497 条为规模占位；文件夹/搜索/数量、双来源、72 秒 Seek、原生流下载 SHA-256、建议原名、单文件无痕分享 |
| 来源隔离 | 手动切换不重取 Vault/不重跑 KDF，取消活动播放和下载；缺失/损坏副本不猜路径/不回退；认证成功但容器 ID 不匹配也拒绝；无来源/坏配置仍可用旧 URL |
| URL | R2 式根前缀、B2 式多级前缀、Unicode/百分号编码、无末尾斜杠；非法 scheme、credentials/query/fragment、dot/编码分隔符、恶意 objectKey 拒绝 |
| 原功能 | 旧链接/旧 Vault、播放器/Seek、Range 恶意响应、Worker 多标签隔离/实际重启、下载取消/失败清理、CSP/WASM/禁止 JS eval 等原有测试继续执行 |

500 个合成输入用于批量容器/状态/ID 验证，不宣称测试了 500 部真实影片；浏览器下载和 H.264 播放使用真实本地对象。双来源为不同地址/独立文件目录的 HTTP Range 模拟器，包含不同 origin 和损坏/缺失副本，不是真实 R2/B2 账户。

浏览器保存测试替换 OS 对话框返回原生 OPFS FileSystemFileHandle，真实调用 Web Crypto、Service Worker、网络、文件流、媒体解码，不用 Blob 保存视频。生产仍调用 showSaveFilePicker。NAS 中断为故障注入，不冒充硬件断电实验。

另外通过独立进程实际执行了 `vault.py batch-encrypt --dry-run`、正常加密和再次执行的 CLI smoke：分别无输出、成功 1 个、验证跳过 1 个，均无错误/未打印 key。

### 补充源码扫描

工具安装在临时审计环境，不加入生产依赖：

```sh
bandit -q -f json -o /tmp/secures3-v2-bandit.json vault.py batch.py
semgrep scan --config security/semgrep.yml --metrics off --disable-version-check \
  --exclude web/vendor --json --output /tmp/secures3-v2-semgrep.json \
  vault.py batch.py web/app.js web/download.js web/config.js web/vault-crypto.js \
  web/vault-kdf.js web/vault.js web/protocol.js web/sw.js
detect-secrets scan --all-files --no-verify vault.py batch.py web/config.js \
  web/vault-crypto.js web/vault.js web/app.js web/download.js \
  tests/test_batch.py tests/test_storage_ui.py
```

- Bandit **1.9.4**：2 个 Low（vault.py:17 B404、:389 B603），均为原有兼容上传命令的 subprocess 导入/参数数组调用。人工复核无 shell、无密码参数；批量模块不上传、不启动 rclone。扫描退出码为 1，未隐藏这些提示。
- Semgrep **1.183.0**：仓库 5 条本地规则，10 个生产源码目标，0 发现/0 解析错误；不是完整安全标准认证或密码学形式化审计。
- detect-secrets **1.5.0**：3 个候选均为公开测试密码、测试用 private sentinel 字符串、JS `typeof password` 类型检查；人工确认为误报。--no-verify 禁止向外部服务验证候选，不扫描未纳入的私有 NAS 资料或全部历史。
- 生产依赖、原 Argon2 WASM 资产/来源、encrypt.py、upload.sh、protocol.js、sw.js、KDF Worker 未变；已做差异核对与 Python/JS 语法检查。本次未另行重查 Python/npm 漏洞库，不能宣称不存在所有已知/未知依赖漏洞；原扫描范围见 VAULT_FORMAT.md / SECURITY_AUDIT.md。

**Not Verified**：真实 R2/B2/S3 的公共权限、对象列表、写权限、域名/TLS、CORS/Range/缓存/费用；rclone 在真实账户上的远端 immutable 行为；NAS 硬件/文件系统真实断电；人工 OS 保存对话框、Edge/Firefox/Safari/移动端与低内存设备；500 部真实云视频逐一播放；WASM 独立第三方审计/可重复构建；失陷托管代码/终端的防护。没有进行生产部署或修改任何云账户。
