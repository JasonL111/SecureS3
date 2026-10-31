# SecureS3 安全审计与加固

> 历史范围提示：本报告及 security/evidence.json、ASVS 矩阵针对 bbbb451 的播放器加固快照，不覆盖 feature/vault 新增的 Vault/Argon2id。新增设计与验证见 [VAULT_FORMAT.md](VAULT_FORMAT.md)，不得把历史结果视作新增密码学功能的独立审计。

## 1. Executive Summary

本次是对代码和本地可运行系统进行的应用安全审查，**不是第三方独立认证，不证明企业级合规或“100% 安全”**。审计基线为 `b948c1e12ec086ad2827c39cd0420d45631052e0`，修复版本为包含本报告的 Git 提交。按阶段 A 先保存 [初始报告](security/INITIAL_AUDIT.md)，再修改应用；原协议 `ES3VID01`、分享 JSON v1、纯静态部署和 4 MiB 分块均保持兼容。

已确认并修复 1 项条件型 Medium 本地文件清理问题；另修复 5 组 Low 的输入/生命周期/可用性及误操作防护问题，补强 1 组 Informational 的边界校验。未发现可复现的 Critical、High 或 AES-GCM 认证绕过。**“未发现”只表示已完成范围的结果，不表示未知漏洞不存在。**

关键结论：未持有密钥的对象存储无法仅通过已测试的头部/密文/标签篡改、重排、跨文件替换获得被接受的未认证明文。下载按块认证并事务性写入，失败不报告完成。跨标签页、非播放器页面和跨源文档读取已知虚拟会话路径均被拒绝。Worker 不能防御恶意同源 JavaScript；同源代码、NAS 和观看端仍在各自明示的信任边界内。

最终运行结果：**40 项 Python 测试全部通过、0 失败、0 跳过；其中协议/Worker 包装测试实际运行 14 个 Node 攻击用例，全部通过；另一个全新哈希锁定运行环境的 5 项加密测试也通过**。详细证据和工具版本见 [evidence.json](security/evidence.json)。

线上 Pages/R2 域名、账户配置与日志未提供：实际 TLS/HSTS、边缘响应头、Bucket 列表/写入权限、token 最小权限及缓存策略均为 **Not Verified**，不把示例配置或本地测试当作生产配置已生效。

## 2. Threat Model

| 资产/组件 | 信任与处理 |
|---|---|
| NAS 原始 MP4、AES key、备份 | 可信加密端；需私有目录、稳定普通文件/快照；不防 root、恶意同 UID 或已入侵 NAS。 |
| 每文件 AES-256 key、完整分享 fragment | 解密能力，必须保密；不受账户/中心服务控制，持有即有权解密。 |
| 明文流、解密后文件 | 仅在观看端生成；不能防终端、扩展、录屏、内存/交换区取证。 |
| `.enc`、头部、Range 响应和 CDN | 完全不可信；可被篡改、截断、混合、回放、停滞或返回异常 MIME/编码。 |
| 静态页面及全部同源脚本 | 必须可信；托管发布凭据失陷可替换代码窃取 key。CSP 不能抵御可同时修改同源页面/脚本/策略的人。 |
| WindowClient、Worker、MessageChannel | 依赖浏览器不可伪造的 source/clientId；隔离普通不同页面的会话资源，不把同源页面当独立安全租户。 |
| Python/browser/rclone/TLS 原生实现 | 依赖维护中的平台实现；本次不审计其机器码、硬件、编解码器或全部依赖树。 |

攻击者可提供恶意分享输入、伪造对象响应、在不同 Range 中替换对象、知道非秘密 session ID，或在可写输出目录与加密任务竞争。对 NAS 文件竞争的确认问题是**条件型本地风险**：若环境确实只有可信且不并发改写文件的任务，其主要表现是稳健性缺陷，不能描述成任意远程删文件。

主要路径为输入 → 解析/分配 → 密文网络 → AEAD → 明文媒体/文件，以及页面消息 → Worker 会话 → 虚拟响应。没有用户数据库、登录接口、后端解密、OAuth/JWT、WebSocket、WebRTC 或模板服务。

密码资产：每文件随机 key 256 位、公开 file_id 128 位、nonce 96 位（file_id 前 64 位 + uint32 大端块号）、GCM tag 128 位、AAD 为完整 48 字节头 + uint32 块号；新虚拟会话 ID 128 位 CSPRNG。旧 UUIDv4 临时 ID 为兼容保留，不作为解密凭据。源代码中没有用户实际 key 的清单。

### 密码学结论与限制

- Python 使用 `os.urandom`、`AESGCM.generate_key(256)`，浏览器导入不可导出的 CryptoKey。每次加密生成新 key；相同文件再次加密也不复用 key。
- 每块最多 4 MiB，远低于 SP 800-38D 每次 GCM 调用的明文长度上限；块号在使用前检查，禁止负数、非整数及 uint32 回绕。
- 完整版本、长度、块大小、file_id、保留字和序号均参与 AAD。先通过 GCM 验证再交付明文；空文件也有一个认证标签。
- 数学偏移、末块长度及密文总长验证，Python 与 JS 无符号大端一致，拒绝未知版本/保留字段和 JS 精度溢出。理论格式上限是整数可表示界限，不是对 PB 文件或所有累计密钥使用量的安全/性能保证。
- 文件头在解析后、块 0 认证成功前仅用于受限计算，不引起按总文件长度分配。播放仅验证读取过的块，不能保证未读取部分的完整性；下载验证全部块。
- 不同 key 的 nonce 可相同；同一文件 key 下序号保证唯一。**若人工复用 key，64 位随机文件 nonce 前缀存在生日碰撞风险，AAD 不会修复 nonce 重用导致的 GCM 失密/伪造。不得复用 key。**
- 密文/完整旧文件回放不提供时间新鲜性或撤销；同一 file/key 中已认证相同位置的旧字节可被重放，这是不可变对象模型的剩余风险。未加入无必要的签名/KMS 服务。

## 3. Findings

以下为代码问题的修复前定位；修复后行号见第 4 节。严重度考虑实际攻击条件，而不是机械地把所有测试失败记为漏洞。ASVS 的严格控制缺口单独列示，不能按其数量推断漏洞数量。

### S3-01 — 路径清理竞争可误删原文件

- **严重度 / CWE**：Medium（条件型本地）；CWE-367，CWE-459。CVSS v4.0 **4.4**，`CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`，由 cvss 3.6 计算；本地目录可写和受害者执行加密是必要前提。
- **影响文件**：基线 `encrypt.py:53-56`（及输出目录打开逻辑）。
- **攻击条件**：其他写入方可以替换输出目录条目/父目录；不能把它称作公开网站远程攻击。
- **过程 / 复现**：在 `AESGCM.encrypt` 测试钩子中将本次输出改名，把原视频移入原输出名，再引发 OSError；基线 except 按名字 unlink，删除了原视频。父目录替换同样可能把清理指向另一文件。
- **实际影响 / 证据**：`test_failure_cleanup_does_not_delete_replaced_original` 在阶段 A 失败，确认文件被删；硬链接/符号链接原有 O_EXCL 防覆盖则通过，不能混为同一漏洞。
- **建议 / 修复**：固定父目录 fd，拒绝非受信/非 sticky 的他人可写输出目录；创建用 O_EXCL，清理仅针对匹配 dev+ino 的本次文件，使用 dir_fd 操作。
- **状态 / 回归**：已修复；`test_failure_cleanup_does_not_delete_replaced_original`、`test_parent_directory_replacement_does_not_redirect_cleanup`、`test_mutable_shared_output_directory_is_rejected`、`test_hardlinks_and_output_symlinks_never_overwrite_source` 通过。依然不保证对 root/恶意同 UID 的 check-unlink 竞争绝对原子；这些进程不在可信 NAS 假设之外提供隔离。

### S3-02 — 同长度源文件修改未被检测

- **严重度 / CWE / CVSS**：Low，CWE-367；未评分，主要是违反稳定输入约定的本地完整性问题，未确认额外攻击者权限。
- **影响文件**：基线 `encrypt.py:31-48`。
- **攻击条件 / 过程**：录制任务或其他写入者在读取首块后改写相同长度的源文件；基线仅检查长度，仍成功。
- **影响 / 证据**：密文可以认证通过却不对应稳定原文件；不是 GCM 伪造。`test_same_size_source_mutation_fails_and_cleans_outputs` 阶段 A 失败。
- **建议 / 修复**：普通文件 + 非阻塞打开避免 FIFO 卡死，比较 inode、size、mtime_ns、ctime_ns，flush/fsync 输出，在异常时清理本次产物。
- **状态 / 回归**：已修复；上述回归及 `test_fifo_input_is_rejected_without_waiting_for_a_writer`、`test_key_permissions_with_permissive_umask` 通过。NAS 文件系统时间精度/恶意写入仍需只读快照或稳定副本，元数据检测不等同原子快照。

### S3-03 — Worker 同名覆盖、过期提交及关闭竞态

- **严重度 / CWE / CVSS**：Low，CWE-863、CWE-362；未提供网络 CVSS，已证明影响为浏览器内会话破坏/生命周期错误，没有读出其他页面 key 的证据。
- **影响文件**：基线 `web/sw.js:26-51`；异步页面候选状态 `web/app.js:53-69`。
- **攻击条件 / 过程**：另一个受控页面知道目标非秘密 ID，并用自己的有效 key/密文配置同 ID；或 A 配置慢、B 配置快，A 最后覆盖 B；close 到达时 pending 尚未提交。
- **影响 / 证据**：覆盖可使原页面失去自己的会话；旧/已关闭配置可再次留存 key。Node 对应配置/关闭/并发用例在初始阶段失败。**真实浏览器跨标签页读明文在修复前已被拒绝，不声称原来有密钥窃取。**
- **补充验证**：阶段 B 发现 close 还需中止已存在响应和恢复握手，否则捕获会话的流仍能继续/旧恢复可重新提交；新增两用例先失败后修复。
- **建议 / 修复**：检查精确播放器 WindowClient/ID/所有者，拒绝碰撞，最新配置 ticket + abort；恢复合并且可取消；close/替换中止流并移除 key 引用；页面使用局部候选和 revision，pagehide 清空 DOM/key/视频。
- **状态 / 回归**：已修复；`another client cannot overwrite...`、`stale concurrent...`、`close cancels...`、`closing a session...`、`closing during a restore...`（Node），以及浏览器跨标签页/非播放器/跨源、实际 Worker.stopWorker 和并发恢复测试通过。同源代码失陷和已发出的明文不受撤销保证。

### S3-04 — 等待队列/会话无上限及取块无期限等待

- **严重度 / CWE / CVSS**：Low 可用性加固；CWE-400、CWE-772；未评分，恶意存储本来即可拒绝服务，同源恶意代码本来即可耗尽自身浏览器。
- **影响文件**：基线 `web/sw.js:10-22`、`web/protocol.js:56-83`。
- **条件 / 过程 / 证据**：80 个阻塞任务全部排队；存储返回头后永不结束正文会永久占用任务。Node 队列容量和挂起响应测试在基线失败。
- **实际影响**：排队对象可增长、请求槽及块缓冲不能及时释放；没有认定远程跨浏览器资源耗尽。
- **建议 / 修复**：最多 3 活跃、24 排队、32 会话/配置、32 响应、每页 8 响应；Range 总超时 120 秒、配置 30 秒、恢复 5 秒，取消退订，无全文件回退、无自动重试。
- **状态 / 回归**：已修复；Node `worker job queue...`、`worker sessions...`、`stalled response...`；取消、seek、实际 3 GiB 有界写入回归通过。限额并非浏览器进程 RSS 的硬限制，长时间跨设备压力仍 Not Verified。

### S3-05 — 畸形分享 fragment 的额外暴露

- **严重度 / CWE / CVSS**：Low，CWE-209；未评分，原来分享能力本就由持有人/其浏览器看到，没有证明 key 被远程发送。
- **影响文件**：基线 `web/app.js:92-104`。
- **条件 / 过程**：编码格式正确但 JSON 损坏的分享输入，解析异常后不清除地址栏 fragment，并把解析器异常消息拼接显示。
- **影响 / 证据**：错误路径保留敏感能力片段，异常可能含片段；阶段 A `test_malformed_share_never_echoes_secret_and_is_removed` 确认 fragment 残留。不是有效分享链接的既定能力设计本身有漏洞。
- **建议 / 修复**：在解析前清理当前 fragment；错误消息固定；规范 43 字符 key、URL 和 fragment 上限；关闭页面清除 key 字段。
- **状态 / 回归**：已修复；畸形分享、恶意 JSON/scheme/XSS、pagehide、实际 HTTP 路径/头及 console 不含测试 key 的回归通过。无法清除已同步历史、剪贴板及第三方消息服务副本。

### S3-06 — 仅后缀检查可误上传改名后的 key

- **严重度 / CWE / CVSS**：Low 操作防护；条件型 CWE-201；未评分。管理员本来有权用 rclone 上传任意数据，不把主动改名误操作称作鉴权绕过。
- **影响文件**：基线 `upload.sh:7-12`。
- **条件 / 过程 / 影响**：key 文本被改名成 `private.enc`，wrapper 直接上传到公开位置，泄露能力。
- **证据**：阶段 A `test_renamed_key_is_not_uploadable_ciphertext` 的 rclone shim 被调用。
- **建议 / 修复**：上传前验证普通文件、固定魔数/版本/块大小/保留字段/整数和总长；继续使用双引号及 `--`，不开发新上传 SDK。
- **状态 / 回归**：已修复，误命名 key 被拒绝，参数不会作为 shell 命令解释。容器结构检查不能在无 key 的情况下认证密文，也不能防管理员故意构造“合法”外壳泄密。

### S3-07 — 防御性解析与供应链边界

- **严重度 / CWE / CVSS**：Informational（边界加固），CWE-20；无独立可利用漏洞，未评分。
- **影响文件**：基线 `web/protocol.js:22-26,56-83`、`requirements.txt:1` 和 `.gitignore`。
- **条件 / 过程**：单独调用 auth 接受回绕 index（实际 decryptBlock 已先调用 block，因此不可用来绕过现有认证）；Number 接受非十进制 CL（真实浏览器通常先拒绝）；直接 helper 可在请求前缺少分配上限，URL 规范化可能变长。
- **影响 / 证据**：Node 边界用例失败；未证明恶意网络能绕过浏览器 framing 或产生未认证明文。缺少传递依赖哈希本身不等于已发生供应链入侵。
- **建议 / 修复**：校验 auth/index、safe integer、十进制响应头、块级长度、错误页 MIME、原文/规范化 URL 长度；增加生产传递依赖哈希锁和私密文件忽略规则。
- **状态 / 回归**：已补强；Node 6000 次变异包含独立 BigInt Range oracle（不是只检查“不崩溃”），bad header/body/URL/index 测试通过；全新 venv 的 `--require-hashes` 安装及加密回归通过。未改加密格式。应用没有新增生产依赖。

## 4. Remediation

| 文件 | 最终变更与证据 |
|---|---|
| `encrypt.py` | 可信输出目录、固定目录 fd、O_EXCL、inode 清理、普通文件及变化检测、0600 和 fsync；文件系统回归。 |
| `upload.sh` | 标准库结构验证 + 原有安全 rclone 调用；误传回归。 |
| `web/protocol.js` | 认证/整数/范围/头/MIME 校验、120 秒请求上限及 128-bit CSPRNG 会话标识；Node 和 Python/浏览器交叉验证。 |
| `web/sw.js` | 所有权、pending ticket、可取消/合并恢复、流终止、限额、导航拒绝、清理引用；真实浏览器与 Node 竞态测试。 |
| `web/app.js` | 候选状态隔离、canonical key、通用错误、解析前去 fragment、pagehide 清理；分享及生命周期回归。 |
| `web/_headers` | 保留 CSP/no-referrer/nosniff，补 COOP；真实响应镜像/iframe/Worker 探针。 |
| `requirements.lock`、`.gitignore` | 生产 3 个包及制品哈希，忽略本地视频/环境文件等；新 venv 实装。 |
| 测试、README、`security/` | 攻击回归、初始证据、全部 ASVS 条目及工具证据/限制。 |

没有改变 NAS 加密格式或分享 JSON，没有重写播放器/下载模块，没有账户/数据库/后端/新框架。已加密文件无需迁移。代码行号应以修复提交的函数为准；初始发现行号指基线，避免把重排后的行号误当原漏洞位置。

## 5. Security Testing

### 环境与实际结果

Python 3.12.14，cryptography 50.0.0，Playwright 1.62.0，系统 Chromium 154.0.8037.57，FFmpeg 7.1.5，Node 24.19.0；POSIX/Linux 工作区。rclone 1.60.1-DEV 仅检查命令构造和版本，**没有实测生产上传或审计其二进制漏洞**。实际 NAS 的 Python 3.10/文件系统、Edge/Safari/Firefox、移动端及操作系统文件对话框为 Not Verified。

最终命令：

```sh
SECURES3_LARGE_DOWNLOAD_TEST=1 .venv/bin/python -m unittest discover -s tests -v
node tests/security_protocol.cjs
# 在全新、仅含锁定生产依赖的 venv 中另运行：
python -m unittest discover -s tests -p test_encrypt.py -v
```

结果：**40 项 Python 测试全部通过、0 失败、0 跳过；其中协议/Worker 包装测试实际运行 14 个 Node 攻击用例，全部通过；另一个全新哈希锁定运行环境的 5 项加密测试也通过**。实际 3 GiB + 137 字节：769 个块的 SHA-256 全部匹配；真实 MP4 和小/非整块/空文件还有完整文件 SHA-256 对比。大文件用原生 FileSystemWritableFileStream 实际落盘，但自动化把系统对话框替换成测试 FileSystemFileHandle，持久测试配置用来避开无痕 OPFS 配额。**不是人工验证用户系统对话框，也不是多 GB 真实电影的长期端到端生产验证。**

本轮大文件渲染进程合计 RSS：**基线约 299.2 MiB，下载峰值约 604.6 MiB（测试断言增量低于 512 MiB）**。内存复杂度由逐块/背压与有限并行控制；不把约 8 MiB 应用持有的密文/明文数组误称为浏览器整体内存上限。

| 用户要求的攻击面 | 执行证据与结果 |
|---|---|
| 1–9：密文、tag、头、重排、截断、超大长度、index、错误/跨文件 key | `FilesystemSecurityTests`、原有加密回归、Node 格式/整数/auth 测试。所有头字节修改均无法通过原 AAD 认证。 |
| 10–14：恶意 CR/CL、200 替代 206、压缩、断流 | Node mock-response 单测覆盖 JS 校验；真实双源 HTTP 覆盖 200、CR 错、403、连接关闭/截断。浏览器会在 JS 前拒绝部分畸形 CL，未把 mock 成功当真实协议利用。 |
| 15–17：Worker 终止、并行播放/下载、多标签页 | CDP 真正 stopWorker，随后并发恢复、其他标签页拒绝、合法页继续读取；真实 H.264 下载时 Seek 后继续播放。 |
| 18–22：分享/URL、取消/刷新、越权、非播放器页 | 恶意 JSON/scheme/长度，DOM XSS，保存/写入/close 错误和取消重试，pagehide、会话切换，已知 ID 的读/关闭/覆盖。HTTP/console 未观察到测试 key。 |
| 23：Range 间替换对象 | 跨文件密文块 + 原 header/key 的测试必定认证失败；真实 HTTP late-tamper 和不同总长/CR 也失败。未验证真实 CDN 更新/缓存配置。 |
| 24：fuzz | 3000 头部变异 + 3000 结构化 Range，边界包含 2^32、MAX_SAFE_INTEGER、空/末块、非整数索引；Range 使用独立 BigInt oracle，断言同时出现接受/拒绝路径。是有限确定性变异，不是持续覆盖引导 fuzz。 |
| CSP/权限/清理 | 从真实 HTTP 脚本执行 inline/eval 探针；镜像仓库响应头，真实浏览器确认 Worker CSP、frame-ancestors、COOP。拒绝源/目录竞态、FIFO、链接覆盖和宽松 umask。 |

### 自动扫描

扫描工具均位于临时审计 venv，不增加运行依赖。实际版本：Bandit 1.9.4、Semgrep 1.183.0、pip-audit 2.10.1、detect-secrets 1.5.0、CVSS calculator 3.6。

```sh
bandit -r encrypt.py -f json -o /tmp/bandit.json
SEMGREP_SETTINGS_FILE=/tmp/semgrep-settings.yml SEMGREP_LOG_FILE=/tmp/semgrep.log \
  semgrep scan --config security/semgrep.yml --metrics off --disable-version-check \
  --json --output /tmp/semgrep.json web encrypt.py
pip-audit -r requirements-dev.txt --vulnerability-service pypi --format json
# 当前树含 untracked 文件；排除环境和生成产物，历史另逐提交 git archive 扫描：
detect-secrets scan --all-files --exclude-files '(^\.git/|^\.venv/|__pycache__|^\.test-artifacts/)'
```

修复前后 Bandit 均 0 告警；Semgrep 5 条本地规则、5 个生产 JS/Python 文件、0 告警/解析错误；代码树与基线两个可达 Git 提交第一轮秘密扫描无候选；最终证据 JSON 加入后出现 14 个候选，逐项对应已知 Git 提交 ID 或重新计算的源码 SHA-256，均为非凭据摘要，确认秘密为 0；pip-audit 的 **PyPI 漏洞查询成功**，7 个生产/开发及传递依赖无已报告漏洞。版本、包清单及结果在 evidence.json。历史扫描不含不可达 GitHub 对象、其他分支历史、用户磁盘和托管秘密。

限制：这不是完整商业 SAST/DAST，也未覆盖所有 Semgrep 社区规则；Bandit 只看应用 Python。没有运行 Gitleaks（使用 detect-secrets），没有对二进制组件做 SCA。PyPI 无报告漏洞不等于无未披露漏洞，未声称 OSV/NVD 数据库也已查询。自动告警为零仍发现手工可复现问题，结论不依赖零告警。

Semgrep 最初因只读默认用户目录失败，改用其受支持的 settings/log 参数后重跑成功；没有绕过 TLS、包校验或期待的制品哈希。最初直接在 DevTools evaluate 调用 Function 的 CSP 假失败已纠正为页面真实加载脚本，避免制造不存在的 CSP 漏洞。Node 测试直接执行且断言实际注册 14 项，避免仅看 runner 的单文件汇总计数。

## 6. ASVS Mapping

采用 OWASP 官方 **v5.0.0**，源提交 `180622b1329ee7ed349c9f5ce5e14fa91f42c359`，英文 CSV 的 **345 条**，L1/L2/L3 均逐条列于 [ASVS_5.0_MAPPING.csv](security/ASVS_5.0_MAPPING.csv)，包含原文、层级、状态、理由及证据，不用抽样表冒充完整 Level 3 检查。

| 状态 | 数量 | 解释 |
|---|---:|---|
| Pass | 82 | 仅在明确的应用/本地测试范围有代码及执行证据；不是全环境认证。 |
| Fail | 12 | 已明确不满足严格条文，主要为企业控制/治理与设计差异。 |
| N/A | 194 | 无账户/MFA/OAuth/JWT/WebRTC/数据库等，逐项写明理由，不为满足条款虚构服务。 |
| Not Verified | 57 | 部署、流程、二进制、TLS、全平台/压力等证据不足。 |

Fail 包括：静态 CSP 未采用 L3 每响应 nonce/hash、没有 CSP 违反上报端点、允许已有预签名 URL 的敏感 query、无杀毒扫描、无完整 NIST 企业密钥生命周期、固定格式没有任意重配算法、允许任意合法 HTTPS 对象域、无全球过期/撤销、无集中完整安全审计日志/全局采集器。它们不自动构成同等数量的可利用漏洞。**本项目未达到 ASVS Level 3 的完整要求**；不通过引入后端/账号/遥测来掩饰架构取舍。

ASVS 原文归 OWASP，来源为 [官方 v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0)，按其 **CC BY-SA 4.0** 许可引用；本 CSV 的标准文字及衍生标注采用同一许可，不改变应用代码的许可状态。

参考而非认证：WSTG 对输入/XSS/会话/授权/配置/密码的攻击路径；Top 10 对注入、访问控制、供应链和配置；SP 800-38D 对 nonce/tag/每调用边界；SP 800-57 对密钥创建/备份/共享/轮换/销毁；SP 800-53 的 SC-12/SC-13、AC-3、SI-10、AU-2、CM-8、CP-9 仅作控制参考，后者多项实际运营证据未提供。没有声称完成这三份 NIST 标准的全量合规验证。

## 7. Residual Risks

1. **分享能力泄露**：完整链接或 key 可复制、同步、记录；没有中心化撤销。删除公开对象不能撤回其他人的已有副本。只能使用新 key 重加密/重新分发，仍不能使旧副本失效。
2. **静态供应链失陷**：Page/Worker 同源代码可读 DOM key 或用 CryptoKey 解密；CSP 对同源整体失陷不是保证。应独立域名、最小发布权限、人工复核及托管账户 MFA。
3. **终端失陷**：浏览器/扩展/系统可记录明文、历史、剪贴板或文件；不可导出 CryptoKey 不等于不可被恶意代码调用。GC/OS 缓存不保证可验证擦除。
4. **公共密文**：不能公开列举/写入 Bucket，但公开 GET 本身允许永久抓取、流量/请求费用与访问模式分析。CORS 不是鉴权；真实 Bucket/Token/日志配置尚未验证。
5. **一致性与新鲜性**：逐块认证不等于版本/时间新鲜性；必须使用不可变对象名，避免播放时覆盖。支持末尾 moov，但错误/恶意视频编码仍可能攻击浏览器解码器。
6. **资源**：每块有界不代表整个浏览器只有 8 MiB；并发响应、浏览器/原生写盘/GC 还会消耗内存、CPU、磁盘。未完成多小时/多设备压力或 PB 级文件验证。120 秒单块超时可能不适合极慢链路。
7. **NAS/恢复**：目录和源必须可信稳定；检测取决于文件系统时间精度，不防同 UID/root 或硬件故障。两个输出不能跨目录原子提交；断电可能留下需人工检查的密文/空 key，不能误删原文件。key 无备份则数据不可恢复。
8. **兼容性**：下载依赖桌面 FSA；自动化未操作原生系统对话框。实际 NAS、Edge、移动端、生产 HTTPS/R2 均需补充验收；不提供 Blob 兼容回退。
9. **运营治理**：无账户身份审计、HSM、组织 key 台账/统一保留/集中过期；缺少生产证据，不能宣称符合企业敏感数据政策。

## 8. Final Assessment

- **未修复的已确认 Critical：0；High：0；Medium：0。** 已确认的 Low 代码问题均已修复；ASVS Fail/Not Verified 不因此变成 Pass。
- 安全目标 1/4/5：在标准密码算法与可信加密端前提下，代码与攻击测试验证文件中无 key、全部明文经过逐块认证、边界/替换失败关闭；不是密码学不可破解的独立证明。
- 目标 2/3/7：本地实际 HTTP/console 检查和源码证据支持正常静态托管不接收 key/明文，无持久化 key；不能保证生产托管被替换或终端被攻陷时仍保密。
- 目标 6：验证普通页面/标签页/跨源以及 Worker 重启的 clientId 隔离；**不承诺防恶意同源 JS**。
- 目标 8/9：实际 3 GiB 有界流式落盘及原文件哈希、取消/失败清理、并行播放/seek 测试通过；并非所有硬件/大规模/长时间负载保证。
- 目标 10：文档已明确公共密文与能力 key/CORS 的区别；实际 R2/S3 访问权限仍 Not Verified。
- **个人生产使用**：在验证实际 HTTPS/CSP/CORS、受信 NAS/私有输出目录、不可变对象名、key 私密分享与备份并接受不可撤销风险后，可有条件建议使用；仍应先用实际设备/小规模目标文件验收。
- **企业敏感数据**：不建议仅凭本次审查直接采用。需补充独立人工审计、真实部署/权限/TLS/日志/恢复验证和组织治理，评估既定“共享 key + 公共密文 + 无中心撤销”是否符合政策；不应将缺失控制用“企业级认证”替代。
