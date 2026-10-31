# SecureS3 阶段 A：修复前审计记录

审计基线：`b948c1e12ec086ad2827c39cd0420d45631052e0`；GitHub main 已读取，和本地一致。此文件在修改应用实现前保存。后续状态及完整标准映射见根目录 `SECURITY_AUDIT.md`。本记录不是认证或第三方审计证明。

## 威胁模型及范围

资产为 AES 密钥、明文视频、源文件和会话归属。可信端为 NAS 加密进程、播放页面及同源脚本；对象存储/CDN/网络返回的数据不可信。考虑畸形分享输入、已知非秘密会话 ID、并发标签页、Worker 重启、受其他写入任务影响的 NAS 输出目录。持有完整分享链接即拥有解密能力，不属于认证绕过。恶意同源 JavaScript 可直接访问同源窗口，不能用 Worker 证明防御整个同源被攻陷。

未提供生产 Pages/R2 域名、账户配置、日志和权限，因此实际边缘响应头、TLS、Bucket 列表/写权限、API Token 权限为 Not Verified；不扫描未知生产目标、不索取秘密值。

## 已执行证据

- 阅读全部应用、配置、依赖和测试；没有 GitHub Actions 工作流。当前版本以及两个可达 Git 提交用 detect-secrets 1.5.0 扫描，未发现候选秘密（启发式扫描有漏报可能）。
- Bandit 1.9.4：运行 `bandit -r encrypt.py -f json`，0 告警。
- Semgrep 1.183.0：5 条仓库内规则（`security/semgrep.yml`），扫描 5 个生产 JS/Python 文件，0 告警、0 解析错误；不是全部 Semgrep 社区规则。
- pip-audit 2.10.1：`pip-audit -r requirements-dev.txt --vulnerability-service pypi --format json`，PyPI 查询成功，含传递依赖的 7 个包无已报告漏洞。不是对未公开漏洞或所有平台内置二进制的担保。
- 新攻击回归 `python -m unittest discover -s tests -p test_security.py -v`：12 项、6 通过、6 失败；失败之一汇总 Node 子测试，Node 中 10 项、1 通过、9 失败。失败包含待修复缺陷和防御性边界要求，不等同于 15 个可独立利用漏洞。
- 已通过：全部 48 个头字节的 AEAD 篡改拒绝、密文/标签篡改、块序号替换、跨文件块替换、错误/另一个文件的密钥、截断、硬链接/符号链接防覆盖、跨标签页读/关闭隔离、恶意 URL/JSON/XSS，以及 6000 次确定性解析器变异。
- CSP 最初通过 DevTools 直接执行 new Function 得出假失败；改成实际同源 HTTP 脚本探针后确认页面阻止 inline/eval。真实响应中镜像 `_headers` 的测试确认 frame-ancestors 和 Worker 自有 CSP 生效；这不证明 Cloudflare 线上配置已生效。

## 初始发现（尚未修复）

| ID | 优先级 | 确认的行为、条件与影响 | 最小复现 / 回归 |
|---|---|---|---|
| S3-01 | Medium，条件型本地数据损坏 | `encrypt.py:53-56` 按路径清理而未核对 inode。加密时把源文件重命名到输出路径并触发异常，会删除被替换进来的原视频。需要输出目录存在其他写入方；不是远程攻击。共享目录未拒绝，父目录重命名也未固定。CWE-367、CWE-459。 | `test_failure_cleanup_does_not_delete_replaced_original` 失败，复现原视频路径被删；`test_mutable_shared_output_directory_is_rejected` 失败。 |
| S3-02 | Low，输入完整性稳健性缺陷 | `encrypt.py:31-48` 仅比较长度，源文件发生同长度修改仍宣告成功，结果可能不对应任何稳定原文件。NAS 需可信、输入原本应静止；不声称绕过 GCM。CWE-367。 | `test_same_size_source_mutation_fails_and_cleans_outputs` 失败：改写首字节后仍成功。 |
| S3-03 | Low，会话归属及生命周期 | `web/sw.js:26-51` 验证配置后无条件覆盖同名 session；已知 ID 的另一受控页面可用自己的合法 key/对象覆盖，使原页面失去会话，不能因此获得原密钥。旧配置可晚于新配置提交；close 不取消 pending 配置；已关闭页面仍可提交。CWE-863、CWE-362。 | Node `another client cannot overwrite...`、`close cancels...`、`stale concurrent...` 均失败。真实浏览器跨标签页读明文仍被拒绝。 |
| S3-04 | Low，可用性及防御性限额 | `web/sw.js:10-22` 只限制活跃任务，等待队列/会话数量没有固定上限；`web/protocol.js:56-83` 正常块读取无超时，恶意对象可使任务持续挂起。可用性原本依赖存储；同源任意恶意脚本本来就可耗尽浏览器，本项不声称新增远程代码执行。CWE-400、CWE-772。 | Node 队列容量和挂起响应测试失败；用 80 个阻塞任务可全部排入队列。 |
| S3-05 | Low，秘密输入的错误处理 | `web/app.js:92-104` 只在成功 JSON 解析后清除 fragment，错误输入留在地址栏；解析异常直接拼到可见错误中，可能含输入片段。既定分享链接历史/剪贴板风险本来存在，本项仅减少额外错误路径暴露。CWE-209。 | `test_malformed_share_never_echoes_secret_and_is_removed` 失败，畸形 fragment 仍保留。 |
| S3-06 | Low，管理员误操作防护 | `upload.sh:7-12` 仅看 `.enc` 后缀，重命名成 `.enc` 的 key 文本会上传。需管理员主动误命名，不是绕过对象存储权限或来自未授权人的读漏洞。CWE-201（条件型）。 | `test_renamed_key_is_not_uploadable_ciphertext` 中 rclone shim 被调用。 |
| S3-07 | Informational，边界防御 | `auth()` 单独调用会接受绕回的块序号，但实际 `decryptBlock()` 先经 `block()` 校验，未发现可触发的 nonce 重用；Number 接受非十进制 Content-Length（浏览器通常会先拒绝线上畸形头）；不验证 HTML 错误页 MIME、helper 请求大小及手动 URL 长度。未证明 AEAD 绕过或真实网络利用。 | 对应 Node auth/headers/allocation 边界用例失败；将补充防御性校验。 |

未确认 Critical 或 High。S3-01 需先修复；其余低风险问题在不改变协议及架构的前提下一并修复。文件格式无需破坏性迁移。

## 尚未证实、不能当作漏洞的事项

- 没有发现认证前输出明文、同 key 合法流 nonce 重复、跨文件/跨块认证绕过。
- 原生 UUIDv4 会话 ID 有约 122 位随机性，不是 ASVS 128 位不猜测秘密要求；它不是解密能力，另有 clientId 授权，不应冒充满足该条款。
- AES-GCM 不保证时间新鲜性；完整旧密文重放、链接密钥泄露和静态同源供应链失陷是架构剩余风险。
- 播放只验证实际读取的块；不能声称尚未读取的整个文件完整性已验证。下载会逐块验证全部数据。
- CSP response header 与 meta 的能力不同：meta 无法实现 frame-ancestors，也不能代替 Worker 脚本自身的响应策略。

阶段 B 将针对上述确认问题修复，添加回归，并再次运行原有测试、安全扫描和实际 3 GiB 流式保存测试。
