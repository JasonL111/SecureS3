# SecureS3 视频保险箱

一个无需后端的 MP4 加密在线播放器。NAS 用 Python 按 4 MiB 分块加密；S3 保存单个密文文件；浏览器通过 Service Worker、HTTP Range 和 Web Crypto 按需解密。原生 `<video controls playsinline>` 支持暂停、音量、全屏和拖动，不生成完整明文 Blob；密码学组件随站点本地托管，不从第三方 CDN 加载脚本。

## V4：一个命令，添加视频或开始观看

在 Linux / Unix NAS 的交互式终端运行：

```sh
python vault.py
```

```text
SecureS3 视频保险箱

1. 添加视频
2. 开始观看
3. 设置

0. 退出
```

首次安装只需准备一次：Python 3.12+、支持 Argon2id 的加密组件，以及已配置好的 **rclone 1.60.1+（1.x）S3 或 B2 Native remote**。R2 和 B2 S3 属于 S3 兼容存储，程序不会仅凭后端类型猜测厂商。

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
# 用 rclone 自己的安全配置流程设置存储凭据；不要交给网页
rclone config
python vault.py
```

在存储平台预先创建**私有视频 Bucket**，另准备**稳定、公开 HTTPS 可读的加密视频库发布位置**，并允许播放器域名的 GET/Range CORS。向导不会创建 Bucket、公开视频、修改 CORS 或关闭 TLS 校验。没有 rclone 配置时会提示先完成配置。

首次向导检测已有视频库和批量工作资料，询问必要的存储位置、公开视频库地址、播放器网站地址及视频文件夹；已有视频库使用原主密码，新库设置并确认密码。随后可在同一次运行里直接添加视频。非敏感设置默认保存在 `~/.config/secures3/settings.json`，视频密钥、工作资料和加密视频库默认放在仓库外的 `~/.local/share/secures3/`。支持 `XDG_CONFIG_HOME` / `XDG_DATA_HOME`；密码、密钥及完整临时授权 URL 不写入设置或明文恢复记录。

- **添加视频**：预览新增数量和大小，确认后输入一次主密码，自动加密、上传、更新视频库、准备观看权限并发布。已确认的副本跳过；没有新增且没有待恢复步骤时不重复哈希大视频或发送存储请求。源文件修改会报冲突，保留原副本。
- **开始观看**：输入一次主密码，复用尚有效的授权和已确认的发布结果；必要时自动刷新并发布。不会扫描源视频、重新加密、导入密钥或上传视频。SSH 下直接显示网站地址；有本地桌面时也只在同意后打开浏览器。
- **设置**：更改文件夹、存储、发布位置、观看期限（默认 6 天）、网站配置，执行只读连接检查；高级选项包含换密码、查看、迁移、备份、恢复和完整校验。配置变化先预览确认，旧库、密钥及云对象保留。

网站配置会自动生成，**无需手写 `web/config.js`**。没有已确认的自动部署关联时，将提示部署生成的 `~/.local/share/secures3/website/` 静态目录；只部署这个目录，勿上传整个私有目录。有部署关联时，也只有在工作区检查通过并当次明确同意（默认 **No**）后，才提交和推送白名单文件 `web/config.js`。有其他改动、敏感文件被追踪或无关未推送提交时会停止自动操作。Git 推送成功不等于网站部署成功。

上传中断后再次选择「添加视频」，只处理尚未确认的对象；签名失败不提交半批；发布失败后选择「开始观看」即可恢复。公开地址回读内容必须与本地视频库 SHA-256 一致，旧缓存不会被报告为发布完成。本地写入、云上传与网站部署不是一个跨系统原子事务。

已有 V1/V2/V3 容器、分享、播放、Seek、流式下载和高级 CLI 均保留。旧视频库未被自动发现时，在向导中指定已有文件；已保存的库缺失或损坏时不会创建新密钥来替代它。浏览器端仍须输入主密码解锁，NAS 不会把密码或密钥传给网站服务器。

实现、恢复边界、Git 防泄露、真实测试和未验证项目见 [V4_INTERACTIVE.md](V4_INTERACTIVE.md)。以下 V3/V2 和单文件命令保留供高级用户使用。

V4 最终验证：**138 项全部通过，无跳过**，含 24 项新增测试、真实 PTY/rclone/TLS 对象存储、真实 Chromium、原有安全/播放/Seek/分享/下载和两项 3 GiB 测试。真实 R2/B2 账户及 GitHub → Pages 部署链路尚未验收，不宣称已自动配置生产云环境。

## V3 高级 CLI：Private Bucket，手动签名并发布 Vault

这是新增的可选模式；下方 V2 公开密文、旧 URL 和旧分享仍可使用。视频放在 **Private Bucket**，加密 Vault 放在**另一个稳定、公开可读取的 HTTPS 位置**。不要把 Vault 上传到仍然私有的视频 Bucket 后误以为网页可以匿名读取它。

首次准备（已有加密视频/Vault 可跳过相应步骤；先按下方安装依赖和配置 rclone）：

```sh
python vault.py batch-encrypt --input-dir /nas/videos \
  --output-dir ./encrypted --private-dir ./private --recursive
rclone copy ./encrypted r2:private-bucket -P --immutable
# 可选：同一份密文也复制到 B2 Private Bucket
rclone copy ./encrypted b2:private-bucket -P --immutable

# 仅在尚无 Vault 时执行 init
mkdir -m 700 private-vault
python vault.py init --output private-vault/vault.enc
python vault.py batch-add --vault private-vault/vault.enc --manifest ./private/manifest.json
```

**想观看时，只需手动运行一次：**

```sh
python vault.py presign --vault private-vault/vault.enc \
  --source r2 --remote r2:private-bucket --expires 6d \
  --vault-remote public:public-bucket/vault.enc --publish
```

交互输入一次 Vault 主密码，程序使用已有 rclone 配置，为所有 objectKey 记录生成临时 GET URL；全部校验成功后统一加密并原子更新 Vault/保留旧备份，随后发布新版。不会重新加密视频、改名、替换 AES Key/Vault Key、重新上传视频或上传 `.key`。结果只输出数量、来源、Unix 秒失效时间、容量及发布结果，不打印签名 URL。

```sh
# 预览对象/名称、后端及容量估算；不生成链接、不更新/上传 Vault
python vault.py presign --vault private-vault/vault.enc \
  --source r2 --remote r2:private-bucket --expires 6d --dry-run

# 只更新本地，不上传：省略 --publish
python vault.py presign --vault private-vault/vault.enc \
  --source r2 --remote r2:private-bucket --expires 6d

# 为第二个来源签名，保留已存在的 R2 授权
python vault.py presign --vault private-vault/vault.enc \
  --source b2 --remote b2:private-bucket --expires 6d \
  --vault-remote public:public-bucket/vault.enc --publish

# 若签名/本地更新成功，但上传失败，只重传，不要重新签 500 个对象
python vault.py upload --vault private-vault/vault.enc --remote public:public-bucket/vault.enc
```

先部署新版网页，再发布 V3 Vault。`web/config.js` 中只填写公开 Vault URL、公共 Vault ID 和来源名称，不填云端 Secret 或临时链接；Private 来源不需要公开 baseUrl：

```javascript
globalThis.SECURES3_CONFIG = Object.freeze({
  vaultUrl: 'https://your-public-vault-domain.example/vault.enc',
  vaultId: '', // 建议填写 NAS 输出的可信公共 ID
  storageSources: [
    {id: 'r2', name: 'Cloudflare R2 Private', type: 'presigned'},
    {id: 'b2', name: 'Backblaze B2 Private', type: 'presigned'}
    // 旧公开来源仍可用：{id:'public',name:'Public',baseUrl:'https://your-domain/'}
  ]
});
```

打开 Pages，刷新/解锁 Vault，即可选择来源、播放、Seek、流式下载或分享。来源 ID 必须与 NAS --source 相同。Private 来源缺少授权/已过期会提示重新 presign，不猜地址、不回退公开来源。授权临近到期会警告；下载/播放期间到期可能中断，HTTP 403 会归类为访问授权问题，不冒充 AES 密钥错误。

需要 rclone **1.60.1+ 的 1.x 系列**；仅接受直接配置的 **S3**（R2、B2 S3 等）和 **B2 Native** remote。S3 使用 SigV4、最长 604800 秒；R2 签名通常指向 S3 API 域名，而非 r2.dev/普通自定义域名。B2 Native 用其专有下载授权，并显式传递 --b2-download-auth-duration；不能假设 --expire 对它生效。B2 Native 是完整对象名的**前缀授权**，并非严格的单对象令牌；必须保持只有规范 objects/<id>.enc 的命名空间，勿创建以该完整名称继续追加后缀的其他对象。原生后端需要相应 shareFiles/read 权限，真实账户限制需核实。

远端名/路径须为简单的 `name:bucket[/prefix]`，不接受临时内联凭据、别名/crypt/union 或不支持到期控制的后端。签名子进程限时/限量捕获输出，关闭继承的敏感调试日志及 RC 服务设置；不创建常驻服务。如果 rclone 配置本身加密，应先使用 rclone 的安全本地配置方式使其可非交互读取，不能把 Vault 主密码传给 rclone 或放进参数/环境变量。

**到期后再次手动运行同一条 presign 即可。**不必每天执行，没有 cron、systemd timer、后台续签、Worker 签名 API 或浏览器自动签名。旧分享仍为 `{v:1,url,key}`，只交付单文件权限，具有相同临时授权期限；Vault 重新签名不会更新已发出的旧链接，需要重新分享。B2 Native 的旧格式分享不携带期限且 token 不透明，接收端无法仅靠链接读取确切到期时间，会提示临时性并在 403 时要求新链接。

签名失败时旧 Vault 不变且不发布半批；上传失败时保留本地新版，使用 upload 重试。本地提交和云端发布不是跨系统原子事务。4 MiB 目录上限保持不变：先估算、逐项跟踪实际增长、最终严格校验，超限拒绝且不截断 URL/条目。

视频 Bucket 必须自行关闭匿名读取、设置允许 Pages Origin 的 CORS，并验证 GET Range 返回正确 206。公开加密 Vault 要用强主密码及 no-store 缓存策略。S3 本地签名不等于整个命令零云请求：rclone 可能先执行 HEAD；B2 Native 签发涉及 API 请求，后续 Range GET 仍可能产生正常费用。云 ACL、CORS、域名和费用均由部署者验证。

本次 **114 项测试全部通过，无跳过**，含 500 对象、真实 rclone 本地 TLS S3/B2 模拟、真实 Chromium 及两项 3 GiB 回归；尚未实测真实 R2/B2 Private Bucket。协议、失败恢复、CORS 示例、安全边界、工具版本与限制见 [V3_PRIVATE.md](V3_PRIVATE.md)。

## V2：不透明对象名、批量处理与多云副本

新视频推荐以下流程。云端仅保存 `objects/<32位小写hex file_id>.enc`，ID 直接来自原有 ES3VID01 容器的随机 128 位 file_id，不从文件名称推导，也不能由批量命令指定。真实名称及相对目录加密保存在 Vault 中。**加密视频格式、每文件独立 AES Key、主密码/包装算法均未改变。**

安装下方 Python 依赖后，先预览，再批量处理：

```sh
python vault.py batch-encrypt --input-dir /nas/videos \
  --output-dir ./encrypted --private-dir ./private --recursive --dry-run
python vault.py batch-encrypt --input-dir /nas/videos \
  --output-dir ./encrypted --private-dir ./private --recursive

# 上传整个密文根目录，保持 objects/ 层级；不要上传 private/
rclone copy ./encrypted r2:mybucket -P --immutable
rclone copy ./encrypted b2:mybucket -P --immutable

# 已有 Vault 则跳过 init；批量导入只输入一次主密码，不需要视频 URL
mkdir -m 700 private-vault
python vault.py init --output private-vault/vault.enc
python vault.py batch-add --vault private-vault/vault.enc \
  --manifest ./private/manifest.json
python vault.py upload --vault private-vault/vault.enc --remote r2:mybucket/vault.enc
```

输出分成两个目录：

```text
encrypted/objects/<file_id>.enc        可以公开上传的密文
private/manifest.json                 原始相对名称/ID/key 文件引用/校验信息
private/keys/<file_id>.key             私有独立 AES key，0600
private/.batch.json                   可信 NAS 本地目录绑定，不上传
```

默认只扫描当前层的 MP4（扩展名不区分大小写），`--recursive` 才包含子目录；目录符号链接不跟随，文件符号链接拒绝。输入、密文输出、私有目录必须互不重叠，受管路径不允许符号链接逃逸。显示文件级进度/成功、跳过、恢复、错误统计，失败退出码为非零。大视频按现有 4 MiB 协议处理，不读入整文件。

密文输出根目录只允许 objects/，其中只能有规范对象文件及本工具的临时复制文件，拒绝混入 `.key`、Manifest、原视频或符号链接。不要手工向上传目录放其他材料；命名检查不能代替密码学认证。

每个完成项立即写入可恢复的 Manifest；重复命令会重新核对源文件快照/哈希、完整密文认证及密钥，再跳过。**续跑需要完整读取已完成对象，因此不是只看时间戳的快速跳过。**源文件被修改/删除、密文截断或 key 不匹配时保留已有数据并报错。密文/密钥/Manifest 提交中断时，私有日志保留恢复材料，使用完全相同命令续跑；不要自行编辑它们。输出冲突不会覆盖。不要在批量任务仍运行时上传输出目录。

Manifest 不保存明文 AES Key 或完整云 URL；key_file 只能是与 ID 一致的私有 keys/ 路径。它仍泄露原始名称、路径和内容指纹，应和 `.key` 一起保密。只接受本工具生成的完整私有批量目录，`.batch.json` 是可信 NAS 配置，不接收他人提供的目录绑定。默认目录及元数据已加入 .gitignore；自定义私有目录建议放在仓库外。

### 配置 R2 / B2 / 其他 S3 存储源

编辑 `web/config.js`，填写**你实际提供并确认的公开 HTTPS 前缀**，不会从 rclone remote 推测域名：

```javascript
globalThis.SECURES3_CONFIG = Object.freeze({
  vaultUrl: 'https://your-r2-domain.example/vault.enc',
  vaultId: '', // 建议填 NAS 输出的受信公共 Vault ID
  storageSources: [
    {id: 'r2', name: 'Cloudflare R2', baseUrl: 'https://your-r2-domain.example/'},
    {id: 'b2', name: 'Backblaze B2', baseUrl: 'https://your-b2-host.example/file/your-bucket/'}
  ]
});
```

例如第二个前缀会生成 `https://your-b2-host.example/file/your-bucket/objects/<file_id>.enc`。尾部 `/` 可省略；Unicode/空格前缀使用合法 URL 编码。禁止 credentials、Query/fragment、点路径、编码分隔符及非 HTTPS 地址（仅 localhost HTTP 可用于测试）；配置中不能有 S3 API Secret。

根页面输入一次主密码 → 按文件夹浏览/搜索真实名称 → 选择存储源 → 播放/拖动/下载/分享。切换只改变访问前缀，不重新派生密码、不重新解密目录、不修改 key 或 Vault；会停止当前播放/下载，重新点击操作即可。下载对话框建议使用原视频 basename，并经过安全处理。缺少对象或副本损坏会报错，可手动切回；不会自动故障转移或猜测其他路径。

分享保持原有 `{v:1,url,key}` fragment，使用当前所选存储源的完整 URL。朋友无需 Vault、主密码或存储源配置即可播放/下载，只得到单文件权限。旧分享链接仍兼容；删除旧对象、改变域名或外部 URL 到期可能使链接失效，不保证永久有效。vaultUrl 与视频存储源相互独立；更换视频副本不会自动切换 Vault 下载地址。

### 已有视频和 Vault 的安全迁移

旧 URL 记录继续使用原 URL，页面显示「旧 URL」，不会丢弃。新 schema 可同时包含旧 URL 和新 objectKey 记录。对已确认的本地旧密文执行：

```sh
python vault.py migrate --vault private-vault/vault.enc \
  --id OLD_VAULT_RECORD_ID --cipher /nas/old/movie.enc \
  --output-dir ./encrypted
# 可选 --name 'Movies/原始名称.mp4'，为不符合安全相对路径规则的旧名称明确命名
rclone copy ./encrypted r2:mybucket -P --immutable
rclone copy ./encrypted b2:mybucket -P --immutable
python vault.py upload --vault private-vault/vault.enc --remote r2:mybucket/vault.enc
```

migrate 使用 Vault 内原 key 完整验证实际容器，从头读取 File ID，然后复制相同密文至标准对象路径；不重新加密、不更换 key、不删除源文件/旧云对象，并备份原 Vault。相同内容的已存在目标可验证后复用，任何不同内容/符号链接冲突均拒绝，绝不覆盖。未映射记录仍保留旧 URL。先部署新版 Web 并上传/验证新对象，再发布更新后的 Vault；确认新路径可播放后再自行决定是否清理旧对象。保留旧对象可让旧分享链接继续有效。

若 NAS 已无旧密文，可先自行用 rclone 取回 `.enc`；迁移命令不联网、不从旧 URL 猜测 ID。没有实际容器或无法确认匹配的记录继续保留旧 URL。

**公开密文、不透明路径和 CORS 都不是身份认证。**持有公开 URL 可匿名下载；对象列表权限、HTTPS 域名、Bucket/CORS/Range 配置由你管理。rclone --immutable 用于拒绝修改已有远端对象；批量加密工具不连接云端或验证远端冲突。Private Bucket 的新增手动预签名流程见上方 V3；没有鉴权网关。

完整 Manifest/Vault schema、崩溃恢复、兼容顺序及实测边界见 [V2_STORAGE.md](V2_STORAGE.md)。下面的单文件 add/publish 流程继续保留为旧 URL 模式，不会自动隐藏它指定的云端文件名。

V2 最终实际验证：**90 项全部通过，无跳过**，包含 500 个合成输入的批量加密/导入、500 条浏览器目录、双 Range 存储副本、旧功能回归和两项真实 3 GiB 测试。3 GiB 批量处理在 96 MiB 地址空间限制下通过，进程峰值 RSS 约 34 MiB。真实 R2/B2 账户、NAS 断电及其他浏览器尚未实测，详细结果/扫描限制见上方文档。

## Vault：一次主密码管理视频库

现支持同一个网站的 **Vault Mode** 和旧版 **Share Mode**。没有配置 Vault 时仍可手动输入 URL/Key，旧链接不失效。NAS 端无需重新加密已存在视频。

先按下方安装 Python 依赖，再在私有目录操作（主密码由 getpass 交互读取，不放在参数、环境变量或 shell history）：

```sh
mkdir -m 700 private-vault
python vault.py init --output private-vault/vault.enc
python vault.py add --vault private-vault/vault.enc \
  --name "Movie A.mp4" --url "https://storage.example.com/a.enc" --key-file movie.key
python vault.py list --vault private-vault/vault.enc
# 从 list 结果读取记录 ID；list 不输出文件 key
python vault.py remove --vault private-vault/vault.enc --id RECORD_ID
python vault.py change-password --vault private-vault/vault.enc
# 可选更高 KDF 成本：change-password ... --memory-kib 131072 --iterations 4
python vault.py upload --vault private-vault/vault.enc --remote remote:bucket/vault.enc
```

新密码至少 12 个 Unicode 码点，最多 1024 UTF-8 字节，建议长随机/多词口令。密码**不规范化也不 trim**，组合重音和预组字符可能是不同密码。SSH 时使用带 TTY 的会话（例如 ssh -t）；非交互 stdin 管道被拒绝，避免静默回退到密码回显。不要把主密码直接写在命令或脚本里。

也可直接使用已有 rclone 配置上传当前密文 Vault：

```sh
rclone copyto private-vault/vault.enc remote:bucket/vault.enc --header-upload "Cache-Control: no-store"
```

upload.sh 继续仅负责 `ES3VID01` 视频，不接受 Vault 的不同魔数。仅上传当前 vault.enc，**不要同步整个私有目录、.key 或 .bak**。Vault 是小型加密元数据，不存视频正文；默认 Argon2id m=64 MiB/t=3/p=1 → KEK → 包装随机 Vault Key → 加密目录内各独立文件 key。密码更改只重新包装 key，目录密文、视频、单文件 key 和分享链接保持不变。

### Cloudflare Pages 配置与使用

编辑唯一的非秘密配置文件 `web/config.js`，继续无构建命令、发布目录 `web`：

```javascript
globalThis.SECURES3_CONFIG = Object.freeze({
  vaultUrl: 'https://your-r2-domain.example/vault.enc',
  vaultId: '从 vault.py 输出读取的32位小写hex公共ID'
});
```

vaultId 可留空，但建议从可信 NAS pin 此公共标识以检测整个 Vault 身份替换。这里**不能写主密码、KEK、Vault Key 或文件 key**。也可以在页面输入 Vault URL，不会持久化该设置。根页面默认显示 Vault 解锁：输入一次主密码 → 搜索/浏览 → 播放/拖动/下载/分享。所有操作共用原视频元素、Worker、Range 和下载实现。下载在保存对话框中取得授权后逐块保存，直接点目录行下载不会切换正在播放的视频。

点击「锁定」停止当前播放/下载、终止解锁任务、清除库/当前 key 引用并返回解锁页；不宣称 JS 可以物理擦除所有历史内存副本。刷新视频库使用内存中的不可导出 KEK，重新认证整个包装和目录；密码包装已变更时需重新输入主密码。刷新认证失败或回滚会清空库并锁定，不展示部分新数据。

从库点击「分享」只复制 `{v:1,url,key}` 的 fragment 链接。朋友在新/无痕窗口打开后，直接进入 Share Mode，不需要主密码，**不会获取整个 Vault 或加载 Argon2 Worker**。单文件链接不含 Vault Key、KEK 或其他文件 key。公开 R2 对象链接的可获取期由对象/域名决定，Presigned URL 受其到期限制；浏览器不生成或续签 URL，NAS 可使用 V3 presign。

R2 CORS 继续允许 GET/HEAD 并向播放器 Origin 暴露 Content-Length；视频 Range 所需头仍按下方示例。Vault 使用普通完整 GET，必须返回 200/完整有界文件，不接受内容压缩。浏览器使用 no-store，但 CDN 规则可覆盖缓存：请让 vault.enc 返回 `Cache-Control: no-store`、不要对它配置长 Edge TTL，并用实际域名核对头。r2.dev/自定义域名/实际账户策略需自行验证。

### 可选的一步 NAS 发布

```sh
python vault.py publish --vault private-vault/vault.enc \
  --input movie.mp4 --output movie.enc --key-out movie.key \
  --name "Movie A.mp4" --url "https://storage.example.com/movie.enc" \
  --remote remote:bucket/videos/movie.enc --vault-remote remote:bucket/vault.enc
```

只输入一次主密码，顺序加密、验证、上传视频、更新本地 Vault、上传 Vault。使用全新不可变对象名；--url 和 --remote 的对应关系由你确认，不自动签发 URL。视频上传失败不提交 Vault；Vault 上传失败保留可信本地最新版本，优先重试 `vault.py upload`。

若已有 `.enc`/`.key`（包括上次发布失败保留的文件），显式使用：

```sh
python vault.py publish --vault private-vault/vault.enc \
  --cipher movie.enc --key-file movie.key \
  --name "Movie A.mp4" --url "https://storage.example.com/movie.enc" \
  --remote remote:bucket/videos/movie.enc --vault-remote remote:bucket/vault.enc
```

这会流式验证现有视频，而不重加密；相同记录的重试不重复添加。冲突的 URL/ID/key 会拒绝，原始 MP4 和 key 不自动删除。两个云对象不是单个分布式事务；中断时可能有未被目录引用的新密文，但始终保留本地恢复材料。NAS 使用 `.bak` 上一加密版本及当前版本作为依据，可将备份复制到新路径后用 list 验证；不要盲目覆盖唯一当前版本。

完整协议、两种 revision、原子写入、缓存/回滚和安全边界见 [VAULT_FORMAT.md](VAULT_FORMAT.md)。旧密码 + 旧副本可恢复旧 Vault Key，**更换密码无法撤销该 key，未来继续用同一 Vault Key 的目录也不免疫**；泄露后须建立新的 Vault/Key，旧文件 key/明文无法远程撤回。静态托管代码被篡改仍可窃取秘密，主密码忘记且无单文件 key/备份时无法恢复。

本地 Argon2id 采用 hash-wasm 4.12.0 的内嵌 WASM，记录 npm SHA-512、资产 SHA-256 及 MIT 许可，不运行时请求第三方 CDN。仅增加 CSP `wasm-unsafe-eval`，保持 JS eval 被禁用。没有取得独立第三方对该具体构建的审计证明，交叉测试不能替代这类保证。

## 快速开始

Python 3.10+，已有 rclone 配置。NAS 加密不需要运行 Web 服务。

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
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
requirements.lock         生产传递依赖与制品 SHA-256 锁
requirements-dev.txt      可选浏览器测试依赖
web/index.html            简洁中文界面、CSP、原生 video
web/style.css             响应式样式
vault.py                  创建/维护/轮换/上传 Vault 与可选发布
batch.py                  无云依赖的批量加密、私有 Manifest、恢复与迁移
presign.py                有界 rclone 签名/上传适配、URL 校验与批次事务准备
web/config.js             非秘密 Vault URL/ID 配置
web/vault.js              同一网站的视频库 UI 与锁定
web/vault-crypto.js       Vault 格式、校验和本地 Web Crypto
web/vault-kdf.js          可取消的 Argon2id Worker
web/vendor/               固定版本本地 WASM/JS、许可和来源
VAULT_FORMAT.md           Vault 二进制协议、密钥边界与实测记录
V2_STORAGE.md             不透明对象、Manifest v2、多云与迁移/验证记录
V3_PRIVATE.md             私有视频/公开 Vault、schema 3、后端/安全/实测记录
web/app.js                分享链接、页面会话、Worker 生命周期
web/download.js           分块解密下载、原生文件流写入、进度与取消
web/protocol.js           文件头、整数校验、Range 和 AES 参数
web/sw.js                 按需读取/解密、流式响应
web/_headers              Cloudflare Pages 安全响应头
 tests/test_encrypt.py    Python 加密/认证/内存测试
 tests/test_browser.py    本地双源 S3 模拟、真实 Chromium 测试
 tests/test_download.py   下载校验、原生文件流、失败清理与大文件测试
 tests/test_vault.py      Vault CLI、原子更新、密码轮换与跨实现向量
 tests/test_vault_ui.py   真实浏览器私人库、分享与锁定回归
 tests/test_batch.py      批量命名、500 个文件、攻击/中断恢复及内存测试
 tests/test_storage_ui.py 双存储源、V2/旧记录兼容与真实浏览器集成
 tests/test_presign.py    签名事务、500 对象、真实 TTY、容量及子进程边界
 tests/test_rclone_backend.py 当前 rclone 与验证 CA 的本地 TLS S3/B2 API
 tests/test_presign_ui.py 临时 URL、过期/403、Query/Range/Seek/分享与隔离
 tests/rclone_stub.py     仅测试用子进程模拟器，不含真实云凭据
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

浏览器测试使用系统 `chromium`（PATH），攻击回归另需 Node.js（仅测试，不是后端）。FFmpeg 生成 H.264 测试片，两个本地 HTTP 源模拟静态托管和 S3。测试保留严格 CSP，不设置 bypass_csp；测试运行需要本地端口和 Chromium 子进程权限。生产运行仅需 cryptography，Playwright/FFmpeg 仅测试使用，不是转码服务。

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


## 安全加固与运行边界

完整审计、逐项标准映射和已执行攻击证据见 [SECURITY_AUDIT.md](SECURITY_AUDIT.md)、[初始报告](security/INITIAL_AUDIT.md) 和 [ASVS 5.0 控制矩阵](security/ASVS_5.0_MAPPING.csv)。本项目没有企业级认证，也没有账户、中心化撤销、DRM 或解密后端。

- NAS 加密脚本使用 POSIX 目录描述符/权限机制，面向 Linux/Unix NAS。请使用当前用户（或 root）拥有的私有输出目录，例如 `mkdir -m 700 encrypted`；非 sticky 的组/其他用户可写目录会被拒绝。不要以 root 身份处理不可信可变输入。文件必须是普通且稳定的文件；对正在录制/改写的文件应先使用 NAS 快照或只读副本。修改时间检测不能替代恶意同 UID/root 攻击下的原子快照。
- 输出使用 O_EXCL，父目录固定，失败清理核对 inode，密钥 0600，并在成功前 flush/fsync。父目录和输入由可信管理员控制仍是前提；不会保证断电后的两个输出原子提交。仅 `.enc` 后缀不足以避免误传，upload.sh 额外检查容器头及总长；这不是无 key 的 GCM 认证，不能代替保密操作规范。
- 生产 Python 安装优先使用 `requirements.lock` 和 `--require-hashes`。开发工具保持在 `requirements-dev.txt`；审计用 Bandit/Semgrep/pip-audit/detect-secrets 安装于临时环境，不是运行依赖。建议每月及发布前检查漏洞数据库；Critical/High 暴露应当天评估、尽快限制使用并安排补丁（建议 Critical 24 小时、High 7 天、Medium 30 天内完成处理/风险接受），随后重跑对应回归。此为建议维护时限，不表示已建立企业持续监控制度。
- key 为 43 字符规范 Base64URL（32 字节）。视频 URL 原文和规范化 URL 均不超过 8192 个字符；分享 fragment 不超过 32768 字符；Range 表达式最多 128 字符。错误 fragment 也会立即从当前地址中移除，错误信息不回显原文，仍不能删除浏览器早已同步的历史或剪贴板副本。
- Worker 每次保留最多 32 个页面会话/32 个配置任务，最多 3 个活跃取块任务、24 个等待任务、32 个响应流及每页 8 个响应流；超过限制报错（响应流限额返回 429）。同页新配置取消旧配置，不允许用同名 ID 覆盖别页会话，关闭时取消 pending/恢复和已有流。新 ID 使用 128-bit CSPRNG；旧 UUIDv4 临时 ID 仍可恢复，不改分享链接格式。
- 单次 Range 包括响应头与整个正文的总超时为 120 秒，配置 30 秒，重启恢复握手 5 秒；不自动重试。很慢的连接可能需要用户修复网络后重新加载。所有异常响应都不会退化为全文件下载。密文 Content-Type 可缺省（仍逐块 GCM 校验），存在时只接受 `application/octet-stream`、`binary/octet-stream` 或 `video/mp4`；不要启用 Content-Encoding。
- pagehide 尽力取消下载、清空密钥输入/会话并停止视频；浏览器崩溃、系统交换区、扩展或恶意同源代码不在可保证擦除范围。关闭后返回页面须重新输入或打开分享链接；不能通过这些措施撤销对方已取得的 key/明文字节。
- 请将播放器独立部署在仅有受信脚本的 HTTPS 域名，仅发布 `web/`。`_headers` 为页面和 Worker 设置 CSP/no-referrer/nosniff/COOP；meta CSP 无法实现 frame-ancestors，也不能替代 Worker 自身的响应策略。生产域名是否真正返回这些头、HSTS/TLS 及是否暴露 `.git`/目录列表必须自行检查。GitHub Pages 不解释 `_headers`，需要支持响应头的平台才能满足相应要求。
- AES key 应通过可信私密渠道分享，并有加密离线备份；key 丢失则无法恢复视频。泄露时须用新随机 key 重新加密并更新 URL，旧 key/密文的既有副本无法撤回。不要复用 key、不要将弱口令直接当 key，也不要认为随机 file_id 可以消除同 key nonce 重用的危害。
- 公共密文不提供访问控制，CORS 也不是鉴权。Bucket 不应公开列举或写入；NAS rclone token 应限定目标 Bucket/前缀及所需操作，Pages 部署凭据不应拥有 R2 管理权。r2.dev 与自定义域名的缓存/限流策略不同，自定义域名也不自动保护公开对象。需要在实际账户配置请求限额、告警、日志权限和保留；公开下载可能产生请求/API/CDN 等费用或流量压力。R2、S3 的收费项目不同，不能一概按出站流量计费。

密码资产清单：每文件 AES-256 key（仅 NAS 私密文件及分享接收端）、16 字节公开 file_id、96-bit nonce（64-bit 文件前缀 + 32-bit 块号）、128-bit GCM tag、完整头 + 块号 AAD、128-bit 浏览器会话标识；测试 SHA-256 用于比对输出。TLS 证书和 rclone/API token 由部署方管理，不包含于前端。未来算法变更应定义新格式版本并保留旧版本只读解密能力，不能静默改变 v1 参数；本次没有变更格式。

危险/高资源组件为：cryptography/OpenSSL、原生浏览器和视频解码器、File System Access 磁盘写入、rclone 和网络 Range。应用有限额并使用维护中的实现，但不提供这些系统组件的完整 SBOM、侧信道或硬件隔离证明。

额外攻击回归需 Node.js（仅测试，不是后端）：`python -m unittest discover -s tests -p test_security.py -v`；底层协议/Worker 模拟为 `node tests/security_protocol.cjs`。生产运行不需要 Node.js。


## Vault 验证记录

核心阶段执行 `python -m unittest discover -s tests -p test_vault.py -v`；集成阶段执行 `python -m unittest discover -s tests -p test_vault_ui.py -v`；最终使用 `SECURES3_LARGE_DOWNLOAD_TEST=1 python -m unittest discover -s tests -v` 验证全部原有和新增测试。2026-10-31 最终 **65 项全部通过，无跳过**，包含真实 3 GiB 流式保存；实际结果和扫描限制见 [VAULT_FORMAT.md](VAULT_FORMAT.md) 的执行记录。

真实浏览器测试覆盖 100 条认证目录（其中两条有真实本地对象）、搜索、H.264 播放/Seek、原生文件流下载哈希、无痕单文件分享、锁定取消、刷新/回滚、包装变更及 Worker 隔离。其余记录用于目录规模验证，不宣称已测试 100 个真实 R2 视频。真实云上传/缓存、NAS 硬件断电、其他浏览器和人工系统保存对话框未验证。
