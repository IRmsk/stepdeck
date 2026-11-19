# 更新记录

## v0.2.0 — 安全与正确性修复（2026-11）

### 修复（会让「看起来成功」变成真成功，或反过来）

- **通道静默回落**：`get_provider()` 以前用 `PROVIDERS.get(name, MockProvider)` 兜底。没装
  `requests` 时选「Zepp · 真实提交」会悄悄跑离线模拟，账号卡片是绿的、提交返回
  `changed: true`，其实一个包都没发。现在未知/缺依赖的通道一律显式报错，
  `/api/meta` 会标注每个通道是否可用，管理端弹黄条说明原因。
- **缺依赖时的假网络错误**：`provider_zepp` 以前在模块层 `import requests`，导入失败被
  `try/except` 吞掉；现在惰性导入 + 每个网络方法入口先检查，直接抛
  `缺 requests 依赖（pip install requests）`，不再伪装成「主机连不上」。
- **调度器时区**：`datetime.now()` 用的是容器本地时间。容器是 UTC 时，执行时间晚 8 小时，
  `last_run` 的「今天」也会错一天，导致一天跑两次或整天不跑。现在统一按 UTC+8。
- **渐进模式形同虚设**：`last_run` 一旦是今天，后续轮次全被跳过，所以「按小时分摊」
  实际只在第一次提交一个零头，永远到不了目标。现在当天未到量就每 30 分钟补一次。
- **公开页泄露全部账号**：以前所有账号默认出现在公开页，任何人都能看到打码账号和当前步数。
  现在必须由管理员在卡片上点「公开」。
- **公开申请列表越权**：`/api/public/requests` 不带 `who` 时会返回所有人最近的申请（含备注）。
  现在必须带 `who`，且只返回自己的。
- **越权下单**：公开端提交申请不校验账号是否开放，知道 id 就能给任何账号下单。现在会拒。
- **步数校验**：超过 98,800 或非数字在提交前拦下；以前会一路发到 provider 才失败。
- **添加账号吞异常**：非 429/超时的登录错误以前直接 500；现在返回具体原因。

### 安全

- 管理员密码从 `sha256(盐|密码)` 升级为 PBKDF2-SHA256（20 万轮），并兼容老库校验。
- **去掉「首次访问谁都能设管理员密码」**：启动时生成随机密码（控制台 + `data/INITIAL-PASSWORD.txt` 0600），
  改密码后删除该文件。
- 登录失败限流：同 IP 连续 5 次失败锁 5 分钟（429）。
- 会话改存 SQLite（只存 `sha256(token)`），重启不掉线；改密码清空全部会话；去掉 `X-Admin-Token` 旁路。
- 账号密码不再 base64：本地随机密钥 + HMAC-SHA256 计数器流 + 独立 tag，带完整性校验；
  老库数据启动时自动升级（`migrate_secrets`）。
- token 缓存从 `/tmp/zepp_tokens`（同机可读）移到 `data/zepp_tokens`（目录 0700、文件 0600）。
- 静态文件路径校验改成 `realpath` + `commonpath`，堵掉 `startswith` 前缀绕过。
- 所有响应加 `X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy`，HTML 加 CSP。
- POST 只接受 `application/json`（顺带挡 CSRF），并校验 `Origin` / `Sec-Fetch-Site`；请求体上限 1 MiB。
- 默认监听 `127.0.0.1`，要开局域网必须显式 `--host 0.0.0.0`，启动时打印警告。

### 改进

- `/api/meta` 返回通道清单（含可用性、真实/模拟标识、步数上限、密码最短长度），前端据此填下拉框。
- 卡片新增「公开 / 取消公开」；公开的账号显示「公开可申请」标签。
- 添加账号时先验证通道可用，再收密码；空密码直接拒。
- `provider_zepp` 演练模式（`zepp_dry`）在没装 `requests` 的机器上也能用（只组包不发送）。
- 读云端 `summary` 兼容 base64 和明文 JSON 两种返回。
- 账号探测（`/api/probe`）改走明文端点，不再依赖 `pycryptodome`；结果不确定时返回「不确定」而不是瞎猜。
- 测试：新增 `tests/test_server.py`，27 条 unittest，`python3 -m unittest discover -s tests -v`。

### 兼容性 / 升级说明

- 旧 `data/keepweb.db` 直接可用：启动时自动补 `share` 列、建 `sessions` 表、把 base64 密码重加密。
- 旧的自定义管理员密码继续有效（首次登录后自动按新格式校验）。
- 命令行调用接口的脚本需要带 `Content-Type: application/json`，否则会拿到 415。
- 想让别的设备访问公开页，要显式 `--host 0.0.0.0`。
