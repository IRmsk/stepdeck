# StepDeck · 网页版步数控制台

一个跑在本机的单页控制台，用来管理多个账号、每天自动提交步数、也可以随时手动改到指定数值。

前端三个静态文件，后端一个标准库 HTTP 服务，数据落在本地 SQLite，不需要数据库和前端工具链。

```
StepDeck
├── server.py              HTTP 服务 + 路由 + 定时任务 + SQLite
├── provider_zepp.py       协议适配器（登录 / 读取 / 上报）
├── web/                   index.html · app.js · style.css
├── tools/
│   ├── push_steps.py      命令行改步数
│   └── zepp_template.json 上报报文模板
└── data/                  运行后生成（数据库与日志）
```

## 一、跑起来

```bash
pip install requests
python3 server.py
```

只依赖 `requests`；`pycryptodome` 是可选依赖，装不装都能用（默认走明文登录，
加密链路只是备份，缺了会跳过并提示）。

默认监听 `0.0.0.0:8088`，同网段的其他设备可以直接访问：

```bash
python3 server.py                      # 默认 0.0.0.0:8088
python3 server.py --port 9000          # 换端口
python3 server.py --port 8088,9000     # 同时开多个，共用一份数据和一个调度器
python3 server.py --host 127.0.0.1     # 只允许本机
```

浏览器打开：

```
http://127.0.0.1:8088/          公开页（只能提交申请）
http://127.0.0.1:8088/admin     管理端（也认 /admin/ 和 /admin.html）
```

公开页没有任何账号管理入口；添加、修改、删除账号只能通过管理端，未登录访问相关接口一律返回
`401 {"ok": false, "needAdmin": true}`。

只依赖 `requests`，其余全是标准库。

## 二、页面能做什么

- 添加多个账号，每个账号独立保存状态、目标步数、执行时间
- 卡片上的「改到」：填多少就改成多少，立刻提交一次
- 目标值 + 托管开关：开启后每天到点自动提交
- 普通模式提交固定值，智能模式按当前小时数按比例分摊
- 每个账号可以改账号 / 密码 / 渠道，不用删了重加
- 备注：添加账号时能填，卡片上有「备注」按钮随时改，公开页显示的就是备注（没填则显示打码邮箱）
- 右侧运行日志，每次提交的返回值都记在里面

## 三、接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/accounts` | 账号列表（已脱敏，不含密码与 token） |
| POST | `/api/accounts` | 添加账号 |
| POST | `/api/accounts/{id}/update` | 改账号 / 密码 / 目标 / 执行时间 / 渠道 |
| POST | `/api/accounts/{id}/submit` | 提交一次，body 可带 `steps` 直接指定数值 |
| POST | `/api/accounts/{id}/custody` | 开关托管 |
| DELETE | `/api/accounts/{id}` | 删除 |
| GET | `/api/logs` | 运行日志 |
| GET | `/api/stats` | 概览 |

## 四、登录链路

三段式，每段都在多台主机之间轮换，命中 429 或超时就换下一台：

```
POST {api-user}/registrations/{account}/tokens
     client_id=HuaMi&country_code=CN&json_response=true
     &name=..&password=..&token=access
→ {"access": "..."}

POST {account}/v2/client/login
     app_name=..&code={access}&grant_type=access_token&third_name=..
→ token_info.login_token / user_id

GET  {account-cn}/v1/client/app_tokens?login_token=..
→ token_info.app_token
```

手机号会自动补 `+86` 前缀，邮箱原样提交。密码用一个独立的 AES-128-CBC 链路做备份，
两条链路的限流互相独立，一条被限时另一条还能用。

## 五、上报链路

```
GET  {data}/users/{uid}/devices?enable=true
→ items[].deviceId          # 取账号真正绑定的设备号

POST {data}/v1/data/band_data.json?&t=<毫秒>
     header: apptoken
     body:   userid=..&last_sync_data_time=..&device_type=0
             &last_deviceid={deviceId}&data_json=<urlencode 后的 JSON 数组>
```

`data_json` 里每一项：

```json
{
  "data_hr": "<按分钟的心率原始块>",
  "date": "2026-11-07",
  "data": [{"start": 0, "stop": 1439, "value": "<原始数据块>", "tz": 28800,
            "did": "<deviceId>", "src": 24}],
  "summary": "{\"v\":6,\"slp\":{...},\"stp\":{\"ttl\":<步数>}}",
  "source": 24,
  "type": 0
}
```

服务端只认 `summary.stp.ttl`，原始块内容不参与校验。
日期必须用 **UTC+8**，容器时钟是 UTC 的话直接取 `now()` 会差一天。

提交后会立刻回读当天记录做校验，HTTP 200 不算成功：

- `云端已更新为 N 步` —— 真的写进去了
- `服务端只加不减：云端已有 X 步` —— 当天值已大于目标，保持原值
- `提交成功但云端仍是 N 步` —— 服务端没接受，需要看日志

## 六、几个约束

**单日只加不减**：服务端保存当天最大值，推一个更小的值会被静默忽略，也没有删除接口。
要降只能等第二天。

**单日上限 98800**：超过会被截断，代码里直接拦下。

**限流**：登录接口对同一 IP 与同一账号都有频率限制，连续几次就返回 429。
多主机轮换能缓解，但账号被单独限流时只能等，通常一小时起步。

**显示位置**：云端数据和 App 界面是两套东西。App 首页读的是本地库，
云端写入后要在 App 里下拉刷新或者换设备登录才可能看到；
如果目标是让 App 里的数字变化，还得从设备侧处理。

## 七、命令行

```bash
export ZEPP_USER=you@example.com
export ZEPP_PASS=yourpassword
python3 tools/push_steps.py 28888
```

会自动登录、查设备号、读当前值、提交、回读校验，遇到 429 退避重试。

## 八、可选：绑定自己的域名（阿里云 DNS）

`tools/alidns.py` 用阿里云 DNS 接口把一条 A 记录指到当前公网 IP，不依赖官方 SDK：

```bash
export ALI_AK_ID=你的AccessKeyId
export ALI_AK_SECRET=你的AccessKeySecret

python3 tools/alidns.py --domain example.com --rr steps --check
python3 tools/alidns.py --domain example.com --rr steps --ip 203.0.113.10
python3 tools/alidns.py --domain example.com --rr steps --auto-ip --watch 300
```

`--watch` 会定时对比出口 IP，变了就自动更新记录（家庭宽带 / 移动网络 IP 会漂）。
AccessKey 建议用 RAM 子账号，只授予 `AliyunDNSFullAccess`。

注意：域名解析只解决"名字 → IP"，能不能访问还取决于该 IP 是否有公网入站。
运营商移动网络的 IPv4 多数在 CGNAT 后面，入站不通，这种情况需要内网穿透或把服务放到云主机上。

## 九、许可

MIT

## 九、公开页与管理端

服务分两个入口，同一套后端：

| 路径 | 入口 | 权限 |
|---|---|---|
| `/` | 公开页 | 任何人 |
| `/admin.html` | 管理端 | 只要密码，无用户名 |

### 公开页

- 列出可申请账号：显示备注名，没有备注就显示打码邮箱（`st***@163.com`），真实账号不外露
- 选中账号 → 填目标步数 + 称呼 + 备注 → 提交申请
- 「我的申请」按称呼过滤，能看状态：待审核 / 已通过 / 被驳回（含理由）
- 同账号同步数的重复申请自动合并

### 管理端

- 首次进入设置密码（只设密码，没有用户名），之后输入密码登录
- 密码存 `sha256(盐 + 密码)`，会话 Cookie 保持 7 天，改密码后所有会话失效
- 顶部「待审申请」区块：同意 → 立即真实提交并回读校验；不同意 → 填理由
- 账号卡片支持备注，标题优先显示备注
- 日志抽屉右上角可改密码

### 权限边界

除 `/api/public/*` 与 `/api/admin/login` 外，所有接口都要求登录，
未登录返回 `401 {"ok": false, "needAdmin": true}`。

### 新增数据表

```sql
requests(id, account_id, steps, note, requester, status, reason, result, created_at, handled_at)
settings(k, v)                -- 管理员密码哈希与盐
accounts.note                 -- 账号备注，老库自动补列
```
