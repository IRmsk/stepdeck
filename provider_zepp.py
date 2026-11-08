#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZeppProvider —— 从 Zepp.apk (com.huami.watch.hmwatchmanager 10.10.5) 里挖出来的协议。

证据（全部来自反编译常量，不是猜的）：

  classes5.dex  Lcom/xiaomi/hm/health/init/coldlaunch/HttpInitTask;->a()
        '/v1/data/band_data.json'          ← 步数/健康数据上传
        '/registrations/[^/]+/tokens'      ← 账号换 token
        '/registrations/[^/]+/password'    ← 改密码
        '/v1/client/register'              ← 注册
        '/encryption/whiteBoxKey'          ← 白盒密钥（密码加密用）

  classes3.dex  Lejk;  (HMSportWebAPI)
        b()  GET  /v1/data/band_data.json   params: query_type=summary|detail,
                                                from_date, to_date
        e()  组装每天一条的 JSON: date / type / source / summary / data /
                                   data_hr / summary_hr / indexs / slp / rhr
        f()  POST /v1/data/band_data.json   params: data_json, last_deviceid,
               last_source, last_sync_data_time, device_type, uuid, push_uuid,
               allowMultiDeviceOnMultiType

  classes3.dex  Lcom/huami/passport/v2/impl/AccountApiV2;->q()
        登录参数: third_name / app_name / grant_type / code / device_id /
                  device_model / app_version / country_code

  classes2.dex  Ll5d0;->a()  → 通用请求头
        appname, apptoken, callid, country, timezone, channel, appplatform=android_phone
  classes3.dex  Lzhu;->m()
        device_language, apptoken, appname, lang, device_source

协议本身是"填参数就能打"的 JSON/表单接口，没有自定义二进制签名；
剩下唯一没定死的是登录密码字段（明文 / MD5 / 白盒加密），所以这里做成可切换。
"""
import hashlib
import json
import os
import urllib.parse
import uuid
import time
from datetime import datetime, timezone, timedelta

try:
    from Crypto.Cipher import AES as _AES_MOD  # noqa: F401
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

# Zepp 以北京时间为准；容器是 UTC，直接用 now() 会差一天（会把昨天的记录当成今天）
CST = timezone(timedelta(hours=8))


def today_str():
    return datetime.now(CST).strftime("%Y-%m-%d")
import uuid as uuidlib
from datetime import datetime

import requests

# ---- 常量（来自 APK） ----
# 实测：真正能吃下账号密码的是这组（/v2/client/login 是第三方 OAuth 客户端用的，不是账号登录）
ACCOUNT_HOST_CN = "https://api-user.zepp.com"
ACCOUNT_HOST_INTL = "https://api-user.zepp.com"
LEGACY_ACCOUNT_HOST = "https://account-cn.zepp.com"
DATA_HOST_CN = "https://api-mifit-cn.huami.com"
DATA_HOST_INTL = "https://api-mifit.zepp.com"

DEFAULT_UA = "okhttp/4.12.0"

# 登录链路（token 交换的请求体是 AES-128-CBC 加密的表单，这就是之前裸发参数一直 400 的原因）
AES_KEY = b"xeNtBVqzDc6tuNTh"
AES_IV = b"MAAAYAAAAAAAAABg"
# 登录多主机轮换（参考 steps.zepplife / zepplife-step：单主机会被限流打死）
LOGIN_HOSTS = ["https://api-user.huami.com", "https://api-user.zepp.com",
               "https://api-user-cn.huami.com", "https://api-user-cn.zepp.com"]
CLIENT_HOSTS = ["https://account.huami.com", "https://account.zepp.com",
                "https://account-cn.huami.com"]
TOKEN_HOSTS = ["https://account-cn.huami.com", "https://account.huami.com"]
# 数据主机池
DATA_HOSTS = ["https://api-mifit-cn.huami.com", "https://api-mifit.huami.com",
              "https://api-mifit.zepp.com", "https://api-mifit-cn.zepp.com"]
# Zepp 单日步数上限，超过会被服务端截断
MAX_STEPS = 98800

TOKENS_HOST = "https://api-user-cn.zepp.com"
LOGIN_HOST = "https://api-mifit-cn.huami.com"
DATA_HOST = "https://api-mifit-cn.huami.com"


class ZeppError(Exception):
    pass


def _device_id():
    """Zepp 用 16 位十六进制设备号"""
    return uuidlib.uuid4().hex[:16]


def _now_hms():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ZeppProvider:
    """
    构造参数（都可覆盖）：
      region   'cn' | 'us'
      app_name Zepp 用的 app_name，CN 版默认 com.huami.midong
      enc      'plain' | 'md5'   —— 登录密码字段怎么处理
      dry_run  True 时不真正发请求，只回放将要发的包（默认开启，安全）
    """

    name = "zepp"

    def __init__(self, region="cn", app_name="com.huami.midong",
                 app_version="9.1.100", enc="plain", dry_run=True):
        self.region = region
        self.app_name = app_name
        self.app_version = app_version
        self.enc = enc
        self.dry_run = dry_run
        self.account_host = ACCOUNT_HOST_CN if region == "cn" else ACCOUNT_HOST_INTL
        self.data_host = DATA_HOST_CN if region == "cn" else DATA_HOST_INTL
        self.device_id = _device_id()

    # ---------------- 公共头 ----------------
    def _headers(self, token=None, user_id=None):
        # 兼容：token 可能来自构造函数外部注入
        h = {
            "User-Agent": DEFAULT_UA,
            "appname": self.app_name,
            "appplatform": "android_phone",
            "appversion": self.app_version,
            "channel": "normal",
            "country": "CN" if self.region == "cn" else "US",
            "lang": "zh_CN",
            "timezone": "Asia/Shanghai",
            "vb": "202509151347", "vn": "9.12.5", "cv": "151689_9.12.5",
            "hm-privacy-diagnostics": "false", "hm-privacy-ceip": "true",
            "x-request-id": str(uuidlib.uuid4()),
            "channel": "a100900101016",
            "v": "2.0",
            "device_id": self.device_id,
            "device_model": "PKM110",
            "device_language": "zh",
        }
        if token:
            h["apptoken"] = token
        if user_id:
            h["userid"] = str(user_id)
        return h

    # ---------------- 登录 ----------------
    def _encode_password(self, password):
        if self.enc == "md5":
            return hashlib.md5(password.encode()).hexdigest()
        return password  # 明文（第一版先按明文试，服务端会明确报错）

    def build_login(self, username, password):
        """token 交换：AES-CBC 加密的 urlencoded 表单 → 303 带 access/refresh"""
        payload = {
            "emailOrPhone": username,
            "state": "REDIRECTION",
            "client_id": "HuaMi",
            "password": password,
            "redirect_uri": "https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html",
            "region": "us-west-2",
            "token": ["access", "refresh"],
            "country_code": "CN" if self.region == "cn" else "US",
        }
        raw = urllib.parse.urlencode(payload, doseq=True).encode()
        body = self._aes(raw)
        headers = {
            "app_name": "com.huami.midong", "appname": "com.huami.midong",
            "cv": "151689_9.12.5", "v": "2.0", "appplatform": "android_phone",
            "vb": "202509151347", "vn": "9.12.5",
            "user-agent": "Zepp/9.12.5 (Pixel 4; Android 12; Density/2.75)",
            "x-hm-ekv": "1",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "accept-encoding": "gzip",
        }
        return TOKENS_HOST + "/v2/registrations/tokens", headers, body

    @staticmethod
    def _aes(data):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
        except ImportError:
            raise ZeppError("这台机器没装 pycryptodome，加密登录不可用；"
                            "明文登录不受影响，pip install pycryptodome 可启用备份链路")
        return AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV).encrypt(pad(data, 16))

    CACHE_DIR = "/tmp/zepp_tokens"

    def _cache_path(self, username):
        import os
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        safe = "".join(c if c.isalnum() else "_" for c in username)
        return os.path.join(self.CACHE_DIR, safe + ".json")

    def cached(self, username):
        import os
        fp = self._cache_path(username)
        if not os.path.exists(fp):
            return None
        try:
            d = json.load(open(fp))
            if d.get("ts", 0) + 3600 > time.time():
                return d
        except Exception:
            pass
        return None

    def login_cached(self, username, password):
        d = self.cached(username)
        if d:
            self.app_token = d["token"]; self.user_id = d["user_id"]
            self.login_token = d.get("login_token")
            return {"token": d["token"], "user_id": d["user_id"],
                    "nickname": username, "status": "ok", "cached": True}
        try:
            r = self.login_plain(username, password)
        except Exception as e1:
            if "429" in str(e1):
                raise
            try:
                r = self.login(username, password)
            except Exception:
                raise e1
        try:
            json.dump({"token": r["token"], "user_id": r["user_id"],
                       "login_token": self.login_token, "ts": time.time()},
                      open(self._cache_path(username), "w"))
        except Exception:
            pass
        return r

    # ---- 参考 zepp-life-update-steps / Zepp-Steps-Automation 的明文三步登录 ----
    PLAIN_H = {
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "user-agent": "MiFit/6.12.0 (MCE16; Android 16; Density/1.5)",
        "app_name": "com.xiaomi.hm.health",
    }

    def login_plain(self, username, password):
        """
        明文三步登录（参考 zepp-life-update-steps / Zepp-Steps-Automation）：
          1) api-user*.huami.com  /registrations/{acct}/tokens  json_response=true → access
          2) account*.huami.com   /v2/client/login              → login_token / user_id
          3) account*-cn.huami.com /v1/client/app_tokens        → app_token
        每步都在多台主机间轮换，命中 429 就换下一台，全部命中才报限流。
        """
        import urllib.parse as up
        acc = ("+86" + username) if (username.isdigit() and len(username) == 11) else username
        third = "huami_phone" if acc.startswith("+86") else "huami"
        quoted = up.quote(acc)

        form = ("client_id=HuaMi&country_code=CN&json_response=true&name=%s&password=%s"
                "&redirect_uri=https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html"
                "&state=REDIRECTION&token=access" % (quoted, up.quote(password)))

        code, last_err, rate_limited, rejected = None, None, 0, 0
        for host in LOGIN_HOSTS:
            try:
                r = requests.post("%s/registrations/%s/tokens" % (host, quoted),
                                  data=form, headers=self.PLAIN_H, timeout=20)
            except Exception as e:
                last_err = "%s 连不上（%s）" % (host, type(e).__name__)
                continue
            if r.status_code == 429:
                rate_limited += 1
                last_err = "%s 限流" % host
                continue
            if r.status_code == 200:
                j = r.json() or {}
                code = j.get("access")
                if code:
                    break
                if j.get("error") in (401, "401"):
                    rejected += 1        # 服务端明确说账号或密码不对
                last_err = "%s 没给 access（error=%s）" % (host, j.get("error"))
            else:
                last_err = "%s HTTP %s" % (host, r.status_code)
        if not code:
            if rate_limited >= len(LOGIN_HOSTS):
                raise ZeppError("429 登录太频繁，多台主机都被限流了，等几分钟")
            if rejected:
                raise ZeppError("账号或密码不对（服务端返回 401）")
            raise ZeppError("登录失败：%s" % (last_err or "未知原因"))

        d2 = ("app_name=com.xiaomi.hm.health&country_code=CN&code=%s&device_id=00:00:00:00:00:00"
              "&device_model=android_phone&app_version=6.12.0&grant_type=access_token"
              "&allow_registration=false&source=com.xiaomi.hm.health&third_name=%s" % (code, third))
        ti = None
        for host in CLIENT_HOSTS:
            try:
                r2 = requests.post(host + "/v2/client/login", data=d2, headers=self.PLAIN_H, timeout=20)
                if r2.status_code == 200:
                    ti = (r2.json() or {}).get("token_info") or {}
                    if ti.get("login_token"):
                        break
            except Exception:
                continue
        if not ti or not ti.get("login_token"):
            raise ZeppError("换取 login_token 失败（所有主机）HTTP")

        app_token = None
        for host in TOKEN_HOSTS:
            try:
                r3 = requests.get(
                    host + "/v1/client/app_tokens?app_name=com.xiaomi.hm.health"
                    "&dn=api-user.huami.com%2Capi-mifit.huami.com%2Capp-analytics.huami.com"
                    "&login_token=" + ti["login_token"] + "&os_version=4.1.0",
                    headers=self.PLAIN_H, timeout=20)
                if r3.status_code == 200:
                    app_token = ((r3.json() or {}).get("token_info") or {}).get("app_token")
                    if app_token:
                        break
            except Exception:
                continue
        if not app_token:
            raise ZeppError("拿 app_token 失败（所有主机）")

        self.app_token = app_token
        self.user_id = ti.get("user_id")
        self.login_token = ti["login_token"]
        return {"token": app_token, "user_id": self.user_id, "nickname": username,
                "status": "ok", "dry_run": self.dry_run}

    def login_any(self, username, password):
        """外部统一走这个：明文优先，失败再试加密链路（加密链路需要 pycryptodome）"""
        try:
            return self.login_plain(username, password)
        except ZeppError as e1:
            if "429" in str(e1) or not HAS_CRYPTO:
                raise
            try:
                return self.login(username, password)
            except ZeppError:
                raise e1
            except Exception:
                raise e1

    def login(self, username, password):
        url, headers, body = self.build_login(username, password)
        if self.dry_run:
            return {"token": "dry-" + uuidlib.uuid4().hex[:10], "nickname": username,
                    "status": "ok", "dry_run": True, "request": {"url": url, "bytes": len(body)}}

        r = requests.post(url, data=body, headers=headers, allow_redirects=False, timeout=25)
        loc = r.headers.get("Location", "")
        if r.status_code == 429:
            raise ZeppError("429 登录太频繁，被限流了，等几分钟再试")
        if r.status_code != 303 or "access=" not in loc:
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
            code = q.get("error")
            if code == "401":
                raise ZeppError("401 密码不对（账号被拒），不是限流、不是网络")
            raise ZeppError("登录失败（HTTP %s / %s）: %s"
                            % (r.status_code, code or "无错误码", (loc or r.text)[:120]))
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
        access = q.get("access")
        if not access:
            raise ZeppError("没拿到 access token: %s" % loc[:160])

        # 第二步：用 access token 换 app_token / user_id
        lp = {
            "code": access, "device_id": str(uuidlib.uuid4()), "device_model": "android_phone",
            "app_version": "9.12.5",
            "dn": "api-mifit.zepp.com,api-user.zepp.com,api-mifit.zepp.com,api-watch.zepp.com,"
                  "app-analytics.zepp.com,auth.zepp.com,api-analytics.zepp.com",
            "third_name": "huami", "source": "com.huami.watch.hmwatchmanager:9.12.5:151689",
            "app_name": "com.huami.midong",
            "country_code": "CN" if self.region == "cn" else "US",
            "grant_type": "access_token", "allow_registration": "false",
            "lang": "zh" if self.region == "cn" else "en",
            "countryState": "CN-ZJ" if self.region == "cn" else "US-NY",
        }
        lh = {
            "app_name": "com.huami.webapp", "appname": "com.huami.webapp",
            "origin": "https://user.zepp.com", "referer": "https://user.zepp.com/",
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "accept": "application/json, text/plain, */*", "accept-language": "zh-CN,zh;q=0.9",
        }
        r2 = requests.post(LOGIN_HOST + "/v2/client/login", data=lp, headers=lh, timeout=25)
        if r2.status_code != 200:
            raise ZeppError("换取 app_token 失败（HTTP %s）: %s" % (r2.status_code, r2.text[:200]))
        info = (r2.json() or {}).get("token_info") or {}
        if not info.get("app_token"):
            raise ZeppError("登录返回没有 app_token: %s" % r2.text[:200])
        self.app_token = info["app_token"]
        self.user_id = info.get("user_id")
        self.login_token = info.get("login_token")
        return {"token": info["app_token"], "user_id": info.get("user_id"),
                "nickname": username, "status": "ok"}

    # ---------------- 探测账号是否存在 ----------------
    def probe(self, username):
        url, headers, body = self.build_login(username, "x")
        r = requests.post(url, data=body, headers=headers, allow_redirects=False, timeout=20)
        loc = r.headers.get("Location", "")
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
        return {"exists": r.status_code == 303 and "access=" in loc,
                "raw": q.get("error") or str(r.status_code)}

    # ---------------- 读云端每日数据 ----------------
    def read_day(self, token, user_id, date=None):
        d = date or today_str()
        H = self._headers(token, user_id); H.pop("Content-Type", None)
        r, err = None, None
        for host in DATA_HOSTS:
            u = ("%s/v1/data/band_data.json?query_type=summary&device_type=0"
                 "&from_date=%s&to_date=%s" % (host, d, d))
            try:
                r = requests.get(u, headers=H, timeout=20)
            except Exception as e:
                err = "%s 连不上（%s）" % (host, type(e).__name__)
                continue
            if r.status_code == 200:
                break
            err = "HTTP %s: %s" % (r.status_code, r.text[:120])
            if r.status_code in (401, 403):
                raise ZeppError("读取失败 %s" % err)
        if r is None or r.status_code != 200:
            raise ZeppError("读取失败（所有主机）%s" % (err or ""))
        data = (r.json() or {}).get("data") or []
        row = next((x for x in data if x.get("date_time") == d), None)
        if not row:
            return None
        import base64 as _b64
        summary = json.loads(_b64.b64decode(row["summary"]))
        return {"row": row, "summary": summary,
                "steps": ((summary.get("stp") or {}).get("ttl") or 0)}

    # ---------------- 步数上传 ----------------
    # 报文模板来自 Caryio/ChangeWechatSport（同样跑 Zepp Life 接口改步数，已跑通）
    TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "tools", "zepp_template.json")
    DEVICE_ID = "DA932FFFFE8816E7"

    def _template(self):
        with open(self.TEMPLATE, encoding="utf-8") as f:
            return json.load(f)[0]

    def build_day(self, steps, uid, date=None, template=None):
        item = dict(template or self._template())
        d = date or today_str()
        item["date"] = d
        summary = json.loads(item["summary"]) if isinstance(item["summary"], str) else dict(item["summary"])
        stp = summary.setdefault("stp", {})
        stp["ttl"] = int(steps)
        stp["dis"] = int(steps * 0.72)
        stp["cal"] = int(steps * 0.04)
        summary["tz"] = 28800
        item["summary"] = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
        for blk in item.get("data") or []:
            blk["did"] = self.DEVICE_ID
            blk["tz"] = 28800
        return item

    def active_device_id(self, token, uid):
        """先问服务端这个账号真正绑定的设备，写数据时用同一个 did，App 才会认"""
        for host in ("https://api-mifit-cn.huami.com", "https://api-mifit.huami.com"):
            try:
                r = requests.get("%s/users/%s/devices?enable=true" % (host, uid),
                                 headers={"apptoken": token}, timeout=12)
                if r.status_code != 200:
                    continue
                items = (r.json() or {}).get("items") or []
                if not items:
                    continue
                # 优先 activeStatus 启用的，其次 bindingStatus 已绑定的
                for it in items:
                    if not it.get("deviceId"):
                        continue
                    if it.get("activeStatus") in (1, True):
                        return it["deviceId"]
                for it in items:
                    if it.get("deviceId") and it.get("bindingStatus") in (1, True):
                        return it["deviceId"]
                return items[0]["deviceId"]
            except Exception:
                continue
        return self.DEVICE_ID

    def build_upload(self, account, steps, date=None, template=None, device_id=None):
        """真实格式：body 必须带 userid，URL 是 ?&t=毫秒时间戳，不需要 query_type"""
        did = device_id or self.DEVICE_ID
        item = self.build_day(steps, account.get("user_id"), date, template)
        for blk in item.get("data") or []:
            blk["did"] = did
        payload = urllib.parse.quote(
            json.dumps([item], ensure_ascii=False, separators=(",", ":")))
        body = ("userid=%s&last_sync_data_time=%d&device_type=0&last_deviceid=%s&data_json=%s"
                % (account.get("user_id"), int(time.time()) - 60, did, payload))
        headers = {"apptoken": account.get("token"),
                   "Content-Type": "application/x-www-form-urlencoded"}
        return (DATA_HOST + "/v1/data/band_data.json?&t=%d" % int(time.time() * 1000)), headers, body

    def submit(self, account, steps, date=None):
        steps = int(steps)
        if steps > MAX_STEPS:
            raise ZeppError("单日步数上限 %d，%d 会被服务端截断" % (MAX_STEPS, steps))
        if steps <= 0:
            raise ZeppError("步数必须大于 0")
        """
        报文必须带设备原始数据（data / data_hr），只发 summary 服务端会静默丢弃。
        模板取自 Caryio/ChangeWechatSport 的实测报文，只替换日期和步数。
        发送后一律回读校验，不拿 200 当成功。
        """
        token, uid = account.get("token"), account.get("user_id")
        if self.dry_run:
            return {"ok": True, "submitted": 0, "dry_run": True,
                    "message": "演练模式：包已组装，未发送"}

        # token 会被新登录顶掉，遇到 401 自动重登一次
        def relogin():
            u, pw = account.get("username"), account.get("password")
            if not u or not pw:
                raise ZeppError("token 失效且没有账号密码可重登")
            try:
                res = self.login_plain(u, pw)
            except Exception as e1:
                if "429" in str(e1):      # 限流就别再撞加密链路了，会把错误搞混
                    raise e1
                res = self.login(u, pw)
            account["token"] = res["token"]
            account["user_id"] = res["user_id"]
            return res["token"], res["user_id"]

        try:
            before = self.read_day(token, uid, date)
        except ZeppError as e:
            if "401" not in str(e):
                raise
            token, uid = relogin()
            before = self.read_day(token, uid, date)

        did = self.active_device_id(token, uid)
        url, headers, form = self.build_upload(account, steps, date, self._template(), did)
        r, last = None, None
        for host in DATA_HOSTS:
            u = "%s/v1/data/band_data.json?&t=%d" % (host, int(time.time() * 1000))
            try:
                r = requests.post(u, data=form, headers=headers, timeout=25)
            except Exception as e:
                last = "%s 连不上（%s）" % (host, type(e).__name__)
                continue
            if r.status_code == 200:
                break
            last = "HTTP %s: %s" % (r.status_code, r.text[:120])
        if r is None or r.status_code != 200:
            raise ZeppError("上传失败（所有主机）%s" % (last or ""))
        try:
            after = self.read_day(token, uid, date)
        except ZeppError:
            after = None
        now_steps = (after or {}).get("steps") or 0
        prev = (before or {}).get("steps") or 0
        changed = now_steps != prev
        if changed:
            msg = "云端已更新为 %d 步" % now_steps
        elif now_steps > steps:
            msg = "服务端只加不减：云端已有 %d 步，比目标 %d 大，保持原值" % (now_steps, steps)
        else:
            msg = "提交成功但云端仍是 %d 步" % now_steps
        return {"ok": True, "submitted": now_steps, "changed": changed,
                "before": (before or {}).get("steps"), "message": msg}
