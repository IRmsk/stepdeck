#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KeepWeb · 网页版步数托管台（全免费，无卡密/无广告/无次数限制）

    python3 server.py --port 8080

它做的事情和截图里那个"运动健康助手"一样：多账号托管、定时提交、智能/普通模式。
区别是这里没有任何付费墙 —— 卡密、看广告得次数、提交次数限制全部删掉了。

协议层是可插拔的：
  * providers.keep   调 Keep 官方接口（需要把抓到的接口/签名填进 config.json）
  * providers.mock   离线模拟，把整套产品先跑通（默认）
"""
import argparse
import json
import os
from datetime import timezone, timedelta

CST = timezone(timedelta(hours=8))


def today_str():
    return datetime.now(CST).strftime("%Y-%m-%d")
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    from provider_zepp import ZeppProvider, ZeppError
except Exception:  # 单文件也能跑
    ZeppProvider = None

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "data", "keepweb.db")
WEB_DIR = os.path.join(BASE, "web")
CONFIG_PATH = os.path.join(BASE, "config.json")

# ---------------------------------------------------------------- 数据库

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    provider    TEXT NOT NULL DEFAULT 'mock',
    nickname    TEXT,
    token       TEXT,
    password    TEXT,
    user_id     TEXT,
    status      TEXT DEFAULT 'ok',        -- ok / expired / error
    target      INTEGER DEFAULT 0,        -- 目标步数, 0=未配置
    current     INTEGER DEFAULT 0,        -- 当前(已提交)步数
    submit_cnt  INTEGER DEFAULT 0,
    exec_at     TEXT,                     -- HH:MM 定时执行
    mode        TEXT DEFAULT 'normal',    -- normal / smart
    custody     INTEGER DEFAULT 0,        -- 托管开关
    enabled     INTEGER DEFAULT 1,
    last_run    TEXT,
    created_at  TEXT
);
CREATE TABLE IF NOT EXISTS requests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT,
    steps      INTEGER,
    note       TEXT,                     -- 申请人备注
    requester  TEXT,                     -- 申请人自称的名字
    status     TEXT DEFAULT 'pending',   -- pending / approved / rejected / failed
    reason     TEXT,                     -- 驳回理由
    result     TEXT,                     -- 执行结果 JSON
    created_at TEXT,
    handled_at TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    k TEXT PRIMARY KEY,
    v TEXT
);
CREATE TABLE IF NOT EXISTS logs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    acc_id   TEXT,
    ts       TEXT,
    level    TEXT,
    message  TEXT
);
"""


def db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = db()
    c.executescript(SCHEMA)
    # 轻量迁移：老库补列
    cols = {r[1] for r in c.execute("PRAGMA table_info(accounts)")}
    for name, typ in (("user_id", "TEXT"), ("password", "TEXT"), ("note", "TEXT")):
        if name not in cols:
            c.execute("ALTER TABLE accounts ADD COLUMN %s %s" % (name, typ))
    c.commit()
    c.close()


# ---------------------------------------------------------------- 管理员口令

import hashlib
import secrets

SESSIONS = {}          # token -> 过期时间戳
SESSION_TTL = 7 * 24 * 3600
COOKIE_NAME = "sd_admin"


def _setting(k, default=None):
    c = db()
    r = c.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    c.close()
    return r[0] if r else default


def _set_setting(k, v):
    c = db()
    c.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
    c.commit()
    c.close()


def _hash(pw, salt):
    return hashlib.sha256((salt + "|" + pw).encode("utf-8")).hexdigest()


def admin_ready():
    return bool(_setting("admin_hash"))


def admin_check(pw):
    salt = _setting("admin_salt") or ""
    return _hash(pw, salt) == (_setting("admin_hash") or "")


def admin_set_password(pw):
    salt = secrets.token_hex(8)
    _set_setting("admin_salt", salt)
    _set_setting("admin_hash", _hash(pw, salt))


def new_session():
    t = secrets.token_hex(24)
    SESSIONS[t] = time.time() + SESSION_TTL
    return t


def session_ok(tok):
    exp = SESSIONS.get(tok)
    if not exp:
        return False
    if exp < time.time():
        SESSIONS.pop(tok, None)
        return False
    return True


def mask_user(u):
    u = u or ""
    if "@" in u:
        n, d = u.split("@", 1)
        return (n[:2] if len(n) > 2 else n[:1]) + "***@" + d
    return u[:3] + "****" + u[-2:] if len(u) > 6 else u


def log(acc_id, message, level="info"):
    c = db()
    c.execute("INSERT INTO logs(acc_id, ts, level, message) VALUES(?,?,?,?)",
              (acc_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), level, message))
    c.commit()
    c.close()


# ---------------------------------------------------------------- 协议层

class ProviderError(Exception):
    pass


class BaseProvider:
    name = "base"

    def login(self, username, password):
        raise NotImplementedError

    def submit(self, account, steps):
        raise NotImplementedError


class MockProvider(BaseProvider):
    """离线模拟：把产品全链路跑通，不碰真实服务"""
    name = "mock"

    def login(self, username, password):
        if not username or "@" not in username and not re.fullmatch(r"1\d{10}", username or ""):
            raise ProviderError("账号格式不对（手机号或邮箱）")
        if not password or len(password) < 4:
            raise ProviderError("密码至少 4 位")
        return {
            "token": "mock-" + uuid.uuid4().hex[:12],
            "nickname": username.split("@")[0],
            "status": "ok",
        }

    def submit(self, account, steps):
        time.sleep(0.4)  # 模拟网络往返
        if steps <= 0:
            raise ProviderError("步数必须大于 0")
        return {"ok": True, "submitted": steps, "message": "模拟提交成功（未连接真实服务）"}


class KeepProvider(BaseProvider):
    """
    真实 Keep 协议适配器。
    接口路径 / 签名算法在 config.json 里配置，缺一项就抛 ProviderError, 不猜。
    """
    name = "keep"

    def __init__(self):
        self.cfg = {}
        if os.path.exists(CONFIG_PATH):
            try:
                self.cfg = json.load(open(CONFIG_PATH, encoding="utf-8")).get("keep", {})
            except Exception:
                self.cfg = {}

    def _need(self, key):
        v = self.cfg.get(key)
        if not v:
            raise ProviderError(
                "Keep 协议未配置：config.json 里缺少 keep.%s\n"
                "把 Keep APK 抓包/逆向得到的接口和签名填进去，或继续用模拟模式。" % key)
        return v

    def login(self, username, password):
        import requests
        host = self._need("host")
        path = self._need("login_path")
        headers = {"User-Agent": self.cfg.get("ua", "okhttp/4.9.0")}
        headers.update(self.cfg.get("base_headers", {}))
        body = {"username": username, "password": password}
        if self.cfg.get("password_rsa"):
            raise ProviderError("config.json 要求 RSA 加密密码，但还没实现填充逻辑")
        r = requests.post(host + path, json=body, headers=headers, timeout=15)
        if r.status_code != 200:
            raise ProviderError("登录失败 HTTP %s: %s" % (r.status_code, r.text[:200]))
        data = r.json()
        token = (data.get("data") or {}).get("token") or data.get("token")
        if not token:
            raise ProviderError("登录返回里没有 token: %s" % r.text[:200])
        return {"token": token, "nickname": (data.get("data") or {}).get("nickname", username),
                "status": "ok"}

    def submit(self, account, steps):
        import requests
        host = self._need("host")
        path = self._need("step_path")
        headers = {
            "User-Agent": self.cfg.get("ua", "okhttp/4.9.0"),
            "Authorization": "Bearer " + (account["token"] or ""),
        }
        headers.update(self.cfg.get("base_headers", {}))
        body = {"steps": steps, "date": today_str()}
        body.update(self.cfg.get("step_extra", {}))
        r = requests.post(host + path, json=body, headers=headers, timeout=15)
        if r.status_code != 200:
            raise ProviderError("提交失败 HTTP %s: %s" % (r.status_code, r.text[:200]))
        return {"ok": True, "submitted": steps, "message": "已提交到 Keep"}


PROVIDERS = {"mock": MockProvider, "keep": KeepProvider}
if ZeppProvider:
    PROVIDERS["zepp_dry"] = lambda: ZeppProvider(dry_run=True)
    PROVIDERS["zepp"] = lambda: ZeppProvider(dry_run=False)


def get_provider(name):
    return PROVIDERS.get(name, MockProvider)()


# ---------------------------------------------------------------- 业务

def row_to_dict(r):
    d = dict(r)
    d.pop("password", None)
    d["tokenReady"] = bool(d.get("token"))
    if d.get("token"):
        d["token_tail"] = "…" + str(d["token"])[-4:]
    d.pop("token", None)
    d["custody"] = bool(d.get("custody"))
    d["enabled"] = bool(d.get("enabled"))
    return d


def api_stats():
    today = today_str()
    c = db()
    rows = [dict(r) for r in c.execute("SELECT * FROM accounts")]
    submits = c.execute(
        "SELECT COUNT(*) FROM logs WHERE message LIKE '提交 %' AND ts LIKE ?",
        (today + "%",)).fetchone()[0]
    c.close()
    today_steps = sum(r["current"] or 0 for r in rows if (r.get("last_run") or "").startswith(today))
    custody = [r for r in rows if r.get("custody") and r.get("enabled") and r.get("exec_at")]
    next_run = min((r["exec_at"] for r in custody), default=None)
    return {"ok": True, "accounts": len(rows), "custody_on": len(custody),
            "today_steps": today_steps, "today_submits": submits, "next_run": next_run}


def api_probe(body):
    """不登录也能知道账号在不在（Zepp 对已注册号返回 400，不存在返回 401）"""
    username = (body.get("username") or "").strip()
    if not username:
        return {"ok": False, "message": "先填账号"}
    try:
        r = ZeppProvider(dry_run=False).probe(username)
        return {"ok": True, "exists": r["exists"], "code": r["raw"]}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def api_accounts():
    c = db()
    rows = [row_to_dict(r) for r in c.execute("SELECT * FROM accounts ORDER BY created_at")]
    c.close()
    return rows


import base64


def _obf(pw):
    return base64.b64encode((pw or "").encode()).decode() if pw else ""


def _deobf(v):
    try:
        return base64.b64decode((v or "").encode()).decode()
    except Exception:
        return ""


def api_add_account(body):
    provider = body.get("provider") or "mock"
    prov = get_provider(provider)
    username = body.get("username", "").strip()
    # 限流/网络问题不要吞掉账号：先存下来，标成待登录，之后提交时自动重登
    try:
        info = getattr(prov, "login_any", prov.login)(username, body.get("password", ""))
    except Exception as e:
        msg = str(e)
        if "429" in msg or "timeout" in msg.lower() or "timed out" in msg.lower():
            acc_id = uuid.uuid4().hex[:12]
            c = db()
            c.execute("""INSERT INTO accounts(id, username, password, provider, nickname, token, user_id,
                         status, created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                      (acc_id, username, _obf(body.get("password")), provider, username, "", "",
                       "pending", datetime.now().isoformat(timespec="seconds")))
            if (body.get("note") or "").strip():
                c.execute("UPDATE accounts SET note=? WHERE id=?",
                          (body["note"].strip()[:40], acc_id))
            c.commit()
            c.close()
            log(acc_id, "账号已保存，但登录被拦（%s），稍后提交时会自动重登"
                % ("限流" if "429" in msg else "网络超时"), "error")
            return {"ok": True, "id": acc_id, "pending": True,
                    "message": "账号已保存；当前登录被限流，稍后提交会自动重试"}
        raise
    acc_id = uuid.uuid4().hex[:12]
    c = db()
    c.execute("""INSERT INTO accounts(id, username, password, provider, nickname, token, user_id, status, created_at)
                 VALUES(?,?,?,?,?,?,?,?,?)""",
              (acc_id, body.get("username", "").strip(), _obf(body.get("password")),
               provider, info.get("nickname"), info.get("token"),
               str(info.get("user_id") or ""), info.get("status", "ok"),
               datetime.now().isoformat(timespec="seconds")))
    if (body.get("note") or "").strip():
        c.execute("UPDATE accounts SET note=? WHERE id=?",
                  (body["note"].strip()[:40], acc_id))
    c.commit()
    c.close()
    log(acc_id, "账号添加成功（%s）" % provider)
    return {"ok": True, "id": acc_id}


def api_update_account(acc_id, body):
    fields, values = [], []
    for k in ("target", "exec_at", "mode", "custody", "enabled", "note"):
        if k in body:
            fields.append("%s=?" % k)
            v = body[k]
            if k in ("custody", "enabled"):
                values.append(int(bool(v)))
            elif k == "target":
                values.append(int(v or 0))
            else:
                values.append(v)
    if not fields:
        return {"ok": True}
    values.append(acc_id)
    c = db()
    c.execute("UPDATE accounts SET %s WHERE id=?" % ",".join(fields), values)
    c.commit()
    c.close()
    return {"ok": True}


def api_edit_account(acc_id, body):
    """改账号、密码、通道。给了新密码就重新登录换 token。"""
    c = db()
    r = c.execute("SELECT * FROM accounts WHERE id=?", (acc_id,)).fetchone()
    c.close()
    if not r:
        return {"ok": False, "message": "账号不存在"}
    acc = dict(r)

    username = (body.get("username") or acc["username"]).strip()
    provider = body.get("provider") or acc["provider"]
    new_pw = body.get("password")
    password = new_pw if new_pw else _deobf(acc.get("password"))

    info = {}
    relogin = bool(new_pw) or username != acc["username"] or provider != acc["provider"]
    if relogin:
        if not password:
            return {"ok": False, "message": "改账号需要重新输入密码"}
        try:
            _p = get_provider(provider)
            info = getattr(_p, "login_any", _p.login)(username, password)
        except Exception as e:
            return {"ok": False, "message": "登录失败：%s" % e}

    c = db()
    sets = ["username=?", "provider=?", "password=?"]
    vals = [username, provider, _obf(password)]
    if relogin:
        sets += ["token=?", "user_id=?", "nickname=?", "status=?"]
        vals += [info.get("token"), str(info.get("user_id") or ""),
                 info.get("nickname") or username, info.get("status", "ok")]
    if "target" in body:
        sets.append("target=?"); vals.append(int(body["target"] or 0))
    if "exec_at" in body:
        sets.append("exec_at=?"); vals.append(body["exec_at"])
    if "mode" in body:
        sets.append("mode=?"); vals.append(body["mode"])
    if "note" in body:
        sets.append("note=?"); vals.append((body.get("note") or "").strip()[:40])
    vals.append(acc_id)
    c.execute("UPDATE accounts SET %s WHERE id=?" % ",".join(sets), vals)
    c.commit()
    c.close()
    log(acc_id, "账号已修改%s" % ("（已重新登录）" if relogin else ""))
    return {"ok": True, "relogin": relogin}


def api_delete_account(acc_id):
    c = db()
    c.execute("DELETE FROM accounts WHERE id=?", (acc_id,))
    c.commit()
    c.close()
    return {"ok": True}


def do_submit(acc_id, steps=None):
    c = db()
    r = c.execute("SELECT * FROM accounts WHERE id=?", (acc_id,)).fetchone()
    c.close()
    if not r:
        return {"ok": False, "message": "账号不存在"}
    acc = dict(r)
    prov = get_provider(acc["provider"])
    # 之前没登录成功（限流/网络）的账号：提交时先补一次登录，成功就继续
    if not acc.get("token") and acc.get("password"):
        try:
            info = getattr(prov, "login_any", prov.login)(acc["username"], _deobf(acc["password"]))
            c = db()
            c.execute("UPDATE accounts SET token=?, user_id=?, status='ok' WHERE id=?",
                      (info.get("token"), str(info.get("user_id") or ""), acc_id))
            c.commit(); c.close()
            acc["token"] = info.get("token")
            acc["user_id"] = str(info.get("user_id") or "")
            log(acc_id, "补登录成功，继续提交")
        except Exception as e:
            c = db(); c.execute("UPDATE accounts SET status='pending' WHERE id=?", (acc_id,))
            c.commit(); c.close()
            log(acc_id, "补登录失败: %s" % str(e)[:80], "error")
            return {"ok": False, "pending": True, "message": str(e)}
    if not acc.get("token"):
        return {"ok": False, "pending": True,
                "message": "账号还没登录成功。点卡片上的『修改』填对密码。"}
    target = steps or acc["target"] or 0
    if target <= 0:
        return {"ok": False, "message": "还没填步数：在卡片输入框里输入数值，或点『设置』填目标"}

    prov = get_provider(acc["provider"])
    try:
        res = prov.submit(acc, target)
    except Exception as e:
        log(acc_id, "提交失败: %s" % e, "error")
        c = db()
        c.execute("UPDATE accounts SET status='error' WHERE id=?", (acc_id,))
        c.commit()
        c.close()
        return {"ok": False, "message": str(e)}

    # 以真实回读为准：provider 返回 changed=False 时不能假装成功
    got = res.get("submitted", target)
    changed = res.get("changed", True)
    c = db()
    if changed:
        c.execute("""UPDATE accounts SET current=?, submit_cnt=submit_cnt+1, status='ok',
                     last_run=? WHERE id=?""",
                  (got, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), acc_id))
    else:
        c.execute("UPDATE accounts SET submit_cnt=submit_cnt+1, status='warn', last_run=? WHERE id=?",
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), acc_id))
    c.commit()
    c.close()
    log(acc_id, "提交 %d 步: %s" % (target, res.get("message", "ok")),
        "info" if changed else "error")
    return {"ok": changed, "submitted": got, "changed": changed,
            "message": res.get("message", "ok")}


# ---------------------------------------------------------------- 申请单

def public_accounts():
    c = db()
    rows = [dict(r) for r in c.execute(
        "SELECT id, username, note, current, target, status FROM accounts ORDER BY created_at")]
    c.close()
    out = []
    for r in rows:
        out.append({"id": r["id"], "note": r.get("note") or "",
                    "account": mask_user(r["username"]), "current": r["current"] or 0,
                    "target": r["target"] or 0, "status": r["status"]})
    return out


def api_request_create(body):
    acc_id = (body.get("account_id") or "").strip()
    try:
        steps = int(body.get("steps") or 0)
    except Exception:
        steps = 0
    note = (body.get("note") or "").strip()[:200]
    who = (body.get("requester") or "").strip()[:40] or "匿名"
    if not acc_id:
        return {"ok": False, "message": "先选一个账号"}
    if steps <= 0:
        return {"ok": False, "message": "步数要大于 0"}
    if steps > 98800:
        return {"ok": False, "message": "单日上限 98,800"}
    c = db()
    acc = c.execute("SELECT * FROM accounts WHERE id=?", (acc_id,)).fetchone()
    if not acc:
        c.close()
        return {"ok": False, "message": "账号不存在"}
    # 同一账号 + 同一目标值，重复待审的申请直接合并，不刷屏
    dup = c.execute("SELECT id FROM requests WHERE account_id=? AND steps=? AND status='pending'",
                    (acc_id, steps)).fetchone()
    if dup:
        c.close()
        return {"ok": True, "id": dup[0], "dup": True, "message": "同样的申请已在等待审核"}
    c.execute("""INSERT INTO requests(account_id, steps, note, requester, status, created_at)
                 VALUES(?,?,?,?, 'pending', ?)""",
              (acc_id, steps, note, who, datetime.now().isoformat(timespec="seconds")))
    rid = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    c.commit()
    c.close()
    log(acc_id, "收到改步数申请 #%d：%d 步（%s）" % (rid, steps, who))
    return {"ok": True, "id": rid, "message": "申请已提交，等管理员审核"}


def api_request_list(status=None, who=None, limit=100):
    q = "SELECT r.*, a.note AS acc_note, a.username, a.current FROM requests r " \
        "LEFT JOIN accounts a ON a.id = r.account_id"
    where, vals = [], []
    if status:
        where.append("r.status=?")
        vals.append(status)
    if who:
        where.append("r.requester=?")
        vals.append(who)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY r.id DESC LIMIT ?"
    vals.append(int(limit))
    c = db()
    rows = [dict(r) for r in c.execute(q, vals)]
    c.close()
    for r in rows:
        r["account"] = mask_user(r.get("username") or "")
        r.pop("username", None)
    return rows


def api_request_handle(req_id, approve, reason=""):
    c = db()
    r = c.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    c.close()
    if not r:
        return {"ok": False, "message": "申请不存在"}
    r = dict(r)
    if r["status"] != "pending":
        return {"ok": False, "message": "这条已经处理过了（%s）" % r["status"]}
    now = datetime.now().isoformat(timespec="seconds")
    if not approve:
        c = db()
        c.execute("UPDATE requests SET status='rejected', reason=?, handled_at=? WHERE id=?",
                  ((reason or "").strip()[:200], now, req_id))
        c.commit(); c.close()
        log(r["account_id"], "驳回申请 #%d（%s）" % (req_id, reason or "未填理由"), "error")
        return {"ok": True, "status": "rejected"}
    res = do_submit(r["account_id"], r["steps"])
    status = "approved" if res.get("ok") else "failed"
    c = db()
    c.execute("UPDATE requests SET status=?, handled_at=?, result=? WHERE id=?",
              (status, now, json.dumps(res, ensure_ascii=False)[:500], req_id))
    c.commit(); c.close()
    log(r["account_id"], "通过申请 #%d：%d 步 → %s" % (req_id, r["steps"], res.get("message", "")),
        "info" if res.get("ok") else "error")
    return {"ok": True, "status": status, "result": res}


def scheduler_loop():
    """托管：到点自动提交，一天只跑一次（智能模式按小时分摊）"""
    while True:
        try:
            c = db()
            rows = c.execute("SELECT * FROM accounts WHERE custody=1 AND enabled=1").fetchall()
            c.close()
            now = datetime.now()
            for r in rows:
                acc = dict(r)
                if acc["target"] <= 0:
                    continue
                exec_at = acc["exec_at"] or now.strftime("%H:%M")
                try:
                    hh, mm = [int(x) for x in exec_at.split(":")[:2]]
                except Exception:
                    continue
                due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if now < due:
                    continue
                last = acc["last_run"] or ""
                if last.startswith(now.strftime("%Y-%m-%d")):
                    continue
                if acc["mode"] == "smart":
                    # 智能模式：按小时把目标拆成多段，本次提交当前应到量
                    hours = max(1, now.hour - 6)
                    part = int(acc["target"] * min(1.0, hours / 18.0))
                    do_submit(acc["id"], max(1, part))
                else:
                    do_submit(acc["id"])
        except Exception as e:
            log(None, "调度异常: %s" % e, "error")
        time.sleep(20)


# ---------------------------------------------------------------- HTTP

MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
        ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        try:
            with open("/tmp/keepweb-access.log", "a") as f:
                f.write("%s %s\n" % (datetime.now().strftime("%H:%M:%S"), fmt % args))
        except Exception:
            pass

    # --- 工具
    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _cookie(self, name):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == name:
                    return v
        return ""

    def _admin(self):
        tok = self._cookie(COOKIE_NAME) or self.headers.get("X-Admin-Token") or ""
        return session_ok(tok)

    def _deny(self):
        return self._json({"ok": False, "needAdmin": True, "message": "需要管理员密码"}, 401)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except Exception:
            return {}

    def _static(self, path):
        if path == "/":
            path = "/index.html"
        if path.rstrip("/") in ("/admin", "/console", "/manage"):
            path = "/admin.html"
        fp = os.path.normpath(os.path.join(WEB_DIR, path.lstrip("/")))
        if not fp.startswith(WEB_DIR) or not os.path.isfile(fp):
            self.send_error(404)
            return
        ext = os.path.splitext(fp)[1]
        data = open(fp, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # --- 路由
    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        try:
            # 公开
            if p == "/api/public/accounts":
                return self._json({"ok": True, "accounts": public_accounts()})
            if p == "/api/public/requests":
                who = (q.get("who") or [""])[0] or None
                return self._json({"ok": True, "requests": api_request_list(who=who, limit=30)})
            if p == "/api/admin/me":
                return self._json({"ok": True, "admin": self._admin(), "ready": admin_ready()})

            # 管理端
            if p.startswith("/api/"):
                if not self._admin():
                    return self._deny()
            if p == "/api/accounts":
                return self._json({"ok": True, "accounts": api_accounts()})
            if p == "/api/requests":
                st = (q.get("status") or [None])[0]
                return self._json({"ok": True, "requests": api_request_list(status=st)})
            if p == "/api/stats":
                return self._json(api_stats())
            if p == "/api/logs":
                n = int((q.get("limit") or ["50"])[0])
                c = db()
                rows = [dict(r) for r in c.execute(
                    "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (n,))]
                c.close()
                return self._json({"ok": True, "logs": rows})
            if p == "/api/meta":
                return self._json({"ok": True, "providers": list(PROVIDERS),
                                   "admin_ready": admin_ready()})
            return self._static(p)
        except Exception as e:
            return self._json({"ok": False, "message": str(e)}, 500)

    def do_POST(self):
        p = urlparse(self.path).path
        body = self._body()
        try:
            # ---- 公开：提交申请 ----
            if p == "/api/public/requests":
                return self._json(api_request_create(body))
            if p == "/api/admin/login":
                if not admin_ready():
                    pw = (body.get("password") or "").strip()
                    if len(pw) < 4:
                        return self._json({"ok": False, "message": "密码至少 4 位"})
                    admin_set_password(pw)
                elif not admin_check((body.get("password") or "").strip()):
                    return self._json({"ok": False, "message": "密码不对"}, 401)
                tok = new_session()
                data = json.dumps({"ok": True, "message": "已登录"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Set-Cookie",
                                 "%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax"
                                 % (COOKIE_NAME, tok, SESSION_TTL))
                self.end_headers()
                self.wfile.write(data)
                return

            if p == "/api/admin/logout":
                tok = self._cookie(COOKIE_NAME)
                SESSIONS.pop(tok, None)
                data = json.dumps({"ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Set-Cookie", "%s=; Path=/; Max-Age=0" % COOKIE_NAME)
                self.end_headers()
                self.wfile.write(data)
                return

            if p == "/api/admin/password":
                if not self._admin():
                    return self._deny()
                old = (body.get("old") or "").strip()
                new = (body.get("new") or "").strip()
                if not admin_check(old):
                    return self._json({"ok": False, "message": "原密码不对"}, 401)
                if len(new) < 4:
                    return self._json({"ok": False, "message": "新密码至少 4 位"})
                admin_set_password(new)
                SESSIONS.clear()
                return self._json({"ok": True, "message": "密码已更新，请重新登录"})

            # ---- 管理端 ----
            if p.startswith("/api/"):
                if not self._admin():
                    return self._deny()

            m = re.fullmatch(r"/api/requests/(\d+)/(approve|reject)", p)
            if m:
                rid = int(m.group(1))
                approve = m.group(2) == "approve"
                return self._json(api_request_handle(rid, approve, body.get("reason", "")))

            if p == "/api/probe":
                return self._json(api_probe(body))
            if p == "/api/accounts":
                return self._json(api_add_account(body))

            m = re.fullmatch(r"/api/accounts/([0-9a-f]+)/edit", p)
            if m:
                return self._json(api_edit_account(m.group(1), body))

            m = re.fullmatch(r"/api/accounts/([0-9a-f]+)/update", p)
            if m:
                return self._json(api_update_account(m.group(1), body))

            m = re.fullmatch(r"/api/accounts/([0-9a-f]+)/submit", p)
            if m:
                return self._json(do_submit(m.group(1), body.get("steps")))

            return self._json({"ok": False, "message": "not found"}, 404)
        except Exception as e:
            return self._json({"ok": False, "message": str(e)}, 400)

    def do_DELETE(self):
        p = urlparse(self.path).path
        if not self._admin():
            return self._deny()
        m = re.fullmatch(r"/api/accounts/([0-9a-f]+)", p)
        if m:
            return self._json(api_delete_account(m.group(1)))
        m = re.fullmatch(r"/api/requests/(\d+)", p)
        if m:
            c = db()
            c.execute("DELETE FROM requests WHERE id=?", (int(m.group(1)),))
            c.commit(); c.close()
            return self._json({"ok": True})
        return self._json({"ok": False, "message": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="8088", help="端口，可写多个：8088,8099")
    ap.add_argument("--host", default="0.0.0.0", help="监听地址，默认 0.0.0.0（同网段可访问）")
    a = ap.parse_args()
    init_db()
    threading.Thread(target=scheduler_loop, daemon=True).start()

    ports = [int(x) for x in str(a.port).replace(" ", "").split(",") if x.strip()]
    servers = []
    for port in ports:
        try:
            srv = ThreadingHTTPServer((a.host, port), Handler)
        except OSError as e:
            print("端口 %d 起不来：%s" % (port, e), flush=True)
            continue
        servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print("StepDeck: http://%s:%d  →  公开页 /  ·  管理端 /admin" % (a.host, port), flush=True)

    if not servers:
        raise SystemExit("所有端口都被占用")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
