#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""diagnose.py —— 检查一个 Zepp 账号「刷步能不能带动微信/支付宝运动」。

为什么需要它：改的是 Zepp 云端记录，而微信运动只认「数据来源」。
Zepp Life 里的原话是：**未绑定手表/手环设备，步数将无法同步到微信运动**。
所以对账之前先确认这个账号到底有没有「已绑定 + 近期同步」的设备。

用法：
    # 查单个账号
    python3 tools/diagnose.py --user you@example.com
    python3 tools/diagnose.py --user you@example.com --password 'xxx'

    # 查管理端里的所有账号（只读，不登录那些 token 还有效的）
    python3 tools/diagnose.py --all

    # 写入验证：推一个数，再看设备的 lastDataSyncTime 有没有跟着变
    python3 tools/diagnose.py --user you@example.com --push 77777

    # 给脚本用
    python3 tools/diagnose.py --user you@example.com --json

退出码：0 正常；2 被限流；3 登录失败；4 账号不存在
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from provider_zepp import (ZeppProvider, ZeppError, ZeppRateLimited,  # noqa: E402
                          device_verdict)

DEFAULT_SQLITE = os.path.join(os.environ.get("STEPDECK_DATA") or os.path.join(BASE, "data"),
                              "keepweb.db")


def _fmt_ts(v):
    try:
        return datetime.fromtimestamp(int(v)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "-"


def _age_days(v):
    try:
        return (time.time() - int(v)) / 86400.0
    except Exception:
        return None


def _fmt_device(it):
    keys = ("deviceId", "deviceType", "deviceSource", "productId", "deviceName",
            "bindingStatus", "activeStatus", "sn", "lastDataSyncTime", "applicationTime")
    keep = {k: it.get(k) for k in keys if it.get(k) not in (None, "")}
    if keep.get("lastDataSyncTime"):
        keep["lastDataSyncTime"] = _fmt_ts(keep["lastDataSyncTime"])
    if keep.get("applicationTime"):
        keep["applicationTime"] = _fmt_ts(keep["applicationTime"])
    return keep


def diagnose(user, password=None, push=None):
    """返回 dict；被限流抛 ZeppRateLimited，其它失败抛 ZeppError。"""
    prov = ZeppProvider(dry_run=False)
    info = prov.login_plain(user, password or "")
    tok, uid = info["token"], info["user_id"]
    items = prov.list_devices(tok, uid)

    day = None
    try:
        day = prov.read_day(tok, uid)
    except ZeppError:
        day = None
    steps = (day or {}).get("steps") or 0

    level, verdict = device_verdict(items)
    res = {
        "user": user,
        "uid": uid,
        "devices": [_fmt_device(it) for it in items],
        "device_count": len(items),
        "cloud_steps_today": steps,
        "verdict_level": level,
        "verdict": verdict,
    }

    if push:
        target = int(push)
        before_sync = max([int(it.get("lastDataSyncTime") or 0) for it in items] or [0])
        acc = {"token": tok, "user_id": uid, "username": user,
               "password": password or "", "device_id": prov.device_id}
        try:
            out = prov.submit(acc, target)
            res["push"] = {"target": target, "submitted": out.get("submitted"),
                           "changed": out.get("changed"), "message": out.get("message")}
        except ZeppRateLimited:
            raise
        except ZeppError as e:
            res["push"] = {"target": target, "error": str(e)}
        time.sleep(8)
        try:
            items2 = prov.list_devices(tok, uid)
        except ZeppError:
            items2 = items
        after_sync = max([int(it.get("lastDataSyncTime") or 0) for it in items2] or [0])
        res["push"]["device_sync_before"] = _fmt_ts(before_sync) if before_sync else "-"
        res["push"]["device_sync_after"] = _fmt_ts(after_sync) if after_sync else "-"
        if after_sync and after_sync != before_sync:
            res["push"]["attribution"] = "写入被服务端当成设备数据（lastDataSyncTime 变了）"
        else:
            res["push"]["attribution"] = ("设备同步时间没变：这次写入没被算作设备同步，"
                                         "微信侧未必认")
        try:
            day2 = prov.read_day(tok, uid)
            res["push"]["cloud_after"] = (day2 or {}).get("steps")
        except ZeppError:
            res["push"]["cloud_after"] = None
    return res


def from_db(db_path):
    import sqlite3
    if not os.path.exists(db_path):
        raise SystemExit("找不到数据库：%s" % db_path)
    c = sqlite3.connect(db_path)
    c.row_factory = sqlite3.Row
    rows = c.execute("SELECT username, provider, token, user_id, device_id FROM accounts "
                     "WHERE provider LIKE 'zepp%'").fetchall()
    c.close()
    return [dict(r) for r in rows]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", action="append", default=[], help="账号，可重复")
    ap.add_argument("--password", default="", help="密码（不给就只读判断，不登录）")
    ap.add_argument("--push", type=int, default=0, help="写入验证：推这个步数再比对设备同步时间")
    ap.add_argument("--all", action="store_true", help="遍历管理端数据库里的 zepp 账号")
    ap.add_argument("--db", default=DEFAULT_SQLITE)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    users = list(a.user)
    if a.all:
        users += [r["username"] for r in from_db(a.db)]
    users = [u for i, u in enumerate(users) if u and u not in users[:i]]
    if not users:
        raise SystemExit("给一个账号：--user xxx@example.com，或者 --all")

    results, code = [], 0
    for u in users:
        try:
            r = diagnose(u, a.password, a.push or None)
            results.append(r)
        except ZeppRateLimited as e:
            r = {"user": u, "verdict_level": "bad", "error": str(e),
                 "retry_after": e.retry_after}
            results.append(r)
            print("被限流：%s（约 %d 分钟后再试）" % (u, e.retry_after // 60), file=sys.stderr)
            code = 2
            break
        except ZeppError as e:
            results.append({"user": u, "verdict_level": "bad", "error": str(e)})
            code = 3

    if a.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return code

    mark = {"ok": "✅", "warn": "⚠️ ", "bad": "❌"}
    for r in results:
        print("=" * 60)
        print("%s %s" % (mark.get(r.get("verdict_level"), "?"), r["user"]))
        if r.get("error"):
            print("   错误：%s" % r["error"])
            continue
        print("   uid            : %s" % r["uid"])
        print("   云端今天       : %s 步" % r["cloud_steps_today"])
        print("   绑定设备       : %d 台" % r["device_count"])
        for d in r["devices"]:
            print("     - %s" % json.dumps(d, ensure_ascii=False))
        print("   结论           : %s" % r["verdict"])
        if r.get("push"):
            p = r["push"]
            print("   写入验证       : 目标 %s → 云端 %s | %s"
                  % (p.get("target"), p.get("cloud_after"), p.get("message") or p.get("error")))
            print("     设备同步时间  : %s → %s" % (p.get("device_sync_before"),
                                                p.get("device_sync_after")))
            print("     归因          : %s" % p.get("attribution"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
