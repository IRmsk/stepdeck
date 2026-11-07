#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
push_steps.py —— 命令行直接改写当天步数（含 429 退避）。

用法:
    export ZEPP_USER=you@example.com
    export ZEPP_PASS=yourpassword
    python3 tools/push_steps.py 28888

上报协议:
    POST {data_host}/v1/data/band_data.json?&t=<毫秒>
    header: apptoken
    body:   userid=..&last_sync_data_time=..&device_type=0&last_deviceid=..&data_json=<urlencode>
    data_json 元素: {data_hr, date, data:[{start,stop,value,tz,did,src}], summary(字符串), source, type}
"""
import os
import sys
import time

import requests

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from provider_zepp import ZeppProvider, ZeppError  # noqa: E402

USER = os.environ.get("ZEPP_USER", "")
PASS = os.environ.get("ZEPP_PASS", "")


def login():
    p = ZeppProvider(dry_run=False)
    for i in range(30):
        try:
            r = p.login_cached(USER, PASS)
            print("[login] ok uid=%s" % r["user_id"], flush=True)
            return p, r
        except ZeppError as e:
            if "429" in str(e):
                print("[login] 429 限流，480s 后重试 (%d/30)" % (i + 1), flush=True)
                time.sleep(480)
                continue
            print("[login] 失败:", str(e)[:120], flush=True)
            time.sleep(120)
        except Exception as e:
            print("[login] 网络异常 %s，120s 后重试 (%d/30)" % (type(e).__name__, i + 1), flush=True)
            time.sleep(120)
    raise SystemExit("登录始终失败")


def main():
    if len(sys.argv) < 2:
        raise SystemExit("用法: python3 tools/push_steps.py <步数>")
    if not USER or not PASS:
        raise SystemExit("先设置环境变量 ZEPP_USER / ZEPP_PASS")
    steps = int(sys.argv[1])

    p, r = login()
    acc = {"token": r["token"], "user_id": r["user_id"], "username": USER, "password": PASS}

    for attempt in range(4):
        try:
            did = p.active_device_id(acc["token"], acc["user_id"])
            print("[device]", did, flush=True)
            day = p.read_day(acc["token"], acc["user_id"])
            print("[cloud] 当前:", (day or {}).get("steps"), flush=True)
            res = p.submit(acc, steps)
            print("[push]", res, flush=True)
            if res.get("changed"):
                break
        except Exception as e:
            print("[push] 失败(%d/4):" % (attempt + 1), str(e)[:140], flush=True)
            time.sleep(60)


if __name__ == "__main__":
    main()
