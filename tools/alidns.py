#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alidns.py —— 阿里云 DNS 记录同步（无第三方 SDK，纯 requests + HMAC-SHA1 签名）

用法：
    export ALI_AK_ID=你的AccessKeyId
    export ALI_AK_SECRET=你的AccessKeySecret

    # 看现有记录
    python3 tools/alidns.py --domain example.com --rr steps --check

    # 新增或更新 A 记录到指定 IP
    python3 tools/alidns.py --domain example.com --rr steps --ip 203.0.113.10

    # 自动取当前公网出口 IP
    python3 tools/alidns.py --domain example.com --rr steps --auto-ip

    # 每 5 分钟盯一次，IP 变了就改
    python3 tools/alidns.py --domain example.com --rr steps --auto-ip --watch 300
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse
import uuid

import requests

ENDPOINT = "https://alidns.aliyuncs.com/"


def _pe(s):
    """阿里云要求的 percentEncode"""
    s = str(s)
    out = urllib.parse.quote(s, safe="")
    return out.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


def _sign(params, secret):
    items = sorted(params.items())
    canon = "&".join("%s=%s" % (_pe(k), _pe(v)) for k, v in items)
    to_sign = "GET&%2F&" + _pe(canon)
    h = hmac.new((secret + "&").encode(), to_sign.encode(), hashlib.sha1).digest()
    return base64.b64encode(h).decode()


def call(action, ak_id, ak_secret, **kwargs):
    params = {
        "Action": action,
        "Format": "JSON",
        "Version": "2015-01-09",
        "AccessKeyId": ak_id,
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": uuid.uuid4().hex,
        "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    params.update({k: v for k, v in kwargs.items() if v not in (None, "")})
    params["Signature"] = _sign(params, ak_secret)
    r = requests.get(ENDPOINT, params=params, timeout=20)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": r.text[:300]}


def public_ip():
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://myip.ipip.net"):
        try:
            r = requests.get(u, timeout=10)
            t = r.text.strip()
            if u.endswith("ipip.net"):
                t = t.split()[-1]
            if t.count(".") == 3:
                return t
        except Exception:
            continue
    raise SystemExit("取不到公网 IP")


def get_record(ak_id, ak_secret, domain, rr):
    code, j = call("DescribeDomainRecords", ak_id, ak_secret,
                   DomainName=domain, RRKeyWord=rr, Type="A", PageSize=100)
    if code != 200:
        raise SystemExit("查询失败 %s: %s" % (code, json.dumps(j, ensure_ascii=False)[:300]))
    for rec in (j.get("DomainRecords") or {}).get("Record") or []:
        if rec.get("RR") == rr and rec.get("Type") == "A":
            return rec
    return None


def upsert(ak_id, ak_secret, domain, rr, ip, ttl=600):
    rec = get_record(ak_id, ak_secret, domain, rr)
    if rec and rec.get("Value") == ip:
        return "unchanged", rec.get("RecordId"), ip
    if rec:
        code, j = call("UpdateDomainRecord", ak_id, ak_secret,
                       RecordId=rec["RecordId"], RR=rr, Type="A", Value=ip, TTL=ttl)
        if code != 200:
            raise SystemExit("更新失败 %s: %s" % (code, json.dumps(j, ensure_ascii=False)[:300]))
        return "updated", rec["RecordId"], ip
    code, j = call("AddDomainRecord", ak_id, ak_secret,
                   DomainName=domain, RR=rr, Type="A", Value=ip, TTL=ttl)
    if code != 200:
        raise SystemExit("新增失败 %s: %s" % (code, json.dumps(j, ensure_ascii=False)[:300]))
    return "created", j.get("RecordId"), ip


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True, help="主域名，例如 example.com")
    ap.add_argument("--rr", default="steps", help="主机记录，例如 steps 或 @")
    ap.add_argument("--ip", help="目标 IPv4")
    ap.add_argument("--auto-ip", action="store_true", help="自动取当前公网出口 IP")
    ap.add_argument("--ttl", type=int, default=600)
    ap.add_argument("--check", action="store_true", help="只查询现有记录")
    ap.add_argument("--watch", type=int, default=0, help="每 N 秒检查一次并同步")
    ap.add_argument("--ak-id", default=os.environ.get("ALI_AK_ID", ""))
    ap.add_argument("--ak-secret", default=os.environ.get("ALI_AK_SECRET", ""))
    a = ap.parse_args()

    if not a.ak_id or not a.ak_secret:
        raise SystemExit("缺 AccessKey：设置 ALI_AK_ID / ALI_AK_SECRET 环境变量，或用 --ak-id --ak-secret")

    if a.check:
        rec = get_record(a.ak_id, a.ak_secret, a.domain, a.rr)
        if not rec:
            print("没有 A 记录：%s.%s" % (a.rr, a.domain))
        else:
            print("%s.%s → %s（TTL %s，RecordId %s）"
                  % (a.rr, a.domain, rec.get("Value"), rec.get("TTL"), rec.get("RecordId")))
        return

    if not a.ip and not a.auto_ip:
        raise SystemExit("给 --ip，或用 --auto-ip")

    while True:
        ip = public_ip() if a.auto_ip else a.ip
        try:
            state, rid, val = upsert(a.ak_id, a.ak_secret, a.domain, a.rr, ip, a.ttl)
            print("[%s] %s.%s → %s（%s）" % (time.strftime("%H:%M:%S"), a.rr, a.domain, val, state),
                  flush=True)
        except SystemExit as e:
            print("[%s] %s" % (time.strftime("%H:%M:%S"), e), flush=True)
        if not a.watch:
            break
        time.sleep(a.watch)


if __name__ == "__main__":
    main()
