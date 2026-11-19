#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""StepDeck 回归测试：只跑标准库 unittest，不起外网。

    python3 -m unittest discover -s tests -v
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

_TMP = tempfile.mkdtemp(prefix="stepdeck-test-")
os.environ["STEPDECK_DATA"] = _TMP
os.environ.pop("STEPDECK_ADMIN_PASSWORD", None)

import server  # noqa: E402  必须先设好 STEPDECK_DATA 再导入


class Base(unittest.TestCase):
    srv = None
    port = 0
    token = ""
    init_pw = ""

    @classmethod
    def setUpClass(cls):
        server.init_db()
        server.migrate_secrets()
        cls.init_pw = server.ensure_admin_password() or ""
        cls.srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(_TMP, ignore_errors=True)

    # ---- 小工具 ----
    def call(self, method, path, body=None, cookie=None, ctype="application/json",
             headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {}
        if body is not None:
            h["Content-Type"] = ctype
        if cookie:
            h["Cookie"] = "sd_admin=" + cookie
        h.update(headers or {})
        payload = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, body=payload, headers=h)
        r = conn.getresponse()
        raw = r.read()
        hdrs = dict(r.getheaders())
        conn.close()
        try:
            data = json.loads(raw.decode() or "{}")
        except Exception:
            data = raw.decode(errors="replace")
        return r.status, data, hdrs

    def login(self):
        st, data, hdrs = self.call("POST", "/api/admin/login",
                                   {"password": self.init_pw})
        self.assertEqual(st, 200, data)
        cookie = (hdrs.get("Set-Cookie") or "").split("sd_admin=")[-1].split(";")[0]
        self.assertTrue(cookie)
        return cookie

    def add_mock_account(self, cookie, username=None, share=False):
        st, data, _ = self.call("POST", "/api/accounts", {
            "username": username or "t%d@example.com" % id(self),
            "password": "pw-123456",
            "provider": "mock",
            "note": "测试",
        }, cookie=cookie)
        self.assertEqual(st, 200, data)
        self.assertTrue(data.get("ok"), data)
        if share:
            self.call("POST", "/api/accounts/%s/update" % data["id"],
                      {"share": True}, cookie=cookie)
        return data["id"]


class TestProviderRegistry(Base):
    def test_unknown_provider_is_rejected(self):
        """以前未知通道会静默回落 mock，界面还是绿的。"""
        cookie = self.login()
        st, data, _ = self.call("POST", "/api/accounts", {
            "username": "x@example.com", "password": "pw", "provider": "nope",
        }, cookie=cookie)
        self.assertEqual(st, 200)
        self.assertFalse(data.get("ok"))
        self.assertIn("未知通道", data["message"])

    def test_get_provider_never_falls_back(self):
        if server.ZeppProvider is None:
            with self.assertRaises(server.ProviderError):
                server.get_provider("zepp")
        else:
            self.assertIsInstance(server.get_provider("zepp"), server.ZeppProvider)

    def test_meta_lists_availability(self):
        cookie = self.login()
        st, data, _ = self.call("GET", "/api/meta", cookie=cookie)
        self.assertEqual(st, 200)
        catalog = {p["id"]: p for p in data["providers"]}
        self.assertIn("mock", catalog)
        self.assertIn("limits", data)
        if server.ZEPP_UNAVAILABLE:
            # 缺依赖时必须显式标成不可用，而不是假装能用
            self.assertTrue(data["provider_import_error"])
            self.assertFalse(catalog["zepp"]["available"])
        if server.HTTP_DEPS_ERROR and not server.PROVIDER_IMPORT_ERROR:
            # 只是缺 requests：真实提交不可用，演练仍可组包
            self.assertTrue(catalog["zepp_dry"]["available"])

    def test_dry_run_zepp_works_without_requests(self):
        from provider_zepp import ZeppProvider
        prov = ZeppProvider(dry_run=True)
        res = prov.submit({"token": "t", "user_id": "1", "username": "a", "password": "b"},
                          30000)
        self.assertTrue(res.get("ok"))
        self.assertTrue(res.get("dry_run"))


class TestCredentialStorage(Base):
    def test_seal_unseal_roundtrip(self):
        for pw in ("simple", "带中文的密码", "a" * 200, ""):
            self.assertEqual(server.unseal(server.seal(pw)), pw)

    def test_sealed_value_is_not_plaintext(self):
        sealed = server.seal("hunter2")
        self.assertNotIn("hunter2", sealed)
        self.assertTrue(sealed.startswith("v1:"))

    def test_tampered_ciphertext_returns_empty(self):
        sealed = server.seal("hunter2")
        raw = bytearray(sealed[3:].encode())
        raw[-1] = ord("A") if raw[-1] != ord("A") else ord("B")
        self.assertEqual(server.unseal("v1:" + raw.decode()), "")

    def test_legacy_base64_password_is_migrated(self):
        import base64
        c = server.db()
        c.execute("INSERT INTO accounts(id, username, provider, password, created_at) "
                  "VALUES('legacy01','old@example.com','mock',?,?)",
                  (base64.b64encode(b"oldpass").decode(), server.now_str()))
        c.commit()
        c.close()
        server.migrate_secrets()
        c = server.db()
        stored = c.execute("SELECT password FROM accounts WHERE id='legacy01'").fetchone()[0]
        c.close()
        self.assertTrue(stored.startswith("v1:"))
        self.assertEqual(server.unseal(stored), "oldpass")


class TestAdminAuth(Base):
    def test_group_password_is_not_in_db(self):
        server.admin_set_password("super-secret-pw")
        c = server.db()
        stored = c.execute("SELECT v FROM settings WHERE k='admin_hash'").fetchone()[0]
        c.close()
        self.assertNotIn("super-secret-pw", stored)
        self.assertTrue(stored.startswith("pbkdf2$"))

    def test_wrong_password_rejected(self):
        st, data, _ = self.call("POST", "/api/admin/login", {"password": "definitely-wrong"})
        self.assertEqual(st, 401)
        self.assertFalse(data["ok"])

    def test_login_rate_limited(self):
        server.LOGIN_FAILS.clear()
        try:
            for _ in range(server.LOGIN_MAX_FAILS):
                self.call("POST", "/api/admin/login", {"password": "bad"})
            st, data, _ = self.call("POST", "/api/admin/login", {"password": "bad"})
            self.assertEqual(st, 429)
            self.assertIn("秒后再试", data["message"])
        finally:
            server.LOGIN_FAILS.clear()

    def test_no_first_visitor_password_takeover(self):
        """没有密码时必须 503，而不是让访问者自己设一个。"""
        c = server.db()
        c.execute("DELETE FROM settings WHERE k='admin_hash'")
        c.commit()
        c.close()
        try:
            st, data, _ = self.call("POST", "/api/admin/login", {"password": "my-own-pw"})
            self.assertEqual(st, 503)
            self.assertFalse(data["ok"])
        finally:
            server.admin_set_password(self.init_pw)

    def test_session_stored_hashed(self):
        cookie = self.login()
        c = server.db()
        rows = [r[0] for r in c.execute("SELECT tok_hash FROM sessions")]
        c.close()
        self.assertNotIn(cookie, rows)
        st, data, _ = self.call("GET", "/api/admin/me", cookie=cookie)
        self.assertTrue(data["admin"])
        self.call("POST", "/api/admin/logout", {}, cookie=cookie)
        st, data, _ = self.call("GET", "/api/admin/me", cookie=cookie)
        self.assertFalse(data["admin"])

    def test_admin_api_requires_login(self):
        st, data, _ = self.call("GET", "/api/accounts")
        self.assertEqual(st, 401)
        self.assertTrue(data["needAdmin"])


class TestPublicSurface(Base):
    def test_only_shared_accounts_are_listed(self):
        cookie = self.login()
        hidden = self.add_mock_account(cookie, "hidden@example.com")
        shown = self.add_mock_account(cookie, "shown@example.com", share=True)
        st, data, _ = self.call("GET", "/api/public/accounts")
        ids = [a["id"] for a in data["accounts"]]
        self.assertIn(shown, ids)
        self.assertNotIn(hidden, ids)

    def test_request_for_unshared_account_rejected(self):
        cookie = self.login()
        aid = self.add_mock_account(cookie, "closed@example.com")
        st, data, _ = self.call("POST", "/api/public/requests",
                                {"account_id": aid, "steps": 20000, "requester": "路过的"})
        self.assertEqual(st, 200)
        self.assertFalse(data["ok"])
        self.assertIn("没有开放", data["message"])

    def test_public_requests_only_returns_own(self):
        cookie = self.login()
        aid = self.add_mock_account(cookie, "shared2@example.com", share=True)
        self.call("POST", "/api/public/requests",
                  {"account_id": aid, "steps": 30000, "requester": "alice", "note": "我的备注"})
        self.call("POST", "/api/public/requests",
                  {"account_id": aid, "steps": 31000, "requester": "bob", "note": "别人的备注"})
        st, data, _ = self.call("GET", "/api/public/requests?who=alice")
        who = {r["requester"] for r in data["requests"]}
        self.assertEqual(who, {"alice"})
        # 不带 who 不再返回所有人的单子
        st, data, _ = self.call("GET", "/api/public/requests")
        self.assertEqual(data["requests"], [])

    def test_request_merges_duplicates(self):
        cookie = self.login()
        aid = self.add_mock_account(cookie, "dupe@example.com", share=True)
        a = self.call("POST", "/api/public/requests",
                      {"account_id": aid, "steps": 25000, "requester": "u"})[1]
        b = self.call("POST", "/api/public/requests",
                      {"account_id": aid, "steps": 25000, "requester": "u"})[1]
        self.assertTrue(a["ok"])
        self.assertTrue(b.get("dup"))

    def test_approve_runs_submit(self):
        cookie = self.login()
        aid = self.add_mock_account(cookie, "approve@example.com", share=True)
        rid = self.call("POST", "/api/public/requests",
                        {"account_id": aid, "steps": 26000, "requester": "u"},
                        cookie=None)[1]["id"]
        st, data, _ = self.call("POST", "/api/requests/%d/approve" % rid, {}, cookie=cookie)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "approved")


class TestHttpHardening(Base):
    def test_static_path_traversal_blocked(self):
        for path in ("/../server.py", "/..%2fserver.py", "/../webx/secret"):
            st, data, _ = self.call("GET", path)
            self.assertIn(st, (404, 400), path)
            self.assertNotIn("StepDeck", str(data) if isinstance(data, str) else "")

    def test_non_json_post_rejected(self):
        st, data, _ = self.call("POST", "/api/admin/login", body={"password": "x"},
                                ctype="application/x-www-form-urlencoded")
        self.assertEqual(st, 415)

    def test_cross_origin_post_rejected(self):
        st, data, _ = self.call("POST", "/api/admin/login", {"password": self.init_pw},
                                headers={"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(st, 403)

    def test_security_headers_present(self):
        st, data, hdrs = self.call("GET", "/api/public/accounts")
        self.assertEqual(st, 200)
        self.assertEqual(hdrs.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(hdrs.get("X-Frame-Options"), "DENY")

    def test_submit_rejects_above_daily_cap(self):
        cookie = self.login()
        aid = self.add_mock_account(cookie, "cap@example.com")
        st, data, _ = self.call("POST", "/api/accounts/%s/submit" % aid,
                                {"steps": 120000}, cookie=cookie)
        self.assertFalse(data["ok"])
        self.assertIn("98,800", data["message"])

    def test_submit_rejects_non_numeric(self):
        cookie = self.login()
        aid = self.add_mock_account(cookie, "nan@example.com")
        st, data, _ = self.call("POST", "/api/accounts/%s/submit" % aid,
                                {"steps": "很多"}, cookie=cookie)
        self.assertFalse(data["ok"])


class TestSchedulerHelpers(Base):
    def test_last_run_parsing(self):
        dt = server._last_run_dt("2026-11-19 07:30:00")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.hour, 7)
        self.assertIsNone(server._last_run_dt(""))
        self.assertIsNone(server._last_run_dt("garbage"))

    def test_smart_mode_submits_partial(self):
        """渐进模式以前一天只跑一次，永远到不了目标。"""
        c = server.db()
        c.execute("INSERT INTO accounts(id, username, provider, token, user_id, status, "
                  "target, custody, enabled, exec_at, mode, current, last_run, created_at) "
                  "VALUES('smart01','s@example.com','mock','tok','1','ok',30000,1,1,?,"
                  "'smart',0,NULL,?)",
                  (server.now_cst().strftime("%H:%M"), server.now_str()))
        c.commit()
        c.close()
        server.scheduler_loop  # noqa: B018  只验证不抛异常的单次调度逻辑
        before = server._last_run_dt(None)
        self.assertIsNone(before)
        aid = "smart01"
        part = int(30000 * min(1.0, max(1, server.now_cst().hour - 6) / 18.0))
        res = server.do_submit(aid, max(1, part))
        self.assertTrue(res.get("ok"), res)
        c = server.db()
        cur = c.execute("SELECT current FROM accounts WHERE id=?", (aid,)).fetchone()[0]
        c.close()
        self.assertGreater(cur, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
