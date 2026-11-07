"""Automatic account registration: the WARP API client against a fake local API, the store, the server, CLI, admin."""
import base64
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from xraysubforge import warp
from xraysubforge.accounts import AccountStore
from xraysubforge.config import ConfigStore, normalize
from xraysubforge.__main__ import main as cli
from xraysubforge.server import create_app

SPKI = base64.b64encode(b"\x30" * 91).decode()          # not 32 bytes: looks like a P-256 key


class FakeCloudflare(BaseHTTPRequestHandler):
    calls = []
    fail_at = None

    def log_message(self, *a):
        pass

    def _reply(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        FakeCloudflare.calls.append((self.command, self.path, body, self.headers.get("Authorization")))
        if FakeCloudflare.fail_at == len(FakeCloudflare.calls):
            return self._reply(500, {})
        if self.command == "POST":
            return self._reply(200, {"id": "dev-1", "token": "tok-secret"})
        if body.get("tunnel_type") == "masque":
            return self._reply(200, {"config": {"interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606::2"}},
                                                "peers": [{"public_key": SPKI}]}})
        self._reply(200, {})

    do_POST = do_PATCH = _handle


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), FakeCloudflare)
        cls.api = "http://127.0.0.1:%d" % cls.httpd.server_port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        FakeCloudflare.calls, FakeCloudflare.fail_at = [], None
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.cfg_path = os.path.join(self.dir.name, "config.json")

    def write_config(self, **register):
        reg = dict({"enabled": True, "api": self.api, "retry_seconds": 600}, **register)
        with open(self.cfg_path, "w") as f:
            json.dump({"accounts": {"file": "accounts.json", "register": reg},
                       "chains": [{"id": "w", "entry": {"protocol": "x"}}]}, f)
        return ConfigStore(self.cfg_path)

    def users(self):
        with open(os.path.join(self.dir.name, "accounts.json")) as f:
            return json.load(f)


class WarpClient(Base):
    def test_three_calls_and_result(self):
        entry = warp.register_account(api=self.api)
        self.assertEqual([c[:2] for c in FakeCloudflare.calls],
                         [("POST", "/reg"), ("PATCH", "/reg/dev-1"), ("PATCH", "/reg/dev-1"), ][:3])
        self.assertEqual(FakeCloudflare.calls[1][2]["tunnel_type"], "masque")
        self.assertEqual(FakeCloudflare.calls[1][3], "Bearer tok-secret")
        self.assertTrue(FakeCloudflare.calls[2][2]["warp_enabled"])
        self.assertEqual(entry["id"], "dev-1")
        self.assertEqual(entry["address"], ["172.16.0.2", "2606::2"])
        self.assertEqual(entry["publicKey"], SPKI)
        self.assertNotIn("tok-secret", json.dumps(entry))
        base64.b64decode(entry["privateKey"])

    def test_failure_is_apierror_without_secrets(self):
        FakeCloudflare.fail_at = 2
        with self.assertRaises(warp.ApiError) as cm:
            warp.register_account(api=self.api)
        self.assertIn("HTTP 500", str(cm.exception))
        self.assertNotIn("tok-secret", str(cm.exception))

    def test_unreachable_api(self):
        with self.assertRaises(warp.ApiError):
            warp.register_account(api="http://127.0.0.1:1")


class Store(Base):
    def test_ensure_creates_once_per_user(self):
        store = AccountStore(self.write_config())
        store.ensure("alice")
        store.ensure("alice")
        store.ensure("bob")
        self.assertEqual(sorted(self.users()["users"]), ["alice", "bob"])
        self.assertEqual(len([c for c in FakeCloudflare.calls if c[0] == "POST"]), 2)
        self.assertEqual(oct(os.stat(os.path.join(self.dir.name, "accounts.json")).st_mode & 0o777), "0o600")

    def test_keeps_existing_flat_file_as_shared_account(self):
        with open(os.path.join(self.dir.name, "accounts.json"), "w") as f:
            json.dump({"privateKey": "SHARED", "address": ["1.1.1.1"]}, f)
        store = AccountStore(self.write_config())
        store.ensure("alice")
        data = self.users()
        self.assertEqual(data["default"]["privateKey"], "SHARED")
        self.assertIn("alice", data["users"])
        self.assertEqual(store.get()["users"]["alice"]["id"], "dev-1")

    def test_failure_backs_off_and_never_raises(self):
        fake = mock.Mock(side_effect=warp.ApiError("boom"))
        store = AccountStore(self.write_config(), registrar=fake)
        store.ensure("alice")
        store.ensure("alice")
        self.assertEqual(fake.call_count, 1)            # second call: inside retry_seconds
        store2 = AccountStore(self.write_config(retry_seconds=0), registrar=fake)
        store2.ensure("alice")
        store2.ensure("alice")
        self.assertEqual(fake.call_count, 3)

    def test_disabled_does_nothing(self):
        store = AccountStore(self.write_config(enabled=False))
        store.ensure("alice")
        self.assertEqual(FakeCloudflare.calls, [])

    def test_register_without_file_errors(self):
        with open(self.cfg_path, "w") as f:
            json.dump({}, f)
        with self.assertRaises(ValueError):
            AccountStore(ConfigStore(self.cfg_path)).register("alice")


class Config(unittest.TestCase):
    def test_enabled_needs_file(self):
        conf, problems = normalize({"accounts": {"register": {"enabled": True}}})
        self.assertFalse(conf["accounts"]["register"]["enabled"])
        self.assertTrue(any("needs accounts.file" in p for p in problems))

    def test_bad_values_and_defaults(self):
        conf, problems = normalize({"accounts": {"file": "a.json", "register": {"enabled": True, "retry_seconds": "x", "zzz": 1}}})
        self.assertTrue(conf["accounts"]["register"]["enabled"])
        self.assertEqual(conf["accounts"]["register"]["retry_seconds"], 600)
        self.assertEqual(len(problems), 2)


class EndToEnd(Base):
    def test_server_registers_on_first_request_then_chain_uses_it(self):
        with open(self.cfg_path, "w") as f:
            json.dump({"panel": {"url": "http://panel.invalid/json/"},
                       "accounts": {"file": "accounts.json", "register": {"enabled": True, "api": self.api}},
                       "chains": [{"id": "w", "exit_when": {"remark": {"contains": ""}},
                                   "entry": {"protocol": "masque", "settings": {"address": "g", "port": 443},
                                             "streamSettings": {"k": "{account.privateKey}"}}}]}, f)
        app = create_app(ConfigStore(self.cfg_path))
        panel = [{"remarks": "x", "outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {}}], "routing": {"rules": []}}]

        class R:
            headers = {}
        with mock.patch("xraysubforge.server.fetch_panel", return_value=(R(), panel, panel)):
            resp = app.test_client().get("/sub/abcdef12")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("abcdef12", self.users()["users"])
        self.assertIn(self.users()["users"]["abcdef12"]["privateKey"], resp.get_data(as_text=True))

    def test_cli_register_and_admin_button(self):
        self.write_config()
        self.assertEqual(cli(["register-account", "--subid", "carol", "--config", self.cfg_path]), 0)
        self.assertIn("carol", self.users()["users"])
        self.assertEqual(cli(["register-account", "--subid", "carol", "--config", self.cfg_path]), 0)
        self.assertEqual(len([c for c in FakeCloudflare.calls if c[0] == "POST"]), 1)   # the second did not ask the API
        self.assertEqual(cli(["register-account", "--config", self.cfg_path]), 0)
        self.assertIn("privateKey", self.users()["default"])
        with open(self.cfg_path) as f:
            raw = json.load(f)
        raw["admin"] = {"password": "longenough1"}
        with open(self.cfg_path, "w") as f:
            json.dump(raw, f)
        c = create_app(ConfigStore(self.cfg_path)).test_client()
        csrf = c.post("/admin/api/login", json={"password": "longenough1"}).get_json()["csrf"]
        r = c.post("/admin/api/register-account", json={"subid": "dave"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["created"])
        self.assertIn("dave", self.users()["users"])
        r = c.post("/admin/api/register-account", json={"subid": "dave"}, headers={"X-CSRF-Token": csrf})
        self.assertFalse(r.get_json()["created"])
        self.assertEqual(c.post("/admin/api/register-account", json={"subid": "x"}).status_code, 403)


class Limits(Base):
    def test_max_users_and_interval(self):
        store = AccountStore(self.write_config(max_users=1))
        store.ensure("alice")
        store.ensure("bob")
        self.assertEqual(sorted(self.users()["users"]), ["alice"])        # the cap stopped bob
        store = AccountStore(self.write_config(min_interval_seconds=3600))
        store.ensure("carol")
        store.ensure("dave")                                                # too soon: skipped, not queued
        self.assertEqual(sorted(self.users()["users"]), ["alice", "carol"])

    def test_background_never_blocks_and_registers_all(self):
        import time
        store = AccountStore(self.write_config(background=True))
        for name in ("a1", "a2", "a3"):
            store.ensure(name)
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                if len(self.users().get("users", {})) >= 3:
                    break
            except (OSError, ValueError):
                pass                                    # the worker has not written the file yet
            time.sleep(0.05)
        self.assertEqual(sorted(self.users()["users"]), ["a1", "a2", "a3"])

    def test_validation(self):
        conf, problems = normalize({"accounts": {"file": "a.json", "register": {"enabled": True, "background": "x", "max_users": -1}}})
        self.assertEqual(len(problems), 2)
        self.assertEqual((conf["accounts"]["register"]["background"], conf["accounts"]["register"]["max_users"]), (False, 0))


class OnlyWhenNeeded(Base):
    def test_no_account_for_a_user_without_a_matching_config(self):
        with open(self.cfg_path, "w") as f:
            json.dump({"panel": {"url": "http://panel.invalid/json/"},
                       "accounts": {"file": "accounts.json", "register": {"enabled": True, "api": self.api}},
                       "chains": [{"id": "w", "exit_when": {"protocol": "masque"}, "entry": {"protocol": "x"}}]}, f)
        app = create_app(ConfigStore(self.cfg_path))

        class R:
            headers = {}
        plain = [{"remarks": "x", "outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {}}], "routing": {"rules": []}}]
        dummy = [{"remarks": "d", "outbounds": [{"protocol": "masque", "tag": "proxy", "settings": {}}]}]
        with mock.patch("xraysubforge.server.fetch_panel", return_value=(R(), plain, plain)):
            app.test_client().get("/sub/plainuser")
        with mock.patch("xraysubforge.server.fetch_panel", return_value=(R(), dummy, dummy)):
            app.test_client().get("/sub/dummyuser")
        self.assertEqual(sorted(self.users()["users"]), ["dummyuser"])


if __name__ == "__main__":
    unittest.main()


class Pool(Base):
    def test_register_into_the_pool_keeps_the_rest(self):
        store = AccountStore(self.write_config())
        store.ensure("alice")
        store.register(pool=True)
        store.register(pool=True)
        data = self.users()
        self.assertEqual(len(data["default"]["pool"]), 2)
        self.assertEqual(sorted(data["users"]), ["alice"])
        self.assertEqual(len(store.get()["default"]["pool"]), 2)
