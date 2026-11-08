"""Tests for the web admin panel backend."""
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from werkzeug.security import generate_password_hash

from xraysubforge.config import ConfigStore
from xraysubforge.server import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "examples", "sample-panel.json"), encoding="utf-8") as f:
    PANEL = json.load(f)
PW = "correct horse"


def make(raw):
    path = os.path.join(tempfile.mkdtemp(), "config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(raw, f)
    return create_app(ConfigStore(path)), path


def login(client, pw=PW):
    r = client.post("/admin/api/login", json={"password": pw})
    return r, (r.get_json() or {}).get("csrf")


class Admin(unittest.TestCase):
    def setUp(self):
        self.hash = generate_password_hash(PW)
        self.raw = {"panel": {"url": "https://panel.example.com/json/"}, "admin": {"password_hash": self.hash},
                    "rules": [{"id": "r1", "when": {"remark": "x"}, "do": "drop"}]}
        self.app, self.path = make(self.raw)
        self.c = self.app.test_client()

    def post(self, path, data, csrf):
        return self.c.post("/admin/api/" + path, json=data, headers={"X-CSRF-Token": csrf})

    def test_disabled_without_password(self):
        app, _ = make({})
        c = app.test_client()
        for url in ("/admin", "/admin/admin.js", "/admin/api/me"):
            self.assertEqual(c.get(url).status_code, 404, url)
        self.assertEqual(c.post("/admin/api/login", json={"password": ""}).status_code, 404)

    def test_pages_and_headers(self):
        r = self.c.get("/admin")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'data-base="/admin"', r.data)
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertEqual(self.c.get("/admin/admin.js").status_code, 200)
        self.assertEqual(self.c.get("/admin/admin.css").status_code, 200)

    def test_login_required_and_wrong_password(self):
        self.assertEqual(self.c.get("/admin/api/state").status_code, 401)
        r, _ = login(self.c, "nope")
        self.assertEqual(r.status_code, 401)
        r, csrf = login(self.c)
        self.assertEqual(r.status_code, 200)
        self.assertIn("HttpOnly", r.headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", r.headers["Set-Cookie"])
        self.assertEqual(self.c.get("/admin/api/state").status_code, 200)

    def test_plain_password_also_works(self):
        app, _ = make({"admin": {"password": "pw1"}})
        r, csrf = login(app.test_client(), "pw1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(login(app.test_client(), "pw2")[0].status_code, 401)

    def test_lockout(self):
        app, _ = make({"admin": {"password_hash": self.hash, "max_failed_logins": 3, "lockout_seconds": 60}})
        c = app.test_client()
        codes = [login(c, "bad")[0].status_code for _ in range(4)]
        self.assertEqual(codes, [401, 401, 401, 429])
        self.assertEqual(login(c)[0].status_code, 429)                   # even the right password is refused while locked

    def test_csrf_required(self):
        _, csrf = login(self.c)
        r = self.c.post("/admin/api/save", json={"config": {}})
        self.assertEqual(r.status_code, 403)
        r = self.c.post("/admin/api/save", json={"config": {}}, headers={"X-CSRF-Token": "wrong"})
        self.assertEqual(r.status_code, 403)

    def test_state_hides_admin_section(self):
        login(self.c)
        d = self.c.get("/admin/api/state").get_json()
        self.assertNotIn("admin", d["config"])
        self.assertEqual(d["config"]["rules"][0]["id"], "r1")
        self.assertNotIn(self.hash, json.dumps(d))

    def test_save_validates_writes_and_keeps_admin(self):
        _, csrf = login(self.c)
        os.chmod(self.path, 0o640)
        bad = self.post("save", {"config": {"rules": [{"id": "x", "do": "explode"}]}}, csrf)
        self.assertEqual(bad.status_code, 400)
        self.assertTrue(bad.get_json()["errors"])
        with open(self.path) as f:
            self.assertEqual(json.load(f)["rules"][0]["id"], "r1")          # nothing written
        new = {"panel": {"url": "https://other.example.com/json/"}, "admin": {"password": "evil"},
               "groups": [{"id": "g", "type": "random", "when": {"remark": {"startswith": "fast-"}}}]}
        ok = self.post("save", {"config": new}, csrf)
        self.assertEqual(ok.status_code, 200, ok.data)
        with open(self.path) as f:
            saved = json.load(f)
        self.assertEqual(saved["admin"], {"password_hash": self.hash})      # submitted admin ignored, existing kept
        self.assertEqual(saved["groups"][0]["id"], "g")
        self.assertNotIn("rules", saved)
        self.assertEqual(self.app.store.get()["panel"]["url"], "https://other.example.com/json/")   # live immediately
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o640)         # file permissions are kept

    def test_preview_runs_candidate_config(self):
        _, csrf = login(self.c)
        cand = {"rules": [{"id": "d", "when": {"remark": {"startswith": "test"}}, "do": "drop"}]}
        r = self.post("preview", {"config": cand, "configs": PANEL}, csrf).get_json()
        self.assertEqual(r["errors"], [])
        self.assertNotIn("test-node", [c["remarks"] for c in r["output"]])
        self.assertEqual([c["action"] for c in r["report"]["configs"]].count("drop"), 1)
        r = self.post("preview", {"config": {"rules": [{"do": "nope"}]}, "configs": PANEL}, csrf).get_json()
        self.assertTrue(r["errors"])
        self.assertEqual(len(r["output"]), len(PANEL))                      # broken rule skipped, rest still shown

    def test_facts_counts_and_values(self):
        _, csrf = login(self.c)
        whens = [{"remark": {"regex": "(berlin|tokyo)-[0-9]$"}},        # 5 of the 8 sample configs
                 {"protocol": "vless", "network": "tcp"},                 # 1
                 {},                                                      # empty condition = every config
                 {"remark": {"regex": "("}},                              # broken regex: no number
                 {"remark": {"nope": 1}},                                 # unknown operator: no number
                 "not an object"]
        r = self.post("facts", {"configs": PANEL, "whens": whens}, csrf).get_json()
        self.assertEqual(r["total"], len(PANEL))
        self.assertEqual(r["counts"], [5, 1, len(PANEL), None, None, None])
        values = {k: dict(v) for k, v in r["values"].items()}
        self.assertEqual(values["protocol"], {"vless": 7, "socks": 1})
        self.assertEqual(values["network"], {"xhttp": 6, "tcp": 2})
        self.assertNotIn("remark", values)                                # names are not offered as suggestions
        self.assertEqual(self.post("facts", {}, csrf).get_json(), {"total": 0, "counts": [], "values": {
            k: [] for k in r["values"]}})
        self.assertEqual(self.c.post("/admin/api/facts", json={}).status_code, 403)       # CSRF token required

    def test_sample_fetch(self):
        _, csrf = login(self.c)

        class Resp:
            status_code, headers = 200, {}
            def json(self): return PANEL
        with mock.patch("xraysubforge.panel.requests.get", return_value=Resp()) as get:
            r = self.post("sample", {"subid": "abcd1234"}, csrf)
        self.assertEqual(len(r.get_json()["configs"]), len(PANEL))
        self.assertEqual(get.call_args[0][0], "https://panel.example.com/json/abcd1234")
        self.assertEqual(self.post("sample", {"subid": "x"}, csrf).status_code, 400)
        self.assertEqual(self.post("sample", {"subid": ""}, csrf).status_code, 400)

    def test_password_change_invalidates_sessions(self):
        login(self.c)
        self.assertEqual(self.c.get("/admin/api/me").status_code, 200)
        with open(self.path, "w") as f:
            json.dump({"admin": {"password_hash": generate_password_hash("new")}}, f)
            f.flush()
        st = os.stat(self.path)
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns + 5 * 10 ** 9))
        self.assertEqual(self.c.get("/admin/api/me").status_code, 401)

    def test_logout(self):
        _, csrf = login(self.c)
        self.post("logout", {}, csrf)
        self.assertEqual(self.c.get("/admin/api/me").status_code, 401)

    def test_custom_admin_path(self):
        app, _ = make({"admin": {"password": "pw1", "path": "/manage"}})
        c = app.test_client()
        self.assertEqual(c.get("/manage").status_code, 200)
        self.assertEqual(c.get("/admin").status_code, 404)
        self.assertEqual(c.post("/manage/api/login", json={"password": "pw1"}).status_code, 200)


if __name__ == "__main__":
    unittest.main()


class Checks(unittest.TestCase):
    def setUp(self):
        self.app, self.path = make({"admin": {"password_hash": generate_password_hash(PW)}})
        self.c = self.app.test_client()
        _, self.csrf = login(self.c)

    def run_checks(self, cfg, subid=None):
        r = self.c.post("/admin/api/checks", json={"config": cfg, "subid": subid}, headers={"X-CSRF-Token": self.csrf})
        self.assertEqual(r.status_code, 200)
        return {c["id"]: c for c in r.get_json()["checks"]}

    def test_needs_login(self):
        self.assertEqual(self.app.test_client().post("/admin/api/checks", json={}).status_code, 401)

    def test_no_panel_url(self):
        c = self.run_checks({})
        self.assertEqual(c["panel_url"]["status"], "fail")
        self.assertNotIn("panel_reach", c)
        self.assertEqual(c["https"]["status"], "warn")
        self.assertEqual(c["config"]["status"], "ok")

    def test_unreachable_panel(self):
        c = self.run_checks({"panel": {"url": "http://127.0.0.1:1/json/"}})
        self.assertEqual(c["panel_reach"]["status"], "fail")
        self.assertEqual(c["panel_reach"]["args"]["kind"], "connect")

    def test_reachable_panel_and_sample(self):
        resp = mock.Mock(status_code=404)
        with mock.patch("requests.get", return_value=resp), \
                mock.patch("xraysubforge.admin.fetch_panel", return_value=(None, [{}, {}, {}], None)):
            c = self.run_checks({"panel": {"url": "http://panel.invalid/json/"}}, subid="abcdef12")
        self.assertEqual(c["panel_reach"]["status"], "ok")
        self.assertEqual(c["sample"]["args"]["n"], 3)

    def test_bad_config_and_chain_without_accounts(self):
        cfg = {"rules": [{"id": "x", "do": "nope"}],
               "chains": [{"id": "w", "entry": {"protocol": "masque", "k": "{account.privateKey}"}}]}
        c = self.run_checks(cfg)
        self.assertEqual(c["config"]["status"], "fail")
        self.assertEqual(c["accounts"]["status"], "fail")
        cfg["accounts"] = {"file": "accounts.json", "register": {"enabled": True}}
        c = self.run_checks(cfg)
        self.assertEqual(c["accounts"]["status"], "ok")

    def test_secure_request_counts_as_https(self):
        r = self.c.post("/admin/api/checks", json={"config": {}}, headers={"X-CSRF-Token": self.csrf, "X-Forwarded-Proto": "https"})
        self.assertEqual({c["id"]: c for c in r.get_json()["checks"]}["https"]["status"], "ok")


class Restart(unittest.TestCase):
    def setUp(self):
        self.app, _ = make({"admin": {"password_hash": generate_password_hash(PW)}})
        self.c = self.app.test_client()
        _, self.csrf = login(self.c)

    def post(self):
        return self.c.post("/admin/api/restart", json={}, headers={"X-CSRF-Token": self.csrf})

    def test_refused_outside_systemd(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INVOCATION_ID", None)
            self.assertEqual(self.post().status_code, 400)
            self.assertFalse(self.c.get("/admin/api/state").get_json()["can_restart"])

    def policy(self, value):
        done = mock.Mock(stdout=value + "\n")
        return mock.patch("subprocess.run", return_value=done)

    def test_refused_when_systemd_would_not_start_it_again(self):
        with mock.patch.dict(os.environ, {"INVOCATION_ID": "x"}), mock.patch("os.getppid", return_value=4242), \
                mock.patch("xraysubforge.admin._unit_name", return_value="subforge.service"), self.policy("no"), \
                mock.patch("os.kill") as kill:
            self.assertFalse(self.c.get("/admin/api/state").get_json()["can_restart"])
            self.assertEqual(self.post().status_code, 400)
            kill.assert_not_called()

    def test_signals_the_master_under_systemd(self):
        with mock.patch.dict(os.environ, {"INVOCATION_ID": "x"}), mock.patch("os.getppid", return_value=4242), \
                mock.patch("xraysubforge.admin._unit_name", return_value="subforge.service"), self.policy("always"), \
                mock.patch("xraysubforge.admin.time.sleep"), mock.patch("os.kill") as kill:
            self.assertTrue(self.c.get("/admin/api/state").get_json()["can_restart"])
            r = self.post()
            self.assertEqual(r.status_code, 200)
            import time as _t
            for _ in range(50):
                if kill.called:
                    break
                _t.sleep(0.02)
        import signal
        kill.assert_called_once_with(4242, signal.SIGTERM)

    def test_needs_login_and_csrf(self):
        self.assertEqual(self.app.test_client().post("/admin/api/restart", json={}).status_code, 401)
        self.assertEqual(self.c.post("/admin/api/restart", json={}).status_code, 403)
