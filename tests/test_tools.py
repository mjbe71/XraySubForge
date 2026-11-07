"""Tests for the command-line helpers the installer uses, 3x-ui detection and the TLS settings."""
import contextlib
import importlib.util
import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest import mock

from xraysubforge import xui
from xraysubforge.__main__ import main
from xraysubforge.config import ConfigStore, normalize
from xraysubforge.server import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch("sys.stdin", io.StringIO(stdin or "")):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class ConfigCommands(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "config.json")

    def read(self):
        with open(self.path) as f:
            return json.load(f)

    def test_config_set_get_unset(self):
        code, _, _ = run("config-set", "--config", self.path, "server.port=8443", "server.host=0.0.0.0",
                         "panel.verify_tls=false", "panel.url=https://p.example.com:2096/json/", "accounts.file=a.json")
        self.assertEqual(code, 0)
        raw = self.read()
        self.assertEqual((raw["server"]["port"], raw["server"]["host"], raw["panel"]["verify_tls"]), (8443, "0.0.0.0", False))
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")           # new file: private
        self.assertEqual(run("config-get", "server.port", "--config", self.path)[1].strip(), "8443")
        self.assertEqual(run("config-get", "panel.url", "--config", self.path)[1].strip(), "https://p.example.com:2096/json/")
        self.assertEqual(run("config-get", "server.route", "--config", self.path)[1].strip(), "/sub/")   # default
        self.assertEqual(run("config-get", "nope.nothing", "--config", self.path)[0], 1)
        run("config-set", "--config", self.path, "--unset", "server.host")
        self.assertNotIn("host", self.read()["server"])

    def test_config_set_refuses_to_overwrite_broken_file(self):
        with open(self.path, "w") as f:
            f.write("{ not json")
        code, _, err = run("config-set", "--config", self.path, "server.port=1")
        self.assertEqual(code, 1)
        with open(self.path) as f:
            self.assertEqual(f.read(), "{ not json")
        self.assertEqual(run("config-set", "--config", self.path, "oops")[0], 1)

    def test_set_admin_password_then_login(self):
        run("config-set", "--config", self.path, "panel.url=https://p.example.com/json/", "admin.password=old")
        code, out, _ = run("set-admin-password", "--config", self.path, "--stdin", stdin="a-good-password\n")
        self.assertEqual(code, 0)
        raw = self.read()
        self.assertNotIn("password", raw["admin"])
        self.assertTrue(raw["admin"]["password_hash"])
        self.assertEqual(raw["panel"]["url"], "https://p.example.com/json/")             # rest untouched
        c = create_app(ConfigStore(self.path)).test_client()
        self.assertEqual(c.post("/admin/api/login", json={"password": "a-good-password"}).status_code, 200)
        self.assertEqual(c.post("/admin/api/login", json={"password": "old"}).status_code, 401)

    def test_set_admin_password_rejects_short(self):
        code, _, err = run("set-admin-password", "--config", self.path, "--stdin", stdin="short\n")
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.path))

    def test_env_var_is_the_default_config_path(self):
        with mock.patch.dict(os.environ, {"XRAYSUBFORGE_CONFIG": self.path}):
            run("config-set", "server.port=9999")
        self.assertEqual(self.read()["server"]["port"], 9999)


class Tls(unittest.TestCase):
    def test_both_or_neither(self):
        conf, problems = normalize({"server": {"tls_cert": "/a.pem"}})
        self.assertEqual((conf["server"]["tls_cert"], conf["server"]["tls_key"]), ("", ""))
        self.assertTrue(any("both or neither" in p for p in problems))
        conf, problems = normalize({"server": {"tls_cert": "/a.pem", "tls_key": "/b.pem"}})
        self.assertEqual((conf["server"]["tls_cert"], problems), ("/a.pem", []))

    def test_gunicorn_conf_uses_certificates(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "config.json")
        with open(path, "w") as f:
            json.dump({"server": {"host": "0.0.0.0", "port": 8443, "tls_cert": "/c.pem", "tls_key": "/k.pem"}}, f)
        with mock.patch.dict(os.environ, {"XRAYSUBFORGE_CONFIG": path}):
            spec = importlib.util.spec_from_file_location("gconf", os.path.join(ROOT, "gunicorn.conf.py"))
            mod = importlib.util.module_from_spec(spec)
            sys.path.insert(0, ROOT)
            spec.loader.exec_module(mod)
        self.assertEqual((mod.bind, mod.certfile, mod.keyfile), ("0.0.0.0:8443", "/c.pem", "/k.pem"))


class Xui(unittest.TestCase):
    def make_db(self, rows, table="settings"):
        d = tempfile.mkdtemp()
        db = os.path.join(d, "x-ui.db")
        con = sqlite3.connect(db)
        con.execute("create table %s (id integer primary key, key text, value text)" % table)
        con.executemany("insert into %s (key, value) values (?, ?)" % table, rows)
        con.commit()
        con.close()
        return d, db

    def test_detect_certs_and_suggestion(self):
        d, db = self.make_db([("webCertFile", os.path.join(os.getcwd(), "x")), ("subPort", "2096"), ("subJsonPath", "json"),
                              ("subDomain", "sub.example.com"), ("webPort", "54321")])
        cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        for p in (cert, key):
            open(p, "w").close()
        con = sqlite3.connect(db)
        con.executemany("insert into settings (key, value) values (?, ?)",
                        [("subCertFile", cert), ("subKeyFile", key), ("webKeyFile", "")])
        con.commit()
        con.close()
        r = xui.detect(db)
        self.assertTrue(r["found"])
        self.assertEqual(r["sub"]["port"], "2096")
        self.assertEqual([c["cert"] for c in r["certs"]], [cert])                      # only pairs whose files exist
        self.assertEqual(r["suggest"], {"url": "https://sub.example.com:2096/json/", "verify_tls": True})

    def test_suggestions_without_tls_or_domain(self):
        _, db = self.make_db([("subPort", "2096"), ("subJsonPath", "/json/")])
        self.assertEqual(xui.detect(db)["suggest"], {"url": "http://127.0.0.1:2096/json/", "verify_tls": True})

    def test_other_table_name_and_case(self):
        _, db = self.make_db([("SUBPORT", "1"), ("subjsonpath", "/j/")], table="whatever")
        self.assertEqual(xui.detect(db)["suggest"]["url"], "http://127.0.0.1:1/j/")

    def test_missing_or_broken_database(self):
        with mock.patch.object(xui, "DB_CANDIDATES", ()), mock.patch.object(xui, "ACME_GLOB", "/nonexistent/*/fullchain.pem"):
            r = xui.detect(None)
        self.assertEqual((r["found"], r["certs"], r["suggest"]), (False, [], None))
        d = tempfile.mkdtemp()
        bad = os.path.join(d, "x-ui.db")
        with open(bad, "w") as f:
            f.write("this is not sqlite")
        self.assertFalse(xui.detect(bad)["found"])

    def test_cli_outputs(self):
        _, db = self.make_db([("subPort", "2096"), ("subJsonPath", "/json/")])
        code, out, _ = run("detect-xui", "--db", db, "--suggest")
        self.assertEqual(out.strip(), "http://127.0.0.1:2096/json/\ttrue")
        self.assertTrue(json.loads(run("detect-xui", "--db", db)[1])["found"])

    def test_acme_dir_certs(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "sub.example.com"))
        for n in ("fullchain.pem", "privkey.pem"):
            open(os.path.join(d, "sub.example.com", n), "w").close()
        with mock.patch.object(xui, "DB_CANDIDATES", ()), mock.patch.object(xui, "ACME_GLOB", os.path.join(d, "*", "fullchain.pem")):
            r = xui.detect(None)
        self.assertEqual(len(r["certs"]), 1)
        self.assertIn("sub.example.com", r["certs"][0]["label"])


if __name__ == "__main__":
    unittest.main()


class ScanCerts(unittest.TestCase):
    """Finding an existing certificate for a domain, wherever 3x-ui / acme.sh / certbot left it."""

    def make(self, d, cn, san, keyname="privkey.pem", certname="fullchain.pem"):
        import subprocess
        os.makedirs(d, exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(d, keyname),
                        "-out", os.path.join(d, certname), "-days", "30", "-subj", "/CN=" + cn,
                        "-addext", "subjectAltName=" + san, "-addext", "basicConstraints=CA:FALSE"], check=True, capture_output=True)
        return os.path.join(d, certname), os.path.join(d, keyname)

    def test_scan(self):
        from xraysubforge import xui
        with tempfile.TemporaryDirectory() as t:
            ac = self.make(os.path.join(t, "acme", "sub.example.com_ecc"), "sub.example.com", "DNS:sub.example.com",
                           keyname="sub.example.com.key", certname="fullchain.cer")
            other = self.make(os.path.join(t, "cert", "other.org"), "other.org", "DNS:other.org")
            wild = self.make(os.path.join(t, "le", "example.net"), "example.net", "DNS:example.net,DNS:*.example.net")
            found = xui.scan_certs("sub.example.com", dirs=[os.path.join(t, "acme"), os.path.join(t, "cert"), os.path.join(t, "le")])
            self.assertEqual(len(found), 3)
            self.assertEqual(found[0]["cert"], ac[0])                 # the matching one is listed first
            self.assertTrue(found[0]["covers"] and found[0]["key"] == ac[1])
            self.assertEqual([c["covers"] for c in found], [True, False, False])
            by = {c["cert"]: c for c in found}
            self.assertFalse(by[other[0]]["covers"])
            self.assertTrue(xui.scan_certs("a.example.net", dirs=[os.path.join(t, "le")])[0]["covers"])   # wildcard
            self.assertFalse(xui.scan_certs("a.b.example.net", dirs=[os.path.join(t, "le")])[0]["covers"])

    def test_scan_cli_and_missing_key(self):
        import io
        from contextlib import redirect_stdout
        from xraysubforge import xui
        with tempfile.TemporaryDirectory() as t:
            c, k = self.make(os.path.join(t, "x"), "a.example.com", "DNS:a.example.com")
            os.unlink(k)
            with mock.patch.dict(os.environ, {"XSF_CERT_DIRS": t, "XUI_DB_FOLDER": t}):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    xui.main(["--scan", "a.example.com"])
            cols = buf.getvalue().strip().split("\t")
            self.assertEqual(cols[0], c)
            self.assertEqual(cols[1], "")                                # no key found
            self.assertEqual(cols[2], "yes")
