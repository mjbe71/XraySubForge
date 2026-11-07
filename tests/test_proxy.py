"""Proxy mode and the raw / clash pass-through routes."""
import json
import os
import tempfile
import unittest
from unittest import mock

import requests

from xraysubforge.config import ConfigStore, normalize
from xraysubforge.server import create_app

JSON_BODY = b'[ {"remarks":"a",  "outbounds":[]} ]'          # deliberately not in json.dumps' own formatting
RAW_BODY = b"dmxlc3M6Ly9leGFtcGxl"
CLASH_BODY = b"proxies:\n  - name: a\n"


class Resp:
    def __init__(self, body, ctype, status=200, headers=None):
        self.content, self.status_code = body, status
        self.headers = dict({"Content-Type": ctype}, **(headers or {}))

    def json(self):
        return json.loads(self.content)


def panel_get(url, **kw):
    if url.startswith("https://p.example/json/"):
        return Resp(JSON_BODY, "application/json; charset=utf-8", headers={"Subscription-Userinfo": "upload=1; total=2"})
    if url.startswith("https://p.example/sub/"):
        return Resp(RAW_BODY, "text/plain; charset=utf-8")
    if url.startswith("https://p.example/clash/"):
        return Resp(CLASH_BODY, "text/yaml; charset=utf-8", headers={"Content-Disposition": "attachment"})
    return Resp(b"", "text/plain", status=404)


def make(panel, server=None):
    path = os.path.join(tempfile.mkdtemp(), "config.json")
    raw = {"panel": dict({"url": "https://p.example/json/"}, **panel)}
    if server:
        raw["server"] = server
    with open(path, "w", encoding="utf-8") as f:
        json.dump(raw, f)
    return create_app(ConfigStore(path)).test_client()


class Proxy(unittest.TestCase):
    def get(self, client, url, **kw):
        with mock.patch("xraysubforge.panel.requests.get", side_effect=panel_get):
            return client.get(url, **kw)

    def test_proxy_mode_returns_the_panel_reply_untouched(self):
        c = make({"mode": "proxy"})
        r = self.get(c, "/sub/abcd1234")
        self.assertEqual(r.data, JSON_BODY)
        self.assertEqual(r.headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(r.headers["Subscription-Userinfo"], "upload=1; total=2")

    def test_engine_mode_still_rewrites_json(self):
        r = self.get(make({}), "/sub/abcd1234")
        self.assertNotEqual(r.data, JSON_BODY)
        self.assertEqual(json.loads(r.data), json.loads(JSON_BODY))

    def test_proxy_mode_without_a_json_url_only_turns_that_format_off(self):
        c = make({"mode": "proxy", "url": "", "raw_url": "https://p.example/sub/"})
        self.assertEqual(self.get(c, "/sub/abcd1234").status_code, 404)
        self.assertEqual(self.get(c, "/raw/abcd1234").data, RAW_BODY)

    def test_proxy_mode_does_not_parse_the_reply(self):
        with mock.patch("xraysubforge.panel.requests.get", return_value=Resp(b"not json", "text/plain")):
            r = make({"mode": "proxy"}).get("/sub/abcd1234")
        self.assertEqual((r.status_code, r.data), (200, b"not json"))

    def test_raw_and_clash_routes(self):
        c = make({"raw_url": "https://p.example/sub/", "clash_url": "https://p.example/clash/"})
        raw = self.get(c, "/raw/abcd1234")
        self.assertEqual((raw.data, raw.headers["Content-Type"]), (RAW_BODY, "text/plain; charset=utf-8"))
        clash = self.get(c, "/clash/abcd1234")
        self.assertEqual((clash.data, clash.headers["Content-Type"]), (CLASH_BODY, "text/yaml; charset=utf-8"))
        self.assertEqual(clash.headers["Content-Disposition"], "attachment")

    def test_formats_without_a_panel_url_are_404(self):
        c = make({})
        self.assertEqual(self.get(c, "/raw/abcd1234").status_code, 404)
        self.assertEqual(self.get(c, "/clash/abcd1234").status_code, 404)

    def test_bad_id_never_reaches_the_panel(self):
        c = make({"raw_url": "https://p.example/sub/"})
        with mock.patch("xraysubforge.panel.requests.get") as g:
            self.assertEqual(c.get("/raw/a").status_code, 404)
            g.assert_not_called()

    def test_panel_errors(self):
        c = make({"raw_url": "https://p.example/missing/", "mode": "proxy"})
        self.assertEqual(self.get(c, "/raw/abcd1234").status_code, 404)
        with mock.patch("xraysubforge.panel.requests.get", side_effect=requests.ConnectionError("x")):
            self.assertEqual(c.get("/raw/abcd1234").status_code, 502)
            self.assertEqual(c.get("/sub/abcd1234").status_code, 502)

    def test_browsers_are_redirected_on_every_format(self):
        c = make({"raw_url": "https://p.example/sub/", "page_url": "https://p.example/page"})
        r = c.get("/raw/abcd1234", headers={"Accept": "text/html"})
        self.assertEqual((r.status_code, r.headers["Location"]), (302, "https://p.example/page/abcd1234"))

    def test_custom_and_disabled_routes(self):
        c = make({"raw_url": "https://p.example/sub/"}, {"raw_route": "/r/", "clash_route": ""})
        self.assertEqual(self.get(c, "/r/abcd1234").data, RAW_BODY)
        self.assertEqual(self.get(c, "/raw/abcd1234").status_code, 404)
        self.assertEqual(self.get(c, "/clash/abcd1234").status_code, 404)

    def test_config_checks(self):
        conf, problems = normalize({"panel": {"mode": "fast"}, "server": {"raw_route": "/sub/", "clash_route": "x"}})
        self.assertEqual(conf["panel"]["mode"], "engine")
        self.assertEqual(conf["server"]["raw_route"], "")
        self.assertEqual(conf["server"]["clash_route"], "/clash/")
        self.assertEqual(sum("panel.mode" in p or "raw_route" in p or "clash_route" in p for p in problems), 3)


if __name__ == "__main__":
    unittest.main()
