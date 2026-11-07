"""Tests for XraySubForge. Run from the project folder:  python3 -m unittest discover -s tests -v"""
import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from xraysubforge.config import ConfigStore, normalize
from xraysubforge.engine import deep_merge, process
from xraysubforge.matching import check_when, fields_of, match
from xraysubforge.server import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_json(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return json.load(f)


PANEL = load_json("examples", "sample-panel.json")
BALANCERS = load_json("examples", "balancers.json")


def conf_of(raw):
    conf, problems = normalize(raw)
    return conf, problems


def by_remark(out, remark):
    return next(c for c in out if c.get("remarks") == remark)


class Matching(unittest.TestCase):
    def test_fields(self):
        f = fields_of(PANEL[1])
        self.assertEqual((f["remark"], f["protocol"], f["address"], f["port"], f["network"], f["security"], f["sni"], f["host"], f["path"]),
                         ("fast-berlin-1", "vless", "b1.example.com", 443, "xhttp", "tls", "a.example.com", "a.example.com", "/x"))
        self.assertEqual(fields_of(PANEL[3])["network"], "tcp")
        self.assertEqual(fields_of(PANEL[0])["protocol"], "socks")

    def test_flag_field(self):
        cfg = copy.deepcopy(PANEL[1])
        cfg["remarks"] = "x \U0001F1E9\U0001F1EA y"
        self.assertEqual(fields_of(cfg)["flag"], "\U0001F1E9\U0001F1EA")

    def test_operators(self):
        c = PANEL[1]
        yes = [{"remark": "fast-berlin-1"}, {"remark": {"contains": "berlin"}}, {"remark": {"icontains": "BERLIN"}},
               {"remark": {"startswith": "fast"}}, {"remark": {"endswith": "-1"}}, {"remark": {"regex": r"^fast-\w+-\d$"}},
               {"remark": {"iregex": "^FAST"}}, {"network": {"in": ["xhttp", "ws"]}}, {"port": {"gt": 400, "lte": 443}},
               {"sni": {"exists": True}}, {"nothing": {"exists": False}}, {"remark": {"not_contains": "tokyo"}},
               {"outbounds.0.settings.address": "b1.example.com"}, {}, None,
               {"any": [{"remark": "x"}, {"network": "xhttp"}]}, {"all": [{"network": "xhttp"}, {"port": 443}]},
               {"not": {"remark": {"contains": "tokyo"}}}]
        for w in yes:
            self.assertTrue(match(w, c), w)
        no = [{"remark": "fast"}, {"remark": {"contains": "tokyo"}}, {"network": {"not_in": ["xhttp"]}},
              {"all": [{"network": "xhttp"}, {"port": 80}]}, {"not": {"network": "xhttp"}}, {"nothing": "x"}]
        for w in no:
            self.assertFalse(match(w, c), w)

    def test_check_when(self):
        self.assertEqual(check_when({"remark": {"contains": "x"}, "any": [{"port": 1}]}, "w"), [])
        self.assertTrue(check_when({"remark": {"bogus": 1}}, "w"))
        self.assertTrue(check_when({"remark": {"regex": "("}}, "w"))
        self.assertTrue(check_when({"any": {"a": 1}}, "w"))
        self.assertTrue(check_when({"remark": {"in": "abc"}}, "w"))


class Config(unittest.TestCase):
    def test_example_is_valid(self):
        conf, problems = conf_of(BALANCERS)
        self.assertEqual(problems, [])
        self.assertEqual(len(conf["rules"]), 2)

    def test_empty_config_is_passthrough_defaults(self):
        conf, problems = conf_of({})
        self.assertEqual((problems, conf["rules"], conf["groups"], conf["patches"]), ([], [], [], []))
        self.assertEqual(conf["panel"]["url"], "")

    def test_bad_values_are_reported_and_ignored(self):
        conf, problems = conf_of({
            "_comment": "ok", "bogus": 1,
            "server": {"port": 0, "route": "nope", "host": "0.0.0.0"},
            "panel": {"url": "ftp://x", "timeout": -1},
            "rules": [{"id": "a", "do": "explode"}, {"id": "b", "do": "drop", "when": {"remark": {"regex": "("}}},
                      {"id": "ok", "do": "drop"}, {"id": "ok", "do": "keep"}, "text"],
            "groups": [{"id": "g"}, {"id": "g2", "type": "random", "split_by": {"field": "remark", "regex": "["}}],
            "patches": [{"stage": "later"}],
        })
        self.assertEqual(conf["server"]["port"], 8080)
        self.assertEqual(conf["server"]["host"], "0.0.0.0")
        self.assertEqual(conf["panel"]["url"], "")
        self.assertEqual([r["id"] for r in conf["rules"]], ["ok"])
        self.assertEqual((conf["groups"], conf["patches"]), ([], []))
        self.assertGreaterEqual(len(problems), 9)

    def test_hot_reload_and_broken_file(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "config.json")

        def write(text, bump):
            with open(path, "w") as f:
                f.write(text)
            st = os.stat(path)
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + bump * 10 ** 9))

        write('{"server": {"port": 9000}}', 0)
        store = ConfigStore(path)
        self.assertEqual(store.get()["server"]["port"], 9000)
        write('{"server": {"port": 9001}}', 2)
        self.assertEqual(store.get()["server"]["port"], 9001)
        write("{ nope", 4)
        self.assertEqual(store.get()["server"]["port"], 9001)       # broken file: keep previous
        write("{}", 6)
        self.assertEqual(store.get()["server"]["port"], 8080)       # empty file: defaults
        os.remove(path)
        self.assertEqual(store.get()["server"]["port"], 8080)       # deleted file: keep current

    def test_missing_file_means_defaults(self):
        store = ConfigStore(os.path.join(tempfile.mkdtemp(), "nope.json"))
        self.assertEqual(store.get()["groups"], [])


class Engine(unittest.TestCase):
    def run_conf(self, raw, panel=PANEL):
        conf, problems = conf_of(raw)
        self.assertEqual([p for p in problems if "unknown key" in p], [], problems)
        return process(copy.deepcopy(panel), conf)

    def test_empty_config_changes_nothing(self):
        out, report = self.run_conf({})
        self.assertEqual(out, PANEL)
        self.assertEqual(report["errors"], [])

    def test_input_is_not_mutated(self):
        before = copy.deepcopy(PANEL)
        conf, _ = conf_of(BALANCERS)
        process(PANEL, conf)
        self.assertEqual(PANEL, before)

    def test_rules_first_match_wins_and_pins(self):
        out, report = self.run_conf({"rules": [
            {"id": "keep-test", "when": {"remark": "test-node"}, "do": "keep"},
            {"id": "drop-test", "when": {"remark": {"startswith": "test"}}, "do": "drop"},
            {"id": "bottom", "when": {"remark": "fast-berlin-1"}, "do": "pin_bottom"},
            {"id": "top", "when": {"protocol": "socks"}, "do": "pin_top"},
            {"id": "off", "enabled": False, "when": {}, "do": "drop"},
        ]})
        remarks = [c["remarks"] for c in out]
        self.assertIn("test-node", remarks)                         # the keep rule came first
        self.assertEqual(remarks[-1], "fast-berlin-1")
        self.assertEqual(remarks[0], "info")
        self.assertEqual(len(out), len(PANEL))

    def test_drop(self):
        out, _ = self.run_conf({"rules": [{"id": "d", "when": {"remark": {"contains": "fast"}}, "do": "drop"}]})
        self.assertEqual([c["remarks"] for c in out], ["info", "test-node", "backup-oslo"])

    def test_group_split_structure(self):
        out, report = self.run_conf(BALANCERS)
        self.assertEqual([c["remarks"] for c in out], ["info", "berlin (balanced, 3)", "tokyo (balanced, 2)", "backup-oslo"])
        berlin = by_remark(out, "berlin (balanced, 3)")
        proxies = [o for o in berlin["outbounds"] if o["protocol"] == "vless"]
        self.assertEqual([o["tag"] for o in proxies], ["fast-0-1", "fast-0-2", "fast-0-3"])
        self.assertEqual([o["tag"] for o in berlin["outbounds"] if o["protocol"] != "vless"], ["direct", "block"])
        self.assertEqual(sorted(o["settings"]["address"] for o in proxies), ["b1.example.com", "b2.example.com", "b3.example.com"])
        bal = berlin["routing"]["balancers"][0]
        self.assertEqual(bal["selector"], ["fast-0-"])
        self.assertEqual(bal["strategy"]["type"], "leastLoad")
        self.assertEqual(bal["strategy"]["settings"]["expected"], 2)
        self.assertEqual(berlin["routing"]["rules"][-1], {"type": "field", "network": "tcp,udp", "balancerTag": bal["tag"]})
        self.assertEqual(berlin["routing"]["rules"][0]["outboundTag"], "direct")       # unrelated rules are untouched
        self.assertEqual(berlin["burstObservatory"]["subjectSelector"], ["fast-0-"])
        self.assertEqual(berlin["burstObservatory"]["pingConfig"]["interval"], "30s")
        self.assertNotIn("observatory", berlin)
        self.assertEqual(berlin["dns"], PANEL[1]["dns"])
        # member_cost: only the b1 node got an entry
        costs = bal["strategy"]["settings"]["costs"]
        self.assertEqual([(c["match"], c["value"]) for c in costs], [("^fast\\-0\\-1$", 5)])
        # tokyo is a separate balancer with a different prefix
        self.assertEqual(by_remark(out, "tokyo (balanced, 2)")["routing"]["balancers"][0]["selector"], ["fast-1-"])
        self.assertEqual(len({o["tag"] for c in out[1:3] for o in c["outbounds"]}), 7)

    def test_group_without_split_and_options(self):
        out, report = self.run_conf({"groups": [{
            "id": "all", "when": {"remark": {"startswith": "fast-"}}, "name": "Everything", "type": "random",
            "remove_members_from_output": False, "position": "bottom"}]})
        remarks = [c["remarks"] for c in out]
        self.assertEqual(remarks[-1], "Everything")
        self.assertEqual(len(remarks), len(PANEL) + 1)               # members stay
        grp = by_remark(out, "Everything")
        self.assertEqual(grp["routing"]["balancers"][0]["strategy"], {"type": "random"})
        self.assertNotIn("burstObservatory", grp)
        self.assertEqual(len([o for o in grp["outbounds"] if o["protocol"] == "vless"]), 5)

    def test_leastping_uses_observatory(self):
        out, _ = self.run_conf({"groups": [{"id": "p", "when": {"remark": {"startswith": "fast-"}}, "type": "leastPing",
                                            "probe": {"probeUrl": "https://example.com/204", "probeInterval": "1m"}}]})
        g = by_remark(out, "p")
        self.assertEqual(g["observatory"], {"subjectSelector": ["p-0-"], "probeUrl": "https://example.com/204", "probeInterval": "1m"})
        self.assertNotIn("burstObservatory", g)

    def test_min_members_and_no_match(self):
        out, _ = self.run_conf({"groups": [{"id": "g", "when": {"remark": {"startswith": "fast-"}}, "type": "random",
                                            "split_by": {"field": "remark", "regex": "^fast-([^-]+)"}, "min_members": 3}]})
        remarks = [c["remarks"] for c in out]
        self.assertIn("berlin", remarks)                         # no `name` given with split_by: the bucket value is used
        self.assertIn("fast-tokyo-1", remarks)                       # tokyo has 2 members: stays as it was
        out, _ = self.run_conf({"groups": [{"id": "g", "when": {"remark": "nothing"}, "type": "random"}]})
        self.assertEqual(out, PANEL)

    def test_rules_reroute_old_tag(self):
        panel = copy.deepcopy(PANEL)
        panel[1]["routing"]["rules"].append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
        out, _ = self.run_conf({"groups": [{"id": "g", "when": {"remark": "fast-berlin-1"}, "type": "random"}]}, panel)
        g = by_remark(out, "g")
        self.assertTrue(all(r.get("outboundTag") != "proxy" for r in g["routing"]["rules"]))
        self.assertEqual(g["routing"]["rules"][-1]["balancerTag"], g["routing"]["balancers"][0]["tag"])
        self.assertEqual(len([r for r in g["routing"]["rules"] if r.get("balancerTag")]), 1)  # no duplicate catch-all

    def test_patches(self):
        out, _ = self.run_conf({"patches": [
            {"id": "p1", "stage": "source", "target": "outbound", "when": {"network": "xhttp"},
             "merge": {"streamSettings": {"xhttpSettings": {"mode": "stream-up"}}, "mux": None}},
            {"id": "p2", "stage": "output", "when": {"remark": "backup-oslo"},
             "merge": {"dns": {"queryStrategy": None, "hosts": {"a.example": "1.1.1.1"}}},
             "routing_prepend": [{"type": "field", "domain": ["x"], "outboundTag": "block"}]},
        ]})
        b1 = by_remark(out, "fast-berlin-1")
        self.assertEqual(b1["outbounds"][0]["streamSettings"]["xhttpSettings"]["mode"], "stream-up")
        self.assertEqual(b1["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"], "/x")       # merged, not replaced
        self.assertEqual(by_remark(out, "fast-berlin-3")["outbounds"][0]["streamSettings"]["network"], "tcp")
        self.assertNotEqual(by_remark(out, "fast-berlin-3")["outbounds"][0]["streamSettings"].get("xhttpSettings", {}).get("mode"), "stream-up")
        self.assertEqual(b1["outbounds"][1], {"tag": "direct", "protocol": "freedom", "settings": {}})  # non-proxy outbound untouched
        oslo = by_remark(out, "backup-oslo")
        self.assertNotIn("queryStrategy", oslo["dns"])
        self.assertEqual(oslo["dns"]["hosts"], {"a.example": "1.1.1.1"})
        self.assertEqual(oslo["routing"]["rules"][0]["domain"], ["x"])

    def test_source_patches_reach_groups(self):
        out, _ = self.run_conf({"patches": [
            {"id": "p", "target": "outbound", "when": {}, "merge": {"mux": {"enabled": True}}}],
            "groups": [{"id": "g", "when": {"remark": {"startswith": "fast-"}}, "type": "random"}]})
        g = by_remark(out, "g")
        self.assertTrue(all(o["mux"] == {"enabled": True} for o in g["outbounds"] if o["protocol"] == "vless"))

    def test_a_broken_group_does_not_break_the_rest(self):
        conf, _ = conf_of({"groups": [{"id": "g", "when": {"remark": {"startswith": "fast-"}}, "type": "random"}]})
        with mock.patch("xraysubforge.engine.build_group", side_effect=RuntimeError("boom")):
            out, report = process(copy.deepcopy(PANEL), conf)
        self.assertEqual(out, PANEL)
        self.assertEqual(len(report["errors"]), 1)

    def test_deep_merge(self):
        self.assertEqual(deep_merge({"a": {"b": 1, "c": 2}, "d": [1]}, {"a": {"b": None, "e": 3}, "d": [2]}),
                         {"a": {"c": 2, "e": 3}, "d": [2]})


class FakeResponse:
    def __init__(self, payload, status=200, headers=None):
        self.payload, self.status_code, self.headers = payload, status, headers or {}

    def json(self):
        if isinstance(self.payload, ValueError):
            raise self.payload
        return self.payload


class Server(unittest.TestCase):
    def app_with(self, raw):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "config.json")
        with open(path, "w") as f:
            json.dump(raw, f)
        return create_app(ConfigStore(path))

    def test_passthrough_and_headers(self):
        app = self.app_with({"panel": {"url": "https://panel.example.com/json"}})
        with mock.patch("xraysubforge.panel.requests.get",
                        return_value=FakeResponse(PANEL, headers={"Profile-Title": "demo", "X-Other": "no"})) as get:
            r = app.test_client().get("/sub/abcd1234")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(json.loads(r.data), PANEL)
        self.assertEqual(r.headers["Profile-Title"], "demo")
        self.assertNotIn("X-Other", r.headers)
        self.assertEqual(get.call_args[0][0], "https://panel.example.com/json/abcd1234")

    def test_rules_applied_and_custom_route(self):
        raw = dict(BALANCERS, server={"route": "/s/"})
        app = self.app_with(raw)
        c = app.test_client()
        with mock.patch("xraysubforge.panel.requests.get", return_value=FakeResponse(PANEL)):
            r = c.get("/s/abcd1234")
            self.assertEqual([x["remarks"] for x in json.loads(r.data)],
                             ["info", "berlin (balanced, 3)", "tokyo (balanced, 2)", "backup-oslo"])
            self.assertEqual(c.get("/sub/abcd1234").status_code, 404)
            self.assertEqual(c.get("/s/x").status_code, 404)                  # id too short
            self.assertEqual(c.get("/s/a/../b").status_code, 404)
        self.assertEqual(c.get("/healthz").status_code, 200)

    def test_single_object_stays_single(self):
        app = self.app_with({"panel": {"url": "https://p.example.com/json/"}})
        with mock.patch("xraysubforge.panel.requests.get", return_value=FakeResponse(PANEL[1])):
            r = app.test_client().get("/sub/abcd1234")
        self.assertEqual(json.loads(r.data), PANEL[1])

    def test_panel_not_set_and_failures(self):
        c = self.app_with({}).test_client()
        self.assertEqual(c.get("/sub/abcd1234").status_code, 503)
        c = self.app_with({"panel": {"url": "https://p.example.com/json/"}}).test_client()
        import requests
        with mock.patch("xraysubforge.panel.requests.get", side_effect=requests.ConnectionError("x")):
            self.assertEqual(c.get("/sub/abcd1234").status_code, 502)
        with mock.patch("xraysubforge.panel.requests.get", return_value=FakeResponse(None, status=404)):
            self.assertEqual(c.get("/sub/abcd1234").status_code, 404)
        with mock.patch("xraysubforge.panel.requests.get", return_value=FakeResponse(None, status=500)):
            self.assertEqual(c.get("/sub/abcd1234").status_code, 502)
        with mock.patch("xraysubforge.panel.requests.get", return_value=FakeResponse(ValueError("no"))):
            self.assertEqual(c.get("/sub/abcd1234").status_code, 502)

    def test_browser_redirect(self):
        c = self.app_with({"panel": {"url": "https://p.example.com/json/", "page_url": "https://p.example.com/sub/"}}).test_client()
        r = c.get("/sub/abcd1234", headers={"Accept": "text/html"})
        self.assertEqual((r.status_code, r.headers["Location"]), (302, "https://p.example.com/sub/abcd1234"))

    def test_engine_failure_falls_back_to_panel_response(self):
        c = self.app_with({"panel": {"url": "https://p.example.com/json/"}}).test_client()
        with mock.patch("xraysubforge.panel.requests.get", return_value=FakeResponse(PANEL)), \
                mock.patch("xraysubforge.server.process", side_effect=RuntimeError("boom")):
            r = c.get("/sub/abcd1234")
        self.assertEqual(json.loads(r.data), PANEL)


if __name__ == "__main__":
    unittest.main()
