"""Tests for `chains` (an admin-defined outbound dialed through an exit config) and the accounts store."""
import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from xraysubforge.accounts import AccountStore, parse
from xraysubforge.config import ConfigStore, normalize
from xraysubforge.engine import process, substitute
from xraysubforge.server import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "examples", "sample-panel.json"), encoding="utf-8") as f:
    PANEL = json.load(f)

ENTRY = {
    "protocol": "masque",
    "settings": {"address": "gate.example", "port": 443},
    "streamSettings": {"masqueSettings": {"warp": {"privateKey": "{account.privateKey}", "address": "{account.address}",
                                                  "note": "exit is {exit.address}"}}},
}
ACCOUNT = {"privateKey": "KEY", "address": ["172.16.0.2"]}


def run(chains, accounts=ACCOUNT, subid=None, extra=None, panel=PANEL):
    raw = dict({"chains": chains}, **(extra or {}))
    conf, problems = normalize(raw)
    acc = {"default": accounts} if accounts else {}
    return process(copy.deepcopy(panel), conf, subid=subid, accounts=acc), problems


def by_remark(out, remark):
    return next(c for c in out if c.get("remarks") == remark)


class Substitute(unittest.TestCase):
    def test_types_and_text(self):
        v = {"account": {"k": "KEY", "list": [1, 2], "n": 5}, "exit": {"address": "a.example"}, "split": "de", "n": 3}
        self.assertEqual(substitute({"a": "{account.list}", "b": "{account.n}", "c": "x-{split}-{n}", "d": ["{exit.address}", 7]}, v),
                         {"a": [1, 2], "b": 5, "c": "x-de-3", "d": ["a.example", 7]})
        self.assertEqual(substitute("{unknown} {braces}", v), "{unknown} {braces}")
        with self.assertRaises(ValueError):
            substitute("{account.missing}", v)


class Chains(unittest.TestCase):
    CHAIN = {"id": "w", "exit_when": {"remark": {"startswith": "fast-"}},
             "split_by": {"field": "remark", "regex": "^fast-([^-]+)"}, "name": "{split} via gate", "entry": ENTRY}

    def test_chain_per_bucket(self):
        (out, report), problems = run([self.CHAIN])
        self.assertEqual(problems, [])
        remarks = [c["remarks"] for c in out]
        self.assertIn("berlin via gate", remarks)
        self.assertIn("tokyo via gate", remarks)
        self.assertEqual(len(out), len(PANEL) + 2)                         # exits stay by default
        b = by_remark(out, "berlin via gate")
        entry, exit_ob = b["outbounds"][0], b["outbounds"][1]
        self.assertEqual((entry["tag"], exit_ob["tag"]), ("w-0-entry", "w-0-exit"))
        self.assertEqual(entry["streamSettings"]["sockopt"]["dialerProxy"], "w-0-exit")
        warp = entry["streamSettings"]["masqueSettings"]["warp"]
        self.assertEqual((warp["privateKey"], warp["address"], warp["note"]), ("KEY", ["172.16.0.2"], "exit is b1.example.com"))
        self.assertEqual(exit_ob["settings"]["address"], "b1.example.com")     # first berlin config is the exit
        self.assertEqual([o["tag"] for o in b["outbounds"][2:]], ["direct", "block"])
        self.assertEqual(b["routing"]["rules"][-1], {"type": "field", "network": "tcp,udp", "outboundTag": "w-0-entry"})
        self.assertEqual(b["routing"]["rules"][0]["outboundTag"], "direct")
        self.assertEqual(b["dns"], PANEL[1]["dns"])
        self.assertEqual(entry["settings"], {"address": "gate.example", "port": 443})
        self.assertEqual(ENTRY["streamSettings"]["masqueSettings"]["warp"]["privateKey"], "{account.privateKey}")  # template untouched
        row = next(c for c in report["configs"] if c["remark"] == "fast-berlin-1")
        self.assertEqual(row["chains"], ["w"])

    def test_without_split_one_chain(self):
        chain = {"id": "one", "exit_when": {"remark": "fast-tokyo-2"}, "entry": ENTRY}
        (out, _), _ = run([chain])
        c = by_remark(out, "one")
        self.assertEqual(c["outbounds"][1]["settings"]["address"], "t2.example.com")

    def test_options(self):
        chain = dict(self.CHAIN, remove_exit_from_output=True, position="top")
        (out, _), _ = run([chain])
        remarks = [c["remarks"] for c in out]
        self.assertEqual(remarks[:2], ["berlin via gate", "tokyo via gate"])
        self.assertNotIn("fast-berlin-1", remarks)
        self.assertIn("fast-berlin-2", remarks)                              # only the exit config itself is removed

    def test_standalone_without_exit(self):
        chain = {"id": "solo", "exit_when": {"remark": "backup-oslo"}, "through_exit": False, "entry": ENTRY}
        (out, _), _ = run([chain])
        c = by_remark(out, "solo")
        self.assertEqual([o["tag"] for o in c["outbounds"]], ["solo-0-entry", "direct", "block"])
        self.assertNotIn("dialerProxy", json.dumps(c))

    def test_old_routing_tag_is_repointed(self):
        panel = copy.deepcopy(PANEL)
        panel[1]["routing"]["rules"].append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
        (out, _), _ = run([self.CHAIN], panel=panel)
        b = by_remark(out, "berlin via gate")
        self.assertNotIn("proxy", [r.get("outboundTag") for r in b["routing"]["rules"]])

    def test_missing_account_value_skips_chain_and_reports(self):
        (out, report), _ = run([self.CHAIN], accounts={})
        self.assertEqual(out, PANEL)
        self.assertTrue(any("account.privateKey" in e for e in report["errors"]), report["errors"])

    def test_per_user_account(self):
        conf, _ = normalize({"chains": [self.CHAIN]})
        accounts = {"default": ACCOUNT, "users": {"user1234": {"privateKey": "PERSONAL"}}}
        out, _ = process(copy.deepcopy(PANEL), conf, subid="user1234", accounts=accounts)
        warp = by_remark(out, "berlin via gate")["outbounds"][0]["streamSettings"]["masqueSettings"]["warp"]
        self.assertEqual((warp["privateKey"], warp["address"]), ("PERSONAL", ["172.16.0.2"]))     # merged over default
        out, _ = process(copy.deepcopy(PANEL), conf, subid="other999", accounts=accounts)
        self.assertEqual(by_remark(out, "berlin via gate")["outbounds"][0]["streamSettings"]["masqueSettings"]["warp"]["privateKey"], "KEY")

    def test_validation(self):
        conf, problems = normalize({"chains": [{"id": "a"}, {"id": "b", "entry": {"protocol": "x"}, "through_exit": "yes"},
                                               {"id": "c", "entry": {"protocol": "x"}, "split_by": {"field": "remark", "regex": "("}},
                                               {"id": "ok", "entry": {"protocol": "x"}}]})
        self.assertEqual([c["id"] for c in conf["chains"]], ["ok"])
        self.assertGreaterEqual(len(problems), 3)


class Accounts(unittest.TestCase):
    def store(self, raw, files=None):
        d = tempfile.mkdtemp()
        for name, data in (files or {}).items():
            with open(os.path.join(d, name), "w") as f:
                json.dump(data, f)
        path = os.path.join(d, "config.json")
        with open(path, "w") as f:
            json.dump(raw, f)
        return AccountStore(ConfigStore(path)), d

    def test_parse_shapes(self):
        self.assertEqual(parse({"privateKey": "K", "_c": "x"}), {"default": {"privateKey": "K"}, "users": {}})
        self.assertEqual(parse({"default": {"a": 1}, "users": {"u": {"b": 2}, "bad": 5}}), {"default": {"a": 1}, "users": {"u": {"b": 2}}})
        self.assertEqual(parse([1]), {"default": {}, "users": {}})

    def test_inline_and_file(self):
        s, d = self.store({"accounts": {"file": "acc.json", "default": {"a": 1, "b": 1}}}, {"acc.json": {"b": 2}})
        self.assertEqual(s.get()["default"], {"a": 1, "b": 2})                     # file wins; path is relative to config.json

    def test_no_source_is_empty(self):
        s, _ = self.store({})
        self.assertEqual(s.get(), {"default": {}, "users": {}})

    def test_reload_and_missing_file(self):
        s, d = self.store({"accounts": {"file": "acc.json"}}, {"acc.json": {"k": 1}})
        self.assertEqual(s.get()["default"], {"k": 1})
        p = os.path.join(d, "acc.json")
        with open(p, "w") as f:
            json.dump({"k": 2}, f)
        st = os.stat(p)
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5 * 10 ** 9))
        self.assertEqual(s.get()["default"], {"k": 2})
        os.remove(p)
        self.assertEqual(s.get()["default"], {})

    def test_broken_file_keeps_previous(self):
        s, d = self.store({"accounts": {"file": "acc.json"}}, {"acc.json": {"k": 1}})
        s.get()
        p = os.path.join(d, "acc.json")
        with open(p, "w") as f:
            f.write("{ nope")
        st = os.stat(p)
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5 * 10 ** 9))
        self.assertEqual(s.get()["default"], {"k": 1})


class ServerWithChains(unittest.TestCase):
    def test_route_uses_account_of_the_user(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "acc.json"), "w") as f:
            json.dump({"default": ACCOUNT, "users": {"user1234": {"privateKey": "PERSONAL"}}}, f)
        path = os.path.join(d, "config.json")
        with open(path, "w") as f:
            json.dump({"panel": {"url": "https://p.example.com/json/"}, "accounts": {"file": "acc.json"},
                       "chains": [Chains.CHAIN]}, f)
        c = create_app(ConfigStore(path)).test_client()

        class Resp:
            status_code, headers = 200, {}
            def json(self): return PANEL
        with mock.patch("xraysubforge.panel.requests.get", return_value=Resp()):
            mine = json.loads(c.get("/sub/user1234").data)
            other = json.loads(c.get("/sub/someone99").data)
        key = lambda out: by_remark(out, "berlin via gate")["outbounds"][0]["streamSettings"]["masqueSettings"]["warp"]["privateKey"]
        self.assertEqual((key(mine), key(other)), ("PERSONAL", "KEY"))


if __name__ == "__main__":
    unittest.main()


class Choices(unittest.TestCase):
    CHAIN = {"id": "w", "exit_when": {"remark": {"startswith": "fast-"}}, "choices": {"endpoint": ["a", "b", "c", "d"]},
             "entry": {"protocol": "masque", "settings": {"address": "{choice.endpoint}", "port": 443}}}

    def addr(self, subid):
        out, _ = run([self.CHAIN], subid=subid)[0]
        chain = next(c for c in out if c.get("remarks") == "w")
        return chain["outbounds"][0]["settings"]["address"]

    def test_stable_per_user_and_spread(self):
        self.assertEqual(self.addr("user-1"), self.addr("user-1"))
        self.assertEqual(self.addr(None), "a")                      # no id: the first one
        seen = {self.addr("user-%d" % i) for i in range(40)}
        self.assertEqual(seen, {"a", "b", "c", "d"})

    def test_validation(self):
        _, problems = normalize({"chains": [dict(self.CHAIN, choices={"x": []})]})
        self.assertTrue(any("choices" in p for p in problems))
        _, problems = normalize({"chains": [self.CHAIN]})
        self.assertEqual(problems, [])

    def test_warp_masque_example(self):
        with open(os.path.join(ROOT, "examples", "warp-masque.json"), encoding="utf-8") as f:
            raw = json.load(f)
        conf, problems = normalize(raw)
        self.assertEqual([p for p in problems if "unknown key" not in p], [])
        acc = {"default": {"privateKey": "K", "publicKey": "P", "address": ["172.16.0.2", "2606::1"]}}
        out, report = process(copy.deepcopy(PANEL), conf, subid="u1", accounts=acc)
        self.assertEqual(report["errors"], [])
        entry = next(c for c in out if c["remarks"] == "warp")["outbounds"][0]
        self.assertEqual(entry["protocol"], "masque")
        self.assertTrue(entry["settings"]["address"].startswith("162.159."))
        self.assertEqual(entry["streamSettings"]["masqueSettings"]["warp"]["address"], ["172.16.0.2", "2606::1"])
        self.assertTrue(entry["streamSettings"]["sockopt"]["dialerProxy"].endswith("-exit"))
        self.assertEqual(entry["streamSettings"]["sockopt"]["happyEyeballs"]["interleave"], 2)   # the admin's own fields survive
