"""Tests for group.expand (several members per server, address pool) and the skip-configs-with-balancer default."""
import copy
import unittest

from xraysubforge.config import normalize
from xraysubforge.engine import process


def cfg(remark, address, tag="proxy"):
    return {"remarks": remark, "outbounds": [
        {"tag": tag, "protocol": "vless", "settings": {"address": address, "port": 443, "id": "u"}},
        {"tag": "direct", "protocol": "freedom"}], "routing": {"rules": []}}


POOL = ["p1.test", "p2.test", "p3.test", "p4.test", "p5.test"]
CONFS = [cfg("DE s1 a", "cf1.test"), cfg("DE s1 b", "cf2.test"), cfg("DE s2 a", "own.example")]


def group(**expand):
    ex = {"copies": 3, "server_by": {"field": "remark", "regex": r"(s\d)"}, "addresses": POOL}
    ex.update(expand)
    return {"groups": [{"id": "g", "type": "leastLoad", "expand": ex}]}


def run(raw, confs=CONFS, subid="u1"):
    conf, problems = normalize(raw)
    assert not [p for p in problems if "unknown" in p], problems
    out, report = process(copy.deepcopy(confs), conf, subid=subid)
    return out, report, problems


def addrs(c):
    return [o["settings"]["address"] for o in c["outbounds"] if o["protocol"] == "vless"]


class Expand(unittest.TestCase):
    def test_validation(self):
        _, p = normalize({"groups": [{"id": "g", "type": "random", "expand": {"copies": 0}}]})
        self.assertTrue(any("copies" in x for x in p))
        _, p = normalize({"groups": [{"id": "g", "type": "random", "expand": {"copies": 2, "pick": "x", "bad": 1}}]})
        self.assertTrue(any("pick" in x for x in p) and any("bad" in x for x in p))

    def test_members_per_server(self):
        out, _, _ = run(group())
        self.assertEqual(len(out), 1)
        self.assertEqual(len(addrs(out[0])), 6)  # 2 servers x 3 copies

    def test_pool_addresses_distinct_within_server(self):
        out, _, _ = run(group())
        a = addrs(out[0])
        self.assertEqual(len(set(a[:3])), 3)
        self.assertTrue(all(x in POOL for x in a))

    def test_keep_own_address(self):
        out, _, _ = run(group(address_regex=r"^cf\d"))
        a = addrs(out[0])
        self.assertEqual(a[3:], ["own.example"] * 3)
        self.assertTrue(all(x in POOL for x in a[:3]))

    def test_alternates_over_server_configs(self):
        confs = [cfg("DE s1 a", "x"), cfg("DE s1 b", "x")]
        confs[1]["outbounds"][0]["settings"]["port"] = 8443
        out, _, _ = run(group(copies=4), confs)
        ports = [o["settings"]["port"] for o in out[0]["outbounds"] if o["protocol"] == "vless"]
        self.assertEqual(ports, [443, 8443, 443, 8443])

    def test_per_user_is_stable_random_is_not_required(self):
        a = addrs(run(group(pick="per_user"), subid="u1")[0][0])
        b = addrs(run(group(pick="per_user"), subid="u1")[0][0])
        c = addrs(run(group(pick="per_user"), subid="u2")[0][0])
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_when_keeps_others_single(self):
        out, _, _ = run(group(when={"remark": {"endswith": " a"}}))
        # both "a" configs are expanded (s1: 3 copies, s2: 3 copies); "b" is single
        self.assertEqual(len(addrs(out[0])), 7)

    def test_no_server_key_each_config_own_server(self):
        ex = group()
        del ex["groups"][0]["expand"]["server_by"]
        out, _, _ = run(ex)
        self.assertEqual(len(addrs(out[0])), 9)

    def test_costs_apply_to_copies(self):
        raw = group()
        raw["groups"][0]["member_cost"] = [{"when": {"remark": {"contains": "s2"}}, "value": 5}, {"value": 1}]
        out, _, _ = run(raw)
        vals = sorted(c["value"] for c in out[0]["routing"]["balancers"][0]["strategy"]["settings"]["costs"])
        self.assertEqual(vals, [1, 1, 1, 5, 5, 5])

    def test_skips_configs_with_balancer(self):
        confs = copy.deepcopy(CONFS)
        confs.append({"remarks": "panel-lb", "outbounds": copy.deepcopy(confs[0]["outbounds"]),
                      "routing": {"rules": [], "balancers": [{"tag": "b", "selector": ["proxy"]}]}})
        out, _, _ = run(group(), confs)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[1]["remarks"], "panel-lb")
        self.assertEqual(len(addrs(out[1])), 1)  # untouched
        raw = group()
        raw["groups"][0]["include_balanced"] = True
        out, _, _ = run(raw, confs)
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()


class Blocks(unittest.TestCase):
    def test_blocks_layout(self):
        confs = [cfg("DE s%d" % i, "x%d" % i) for i in (1, 2, 3, 4)]
        for i, c in enumerate(confs, 1):
            c["outbounds"][0]["settings"]["port"] = 1000 + i
        out, _, _ = run(group(copies=2, layout="blocks"), confs)
        ports = [o["settings"]["port"] for o in out[0]["outbounds"] if o["protocol"] == "vless"]
        self.assertEqual(sorted(ports), sorted([1001, 1002, 1003, 1004] * 2))
        self.assertEqual(len(set(ports[:4])), 4)  # block 1 has one member of every server
        self.assertEqual(len(set(ports[4:])), 4)
        self.assertNotEqual(ports[:4], ports[4:])  # even server count: the second block is rotated

    def test_no_duplicate_catchall(self):
        out, _, _ = run(group())
        rules = [r for r in out[0]["routing"]["rules"] if r.get("balancerTag")]
        self.assertEqual(len(rules), 1)


class MemberPatch(unittest.TestCase):
    def test_patch_random_and_delete(self):
        confs = [cfg("DE s1 a", "x")]
        confs[0]["outbounds"][0]["streamSettings"] = {"network": "xhttp", "security": "tls",
                                                      "tlsSettings": {"serverName": "s", "echConfigList": "e", "pin": "p"},
                                                      "xhttpSettings": {"host": "h"}}
        raw = group(copies=6)
        raw["groups"][0]["member_patch"] = [
            {"merge": {"streamSettings": {"tlsSettings": {"echConfigList": None, "settings": {"echConfigList": None}, "alpn": ["h2"]}}},
             "random": {"streamSettings.tlsSettings.cipherSuites": ["A", "B"], "streamSettings.finalmask.tcp": [[1], [2]]}},
            {"when": {"network": "xhttp"}, "merge": {"streamSettings": {"xhttpSettings": {"host": ""}}}},
            {"when": {"network": "ws"}, "merge": {"marker": True}},
        ]
        import random
        random.seed(3)
        out, _, _ = run(raw, confs)
        obs = [o for o in out[0]["outbounds"] if o["protocol"] == "vless"]
        for o in obs:
            tls = o["streamSettings"]["tlsSettings"]
            self.assertNotIn("echConfigList", tls)
            self.assertNotIn("settings", tls)             # no empty object left behind
            self.assertEqual((tls["alpn"], o["streamSettings"]["xhttpSettings"]["host"]), (["h2"], ""))
            self.assertNotIn("marker", o)
        self.assertEqual({o["streamSettings"]["tlsSettings"]["cipherSuites"] for o in obs}, {"A", "B"})  # picked per member
        self.assertTrue(confs[0]["outbounds"][0]["streamSettings"]["tlsSettings"]["echConfigList"])    # input untouched
