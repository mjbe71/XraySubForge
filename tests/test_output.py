"""Tests for the `output` section (inbounds, dns-out, base rules, dedicated DNS, QUIC block, sampling, panel balancers)."""
import copy
import unittest

from xraysubforge.config import normalize
from xraysubforge.engine import process


def base():
    return {"remarks": "A", "inbounds": [{"protocol": "mixed", "port": 10808, "tag": "mixed"}],
            "dns": {"servers": ["1.1.1.1"]},
            "outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {"address": "x.example.com", "port": 443, "id": "u"},
                           "streamSettings": {"network": "xhttp", "security": "tls",
                                              "tlsSettings": {"serverName": "sni.example.com"}}},
                          {"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}]}}


def run(output, cfgs=None, groups=None):
    conf, problems = normalize({"output": output, "groups": groups or []})
    out, _ = process(copy.deepcopy(cfgs or [base()]), conf)
    return out, problems


class Output(unittest.TestCase):
    def test_off_by_default(self):
        out, _ = run({})
        self.assertEqual(out, [base()])

    def test_validation(self):
        _, p = run({"dns_out": "yes", "bogus": 1, "sampling": {"x": 1}})
        self.assertEqual(len(p), 3)

    def test_split_inbounds_keeps_port(self):
        out, _ = run({"split_inbounds": True})
        self.assertEqual([(i["protocol"], i["port"], i["tag"]) for i in out[0]["inbounds"]],
                         [("socks", 10808, "socks"), ("http", 10809, "http")])

    def test_dns_out_and_block_and_base_rules(self):
        out, _ = run({"dns_out": True, "block_udp_443": True, "base_rules": True, "quic_domains": ["a.com"]})
        c = out[0]
        tags = [o["tag"] for o in c["outbounds"]]
        self.assertIn("dns-out", tags)
        self.assertIn("block", tags)
        rules = c["routing"]["rules"]
        self.assertEqual(rules[0]["outboundTag"], "dns-out")
        self.assertEqual(rules[-1]["outboundTag"], "proxy")  # the original rule stays last
        self.assertIn({"type": "field", "network": "udp", "port": "443", "outboundTag": "block", "domain": ["a.com"]}, rules)

    def test_dns_out_needs_dns_servers(self):
        cfg = base()
        del cfg["dns"]
        out, _ = run({"dns_out": True}, [cfg])
        self.assertNotIn("dns-out", [o["tag"] for o in out[0]["outbounds"]])

    def test_dedicated_dns(self):
        out, _ = run({"dedicated_dns": {"ip": "9.9.9.9"}, "base_rules": True})
        first = out[0]["dns"]["servers"][0]
        self.assertEqual((first["address"], first["tag"], sorted(first["domains"])),
                         ("9.9.9.9", "dedicated-dns", ["sni.example.com", "x.example.com"]))
        self.assertEqual(out[0]["routing"]["rules"][0]["inboundTag"], ["dedicated-dns"])

    def test_replace_routing_keeps_balancer_rules(self):
        cfg = base()
        cfg["routing"]["rules"] += [{"type": "field", "network": "tcp", "balancerTag": "b"}]
        out, _ = run({"replace_routing": True, "domain_strategy": "IPOnDemand"}, [cfg])
        self.assertEqual(out[0]["routing"]["rules"], [{"type": "field", "network": "tcp", "balancerTag": "b"}])
        self.assertEqual(out[0]["routing"]["domainStrategy"], "IPOnDemand")

    def test_sampling_only_on_our_balancers(self):
        cfgs = []
        for i in range(4):
            c = base()
            c["remarks"] = "m%d" % i
            cfgs.append(c)
        panel = base()
        panel["remarks"] = "panel"
        panel["burstObservatory"] = {"subjectSelector": ["proxy"], "pingConfig": {"sampling": 9}}
        out, _ = run({"sampling": {"members_div": 2, "extra": 1}}, cfgs + [panel],
                     [{"id": "g", "type": "leastLoad", "when": {"remark": {"startswith": "m"}},
                       "probe": {"destination": "https://x/204", "sampling": 4}}])
        ours = next(c for c in out if c["remarks"] == "g")
        self.assertEqual(ours["burstObservatory"]["pingConfig"]["sampling"], 3)  # 4 members // 2 + 1
        self.assertEqual(next(c for c in out if c["remarks"] == "panel")["burstObservatory"]["pingConfig"]["sampling"], 9)

    def test_panel_balancers(self):
        cfg = base()
        cfg["outbounds"] += [{"tag": "t2", "protocol": "vless", "settings": {"address": "y.example.com", "port": 1}}]
        cfg["routing"]["balancers"] = [{"tag": "b", "selector": ["proxy", "t"], "strategy": {"type": "leastLoad"}}]
        out, _ = run({"panel_balancers": {"max_rtt": "2500ms", "few_max_members": 2, "expected_few": 1, "expected_many": 2}}, [cfg])
        self.assertEqual(out[0]["routing"]["balancers"][0]["strategy"]["settings"], {"maxRTT": "2500ms", "expected": 1})


if __name__ == "__main__":
    unittest.main()


class Details(unittest.TestCase):
    def test_direct_dns_from_server_tags(self):
        cfg = base()
        cfg["dns"]["servers"] += [{"address": "1.2.3.4", "tag": "domestic-dns_0_0"}, {"address": "5.6.7.8", "tag": "other"}]
        out, _ = run({"direct_dns": True}, [cfg])
        self.assertIn({"type": "field", "inboundTag": ["domestic-dns_0_0"], "outboundTag": "direct"}, out[0]["routing"]["rules"])

    def test_catchall_rules_and_member_position(self):
        cfgs = []
        for r in ("a1", "a2", "gc"):
            c = base()
            c["remarks"] = r
            c["outbounds"][0]["settings"]["port"] = {"a1": 1, "a2": 2, "gc": 3}[r]
            cfgs.append(c)
        out, _ = run({}, cfgs, [{"id": "g", "type": "random", "catchall_rules": [{"port": "0-65535"}, {"network": "tcp,udp"}],
                                 "member_position": [{"when": {"remark": "gc"}, "at": "first"}]}])
        g = out[0]
        self.assertEqual([o["settings"]["port"] for o in g["outbounds"] if o["protocol"] == "vless"], [3, 1, 2])
        bal = [r for r in g["routing"]["rules"] if r.get("balancerTag")]
        self.assertEqual([(r.get("port"), r.get("network")) for r in bal], [("0-65535", None), (None, "tcp,udp")])


class Decoy(unittest.TestCase):
    def run_decoy(self, spec, params):
        conf, p = normalize({"output": {"decoy": spec}})
        self.assertEqual(p, [])
        return process([base()], conf, params=params)[0][0]

    def test_param_switch(self):
        spec = {"param": "decoy"}
        self.assertEqual(self.run_decoy(spec, {})["outbounds"][0]["tag"], "proxy")
        c = self.run_decoy(spec, {"decoy": "1"})
        self.assertEqual([o["tag"] for o in c["outbounds"]][:2], ["decoy", "proxy"])
        self.assertEqual(c["outbounds"][0]["protocol"], "freedom")

    def test_default_on_and_off_switch(self):
        spec = {"default": True}
        self.assertEqual(self.run_decoy(spec, {})["outbounds"][0]["tag"], "decoy")
        self.assertEqual(self.run_decoy(spec, {"decoy": "0"})["outbounds"][0]["tag"], "proxy")

    def test_adds_catchall_only_without_balancer_rule(self):
        c = self.run_decoy({}, {"decoy": "1"})
        self.assertEqual(c["routing"]["rules"][-1]["outboundTag"], "proxy")
        cfg = base()
        cfg["routing"]["rules"] = [{"type": "field", "network": "tcp,udp", "balancerTag": "b"}]
        conf, _ = normalize({"output": {"decoy": {}}})
        out = process([cfg], conf, params={"decoy": "1"})[0][0]
        self.assertEqual(out["routing"]["rules"], [{"type": "field", "network": "tcp,udp", "balancerTag": "b"}])

    def test_validation(self):
        _, p = normalize({"output": {"decoy": {"default": "x", "bogus": 1}}})
        self.assertEqual(len(p), 2)
