"""The block layout (blocks.py), kinds (kinds.py) and the `random` key of patches."""
import unittest

from xraysubforge.blocks import CIPHER_PRESETS, FRAGMENT_PRESETS, cipher_value, fragment_value
from xraysubforge.config import normalize
from xraysubforge.engine import process
from xraysubforge.kinds import kinds_of
from xraysubforge.matching import match

DE, TR = "\U0001F1E9\U0001F1EA", "\U0001F1F9\U0001F1F7"


def cfg(remark, network="xhttp", security="tls", protocol="vless", address="srv.example.com"):
    st = {"network": network, "security": security}
    if security == "tls":
        st["tlsSettings"] = {"serverName": "sni.example.com"}
    if security == "reality":
        st["realitySettings"] = {"serverName": "sni.example.com"}
    return {"remarks": remark,
            "outbounds": [{"tag": "proxy", "protocol": protocol, "streamSettings": st,
                           "settings": {"vnext": [{"address": address, "port": 443, "users": [{"id": "0" * 8}]}]}},
                          {"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": []}}


def sample():
    return [
        cfg("Srv1" + DE + "CF"), cfg("Srv2" + DE + "CF"), cfg("Srv3" + DE + "CF"),
        cfg("Srv1" + TR + "CF"), cfg("Srv2" + TR + "CF"),
        cfg("DE" + DE + "Reality1", network="tcp", security="reality"), cfg("DE" + DE + "Reality2", network="tcp", security="reality"),
        cfg("Tunnel" + DE + "AT", network="tcp"), cfg("Tunnel" + TR + "DT", network="tcp"),
        cfg("Old vmess 1", protocol="vmess", network="tcp", security="none"),
    ]


def kind_when(remark_regex, **extra):
    return dict({"remark": {"regex": remark_regex}}, **extra)


CF = kind_when("CF$", network="xhttp")
REALITY = kind_when("Reality", security="reality")
TUNNEL = kind_when("^Tunnel")


def run(blocks, configs=None, **rest):
    conf, problems = normalize(dict({"blocks": blocks}, **rest))
    out, report = process(configs or sample(), conf)
    return out, report, conf, problems


def main_ob(c):
    return c["outbounds"][0]


class Kinds(unittest.TestCase):
    def test_numbers_make_one_kind_and_every_kind_matches_only_its_configs(self):
        configs = sample()
        kinds = kinds_of(configs)
        self.assertEqual([k["count"] for k in kinds], [3, 2, 2, 1, 1, 1])
        self.assertEqual(kinds[0]["flag"], DE)
        self.assertIn("vless", kinds[0]["label"])
        for c in configs:
            self.assertEqual(sum(match(k["when"], c) for k in kinds), 1, c["remarks"])
        self.assertTrue(match(kinds[0]["when"], cfg("Srv17" + DE + "CF")))   # the next server joins the kind
        self.assertFalse(match(kinds[0]["when"], cfg("Srv1" + DE + "CF", network="grpc")))

    def test_info_line_matches_every_user(self):
        mine = cfg("Sam|\U0001F4CA 12.5GB \u23f3 23d 20h", protocol="socks", network="tcp", security="none")
        other = cfg("Ali|\U0001F4CA 3GB \u23f3 1d 2h", protocol="socks", network="tcp", security="none")
        k = kinds_of([mine])[0]
        self.assertTrue(k["label"].startswith("User info"))
        self.assertTrue(match(k["when"], other))

    def test_skips_non_objects(self):
        self.assertEqual(kinds_of([None, "x"]), [])


class Blocks(unittest.TestCase):
    def test_full_layout(self):
        blocks = {"rest": "keep", "list": [
            {"id": "fast", "name": "Fast", "type": "balancer", "per_country": True, "kinds": [CF],
             "settings": {"fragment": ["tlshello-0-len", "tlshello-6-98"], "cipher": ["semi-python", "real-firefox"],
                          "fingerprint": "chrome", "pool": ["a.example.com", "b.example.com"]}},
            {"id": "reality", "name": "Reality", "kinds": [REALITY], "settings": {"fingerprint": "firefox"}},
            {"id": "gone", "type": "drop", "kinds": [TUNNEL]},
        ]}
        out, report, conf, problems = run(blocks)
        self.assertEqual([p for p in problems if "unknown" in p or "skipped" in p], [])
        self.assertEqual([c["remarks"] for c in out],
                         ["Fast " + DE, "Fast " + TR, "DE" + DE + "Reality1", "DE" + DE + "Reality2", "Old vmess 1"])
        de = out[0]
        members = [o for o in de["outbounds"] if o.get("tag", "").startswith("blk-fast-")]
        self.assertEqual(len(members), 6)                       # 3 servers x 2 pool addresses
        self.assertEqual(sorted({m["settings"]["vnext"][0]["address"] for m in members}), ["a.example.com", "b.example.com"])
        for m in members:
            st = m["streamSettings"]
            self.assertEqual(st["tlsSettings"]["fingerprint"], "chrome")
            self.assertIn(st["tlsSettings"]["cipherSuites"], CIPHER_PRESETS.values())
            self.assertIn(st["finalmask"]["tcp"], FRAGMENT_PRESETS.values())
        self.assertEqual(de["routing"]["balancers"][0]["strategy"]["type"], "leastLoad")
        self.assertIn("burstObservatory", de)                    # leastLoad gets a probe
        reality = main_ob(out[2])["streamSettings"]
        self.assertEqual(reality["realitySettings"]["fingerprint"], "firefox")
        self.assertNotIn("tlsSettings", reality)
        dropped = [c["remark"] for c in report["configs"] if c["action"] == "drop"]
        self.assertEqual(sorted(dropped), sorted(["Tunnel" + DE + "AT", "Tunnel" + TR + "DT"]))

    def test_first_block_wins(self):
        out, _, _, _ = run({"list": [
            {"id": "a", "type": "drop", "kinds": [REALITY]},
            {"id": "b", "name": "Again", "type": "balancer", "kinds": [REALITY]},
        ]})
        self.assertNotIn("Again", [c["remarks"] for c in out])
        self.assertEqual(len(out), 8)

    def test_balancers_share_kinds_but_lists_do_not(self):
        out, _, _, _ = run({"list": [
            {"id": "n", "name": "N", "type": "balancer", "kinds": [CF]},
            {"id": "f", "name": "F", "type": "balancer", "kinds": [CF], "settings": {"fragment": ["tlshello-0-len"]}},
            {"id": "l1", "kinds": [REALITY]},
            {"id": "l2", "name": "Late", "type": "balancer", "kinds": [REALITY]},
        ]})
        names = [c["remarks"] for c in out]
        self.assertEqual(names[:2], ["N", "F"])
        self.assertNotIn("Late", names)
        self.assertNotIn("finalmask", main_ob(out[0])["streamSettings"])
        self.assertIn("finalmask", main_ob(out[1])["streamSettings"])

    def test_advanced_keeps_classic_group_keys(self):
        out, _, _, problems = run({"list": [{"id": "f", "name": "F", "type": "balancer", "kinds": [CF],
            "advanced": {"group": {"name": "{split} Auto", "split_by": {"field": "flag", "regex": "(.+)"}, "params": {"expected": 2}},
                         "member_patch": [{"merge": {"mux": {"enabled": False}}}]}}]})
        self.assertEqual([p for p in problems if "blocks" in p], [])
        self.assertEqual(out[0]["remarks"], DE + " Auto")
        self.assertEqual(out[0]["routing"]["balancers"][0]["strategy"]["settings"], {"expected": 2})
        self.assertIs(main_ob(out[0])["mux"]["enabled"], False)
        _, problems = normalize({"blocks": {"list": [{"id": "x", "advanced": {"group": {"when": {}}}}]}})
        self.assertTrue(any("advanced" in p for p in problems))

    def test_order_follows_the_blocks(self):
        out, _, _, _ = run({"list": [
            {"id": "old", "kinds": [{"protocol": "vmess"}]},
            {"id": "reality", "kinds": [REALITY]},
        ]})
        self.assertEqual(out[0]["remarks"], "Old vmess 1")
        self.assertEqual([c["remarks"] for c in out[1:3]], ["DE" + DE + "Reality1", "DE" + DE + "Reality2"])

    def test_rest_hide(self):
        out, _, _, _ = run({"rest": "hide", "list": [{"id": "reality", "kinds": [REALITY]}]})
        self.assertEqual([c["remarks"] for c in out], ["DE" + DE + "Reality1", "DE" + DE + "Reality2"])

    def test_rest_top(self):
        out, _, _, _ = run({"rest": "top", "list": [{"id": "fast", "name": "Fast", "type": "balancer", "kinds": [CF]}]})
        self.assertEqual(out[0]["remarks"], "DE" + DE + "Reality1")
        self.assertEqual(out[-1]["remarks"], "Fast")

    def test_disabled_block_lets_its_configs_through(self):
        out, _, _, _ = run({"list": [{"id": "gone", "type": "drop", "enabled": False, "kinds": [TUNNEL]}]})
        self.assertEqual(len(out), 10)

    def test_per_country_without_flags_still_balances(self):
        configs = [cfg("fast-berlin-1"), cfg("fast-berlin-2"), cfg("Srv1" + DE + "CF"), cfg("other", network="tcp")]
        out, _, _, _ = run({"list": [{"id": "fast", "name": "Fast", "type": "balancer", "per_country": True,
                                      "kinds": [{"remark": {"regex": "^fast"}}, CF]}]}, configs)
        self.assertEqual([c["remarks"] for c in out], ["Fast", "Fast " + DE, "other"])
        out, _, _, _ = run({"list": [{"id": "fast", "name": "Fast", "type": "balancer", "per_country": True, "flagless": "single",
                                      "kinds": [{"remark": {"regex": "^fast"}}, CF]}]}, configs)
        self.assertEqual([c["remarks"] for c in out], ["fast-berlin-1", "fast-berlin-2", "Fast " + DE, "other"])

    def test_balancer_without_country_and_with_own_name(self):
        out, _, _, _ = run({"list": [{"id": "fast", "name": "Fast", "type": "balancer", "kinds": [CF],
                                      "settings": {"strategy": "random", "name": "{block} all"}}]})
        self.assertEqual(out[0]["remarks"], "Fast all")
        self.assertNotIn("burstObservatory", out[0])
        self.assertNotIn("observatory", out[0])

    def test_list_block_random_choices_and_classic_items_still_work(self):
        out, _, conf, _ = run({"list": [{"id": "cf", "kinds": [CF], "settings": {"cipher": ["semi-python"], "fragment": ["tlshello, 10-20, 1"]}}]},
                              rules=[{"id": "mine", "when": {"remark": {"startswith": "Old"}}, "do": "drop"}])
        self.assertEqual(conf["rules"][0]["id"], "mine")
        self.assertNotIn("Old vmess 1", [c["remarks"] for c in out])
        st = main_ob(out[0])["streamSettings"]
        self.assertEqual(st["tlsSettings"]["cipherSuites"], CIPHER_PRESETS["semi-python"])
        self.assertEqual(st["finalmask"]["tcp"], [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["10-20"], "delays": ["1"]}}])

    def test_problems(self):
        _, problems = normalize({"blocks": {"rest": "x", "list": [
            {"id": "a b"}, {"id": "t", "type": "bad"}, {"id": "p", "settings": {"pool": ["x"]}},
            {"id": "f", "settings": {"fragment": ["nope"]}}, {"id": "ok", "kinds": [{"remark": {"bad_op": 1}}]},
            {"id": "dup"}, {"id": "dup"},
        ]}})
        text = "\n".join(problems)
        for part in ("blocks.rest", "blocks.list[1].id", "blocks[t].type", "blocks[p].settings.pool: not available",
                     "blocks[f].settings.fragment", "unknown operator", "blocks[dup]: duplicate id"):
            self.assertIn(part, text)
        conf, _ = normalize({"blocks": {"list": [{"id": "fine", "type": "drop", "kinds": [TUNNEL]}]}})
        self.assertEqual([b["id"] for b in conf["blocks"]["list"]], ["fine"])
        self.assertEqual(conf["rules"][0]["id"], "blk-fine")

    def test_values(self):
        self.assertEqual(fragment_value("tlshello-0-len"), FRAGMENT_PRESETS["tlshello-0-len"])
        self.assertEqual(fragment_value("1-3, 5 10, 1, 4")[0]["settings"], {"packets": "1-3", "lengths": ["5", "10"], "delays": ["1"], "maxSplit": "4"})
        self.assertIsNone(fragment_value("only, two"))
        self.assertEqual(cipher_value("TLS_A:TLS_B"), "TLS_A:TLS_B")
        self.assertEqual(cipher_value("TLS_A TLS_B"), "TLS_A:TLS_B")
        self.assertIsNone(cipher_value("not a cipher"))


class MoreBlocks(unittest.TestCase):
    def test_list_name_and_patches(self):
        out, _, _, problems = run({"list": [{"id": "r", "name": "Reality", "kinds": [REALITY], "settings": {"name": "{block} {country} {n}"},
                                             "advanced": {"patches": [{"target": "outbound", "merge": {"mux": {"enabled": True}}}]}}]})
        self.assertEqual([p for p in problems if "blocks" in p], [])
        self.assertEqual([c["remarks"] for c in out[:2]], ["Reality " + DE + " 1", "Reality " + DE + " 2"])
        self.assertIs(main_ob(out[0])["mux"]["enabled"], True)
        self.assertNotIn("mux", main_ob(out[3]))

    def test_warp_block_becomes_an_exit_first_chain(self):
        conf, problems = normalize({"blocks": {"list": [
            {"id": "m", "name": "Masque", "type": "warp", "per_country": True, "kinds": [{"protocol": "masque"}],
             "settings": {"name": "{country}Masque", "pick": "per_user"}},
            {"id": "solo", "name": "Free", "type": "warp", "kinds": [{"remark": "IR"}], "settings": {"warp": "only"},
             "advanced": {"chain": {"entry_merge": {"streamSettings": {"sockopt": {"domainStrategy": "UseIP"}}}}}}]}})
        self.assertEqual([p for p in problems if "blocks" in p or "chains" in p], [])
        m, solo = conf["chains"]
        self.assertEqual((m["mode"], m["entry"], m["endpoints"], m["pick"], m["name"]),
                         ("exit_first", "{account.masque.outbound}", "{account.masque.endpoints}", "per_user", "{split}Masque"))
        self.assertEqual(m["split_by"], {"field": "flag", "regex": "(.+)"})
        self.assertIs(solo["exit"], False)
        self.assertIn("entry_merge", solo)
        _, problems = normalize({"blocks": {"list": [{"id": "x", "type": "warp", "settings": {"warp": "both"}, "advanced": {"chain": {"mode": "x"}}}]}})
        self.assertTrue(any("settings.warp" in p for p in problems) and any("advanced.chain" in p for p in problems))

    def test_warp_only_decoy_setting(self):
        conf, problems = normalize({"blocks": {"list": [
            {"id": "solo", "name": "Free", "type": "warp", "kinds": [{"remark": "IR"}], "settings": {"warp": "only", "decoy": "vless"}}]}})
        self.assertEqual([p for p in problems if "blocks" in p], [])
        before = conf["chains"][0]["before"][0]
        self.assertEqual((before["protocol"], before["tag"], before["streamSettings"]["security"]), ("vless", "decoy", "tls"))
        _, problems = normalize({"blocks": {"list": [{"id": "x", "type": "warp", "settings": {"decoy": "freedom"}}]}})
        self.assertTrue(any("settings.decoy" in p for p in problems))


class PatchRandom(unittest.TestCase):
    def test_random_in_patches(self):
        conf, problems = normalize({"patches": [{"id": "r", "target": "outbound", "random": {"mux.enabled": [True]}},
                                                {"id": "bad", "random": {"x": []}}]})
        self.assertTrue(any("patches[bad].random" in p for p in problems))
        out, _ = process(sample()[:1], conf)
        self.assertIs(main_ob(out[0])["mux"]["enabled"], True)


if __name__ == "__main__":
    unittest.main()


class BalancerLoadAndProbe(unittest.TestCase):
    def test_load_and_probe_reach_the_group(self):
        conf, problems = normalize({"blocks": {"list": [{"id": "t", "name": "Balancer", "type": "balancer", "per_country": True,
            "kinds": [{"remark": {"contains": "x"}}],
            "settings": {"load": {"expected": 2, "maxRTT": "2500ms"},
                         "probe": {"destination": "https://www.google.com/generate_204", "interval": "4h", "sampling": 4}}}]}})
        self.assertEqual([p for p in problems if "blocks" in p], [])
        g = next(x for x in conf["groups"] if x["id"].startswith("blk-t"))
        self.assertEqual(g["params"], {"expected": 2, "maxRTT": "2500ms"})
        self.assertEqual((g["probe"]["interval"], g["probe"]["sampling"]), ("4h", 4))
        _, problems = normalize({"blocks": {"list": [{"id": "t", "type": "balancer", "settings": {"load": {"expected": "x", "bogus": 1}}}]}})
        self.assertEqual(sum("settings.load" in p for p in problems), 2)


class StrategyParameters(unittest.TestCase):
    def group(self, settings):
        conf, problems = normalize({"blocks": {"list": [{"id": "t", "type": "balancer", "kinds": [{"remark": {"contains": "x"}}], "settings": settings}]}})
        return conf, [p for p in problems if "blocks" in p]

    def test_least_ping_uses_the_observatory_keys(self):
        conf, problems = self.group({"strategy": "leastPing"})
        self.assertEqual(problems, [])
        self.assertEqual(set(conf["groups"][0]["probe"]), {"probeUrl", "probeInterval"})
        conf, problems = self.group({"strategy": "leastPing", "probe": {"probeInterval": "10s", "enableConcurrency": True}})
        self.assertEqual((problems, conf["groups"][0]["probe"]["probeInterval"]), ([], "10s"))

    def test_wrong_keys_for_the_strategy(self):
        self.assertTrue(self.group({"strategy": "leastPing", "load": {"expected": 1}})[1])            # leastPing has no strategy settings
        self.assertTrue(self.group({"strategy": "leastPing", "probe": {"destination": "x"}})[1])      # that is a burstObservatory key
        self.assertTrue(self.group({"strategy": "random", "probe": {"interval": "1m"}})[1])
        self.assertEqual(self.group({"strategy": "leastLoad", "load": {"baselines": ["1s", "2s"], "tolerance": 0.01}})[1], [])


class MemberCost(unittest.TestCase):
    def test_cost_rules_reach_the_group(self):
        cost = [{"when": {"remark": {"contains": "GC-"}}, "value": 5}, {"value": 1}]
        conf, problems = normalize({"blocks": {"list": [{"id": "t", "type": "balancer", "kinds": [{"remark": {"contains": "x"}}],
                                                         "settings": {"cost": cost}}]}})
        self.assertEqual([p for p in problems if "blocks" in p], [])
        self.assertEqual(conf["groups"][0]["member_cost"], cost)
        _, problems = normalize({"blocks": {"list": [{"id": "t", "type": "balancer", "settings": {"strategy": "leastPing", "cost": cost}}]}})
        self.assertTrue(any("settings.cost" in p for p in problems))
        _, problems = normalize({"blocks": {"list": [{"id": "t", "type": "balancer", "settings": {"cost": [{"value": "x"}]}}]}})
        self.assertTrue(any("settings.cost" in p for p in problems))


class MemberPlacementAndPatch(unittest.TestCase):
    def build(self, settings):
        return normalize({"blocks": {"list": [{"id": "t", "type": "balancer", "kinds": [{"remark": {"contains": "x"}}], "settings": settings}]}})

    def test_settings_reach_the_group(self):
        pos = [{"when": {"remark": {"contains": "GC-"}}, "at": "last"}]
        patch = [{"when": {"network": "xhttp"}, "merge": {"streamSettings": {"sockopt": {"tcpFastOpen": True}}}}]
        rules = [{"port": "53", "network": "udp"}, {"network": "tcp,udp"}]
        conf, problems = self.build({"member_position": pos, "member_patch": patch, "catchall_rules": rules, "fingerprint": "chrome"})
        self.assertEqual([p for p in problems if "blocks" in p], [])
        g = conf["groups"][0]
        self.assertEqual((g["member_position"], g["catchall_rules"]), (pos, rules))
        self.assertEqual(g["member_patch"][-1], patch[0])          # after the fingerprint steps
        self.assertTrue(len(g["member_patch"]) > 1)

    def test_validation(self):
        for bad in ({"member_position": [{"at": "middle"}]}, {"member_patch": [{"merge": 3}]}, {"catchall_rules": []}):
            self.assertTrue([p for p in self.build(bad)[1] if "settings." in p], bad)


class ExpandAndEntryMerge(unittest.TestCase):
    def test_settings_reach_group_and_chain(self):
        ex = {"addresses": ["a.example.com", "b.example.com"], "copies": 2, "layout": "blocks", "server_by": {"field": "remark", "regex": "s(\\d)"}}
        conf, problems = normalize({"blocks": {"list": [
            {"id": "t", "type": "balancer", "kinds": [{"remark": {"contains": "x"}}], "settings": {"expand": ex}},
            {"id": "w", "type": "warp", "kinds": [{"remark": {"contains": "y"}}], "settings": {"warp": "only", "entry_merge": {"streamSettings": {"sockopt": {"domainStrategy": "UseIP"}}}}}]}})
        self.assertEqual([p for p in problems if "blocks" in p or "expand" in p or "entry_merge" in p], [])
        self.assertEqual(conf["groups"][0]["expand"], ex)
        self.assertEqual(conf["chains"][0]["entry_merge"]["streamSettings"]["sockopt"]["domainStrategy"], "UseIP")
        _, problems = normalize({"blocks": {"list": [{"id": "t", "type": "balancer", "settings": {"expand": []}}]}})
        self.assertTrue(any("settings.expand" in p for p in problems))


class PlacementSettings(unittest.TestCase):
    def test_balancer_and_warp_settings(self):
        conf, problems = normalize({"blocks": {"list": [
            {"id": "t", "type": "balancer", "kinds": [{"remark": {"contains": "x"}}],
             "settings": {"min_members": 3, "keep_members": True, "position": "bottom", "include_balanced": True, "probe_kind": "observatory"}},
            {"id": "w", "type": "warp", "kinds": [{"remark": {"contains": "y"}}], "settings": {"warp": "exit", "position": "top", "remove_exit": True}}]}})
        self.assertEqual([p for p in problems if "blocks" in p], [])
        g, c = conf["groups"][0], conf["chains"][0]
        self.assertEqual((g["min_members"], g["remove_members_from_output"], g["position"], g["include_balanced"], g["probe_kind"]),
                         (3, False, "bottom", True, "observatory"))
        self.assertEqual((c["position"], c["remove_exit_from_output"]), ("top", True))
        for bad in ({"min_members": 0}, {"position": "middle"}, {"keep_members": "yes"}, {"probe_kind": "x"}):
            _, problems = normalize({"blocks": {"list": [{"id": "t", "type": "balancer", "settings": bad}]}})
            self.assertTrue([p for p in problems if "settings." in p], bad)


class WarpAndListLeftovers(unittest.TestCase):
    def test_entry_choices_endpoints_and_patches(self):
        patch = {"stage": "output", "target": "outbound", "merge": {"mux": {"enabled": False}}, "routing_prepend": [{"type": "field", "domain": ["example.org"], "outboundTag": "direct"}]}
        conf, problems = normalize({"blocks": {"list": [
            {"id": "w", "type": "warp", "kinds": [{"remark": {"contains": "y"}}],
             "settings": {"choices": {"ep": ["1.1.1.1", "2.2.2.2"]}, "entry": "{account.masque.outbound}", "endpoints": ["a.example.com:443"]}},
            {"id": "l", "type": "list", "kinds": [{"remark": {"contains": "z"}}], "settings": {"patches": [patch]}}]}})
        self.assertEqual([p for p in problems if "blocks" in p], [])
        c = conf["chains"][0]
        self.assertEqual((c["choices"], c["endpoints"]), ({"ep": ["1.1.1.1", "2.2.2.2"]}, ["a.example.com:443"]))
        self.assertTrue(any(x.get("routing_prepend") and x["merge"] == {"mux": {"enabled": False}} for x in conf["patches"]))
        for bad in ({"choices": {"a": []}}, {"entry": "x"}, {"endpoints": "x"}):
            _, problems = normalize({"blocks": {"list": [{"id": "w", "type": "warp", "settings": bad}]}})
            self.assertTrue([p for p in problems if "settings." in p], bad)
