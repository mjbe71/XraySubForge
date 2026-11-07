"""Tests for chains in mode "exit_first": [exit, entry], the exit dialed through the entry, user's own id filled in."""
import copy
import unittest

from xraysubforge.config import normalize
from xraysubforge.engine import process

DE, TR = "\U0001F1E9\U0001F1EA", "\U0001F1F9\U0001F1F7"
UID = "11111111-1111-4111-8111-111111111111"


def vless(remark, uid=UID):
    return {"remarks": remark, "outbounds": [{"tag": "proxy", "protocol": "vless",
            "settings": {"address": "a.example", "port": 443, "id": uid}}], "routing": {"rules": []}}


def dummy(flag):
    return {"remarks": "Dummy" + flag, "inbounds": [{"tag": "socks"}], "routing": {"rules": [{"x": 1}]},
            "outbounds": [{"tag": "proxy", "protocol": "masque", "settings": {"address": "127.0.0.1"}}]}


ACCOUNT = {
    "masque": {"outbound": {"protocol": "masque", "settings": {"address": "0.0.0.0", "port": 443},
                            "streamSettings": {"sockopt": {"dialerProxy": "old"},
                                               "masqueSettings": {"warp": {"privateKey": "{account.privateKey}"}}}},
               "endpoints": ["1.1.1.1:2408", "[2606::1]:500", "3.3.3.3"]},
    "exits": {DE: {"protocol": "vless", "settings": {"address": "de.example", "port": 1, "id": ""},
                   "streamSettings": {"sockopt": {"domainStrategy": "UseIP"}}}},
    "exit": {"outbound": {"protocol": "vless", "settings": {"address": "any.example", "port": 2, "id": ""}}},
    "privateKey": "KEY",
}
CHAIN = {"id": "m", "mode": "exit_first", "exit_when": {"protocol": "masque"}, "split_by": {"field": "flag", "regex": "(.+)"},
         "name": "{split}TypeM", "entry": "{account.masque.outbound}", "endpoints": "{account.masque.endpoints}",
         "entry_merge": {"streamSettings": {"sockopt": {"domainStrategy": "UseIP"}}}}


def run(chain=CHAIN, panel=None, subid="u1", account=ACCOUNT):
    conf, problems = normalize({"chains": [chain]})
    assert not problems, problems
    out, report = process(copy.deepcopy(panel or [vless("n1"), dummy(DE), dummy(TR)]), conf, subid=subid, accounts={"default": account})
    return out, report


class ExitFirst(unittest.TestCase):
    def test_structure(self):
        out, rep = run()
        m = next(c for c in out if c["remarks"] == DE + "TypeM")
        exit_ob, entry = m["outbounds"]
        self.assertEqual(exit_ob["streamSettings"]["sockopt"], {"domainStrategy": "UseIP", "dialerProxy": entry["tag"]})
        self.assertEqual(exit_ob["settings"]["id"], UID)           # the user's own id
        self.assertEqual(exit_ob["settings"]["address"], "de.example")
        self.assertNotIn("dialerProxy", entry["streamSettings"]["sockopt"])
        self.assertEqual(entry["streamSettings"]["sockopt"]["domainStrategy"], "UseIP")
        self.assertEqual(entry["streamSettings"]["masqueSettings"]["warp"]["privateKey"], "KEY")
        self.assertNotIn("routing", m)
        self.assertEqual(m["inbounds"], [{"tag": "socks"}])        # the placeholder config is the base
        self.assertEqual(rep["errors"], [])

    def test_placeholders_removed_and_default_exit(self):
        out, _ = run()
        self.assertEqual([c["remarks"] for c in out], ["n1", DE + "TypeM", TR + "TypeM"])
        tr = out[2]
        self.assertEqual(tr["outbounds"][0]["settings"]["address"], "any.example")  # no TR template: the default exit

    def test_endpoint_from_pool(self):
        seen = set()
        for i in range(40):
            out, _ = run(subid="u%d" % i)
            e = out[1]["outbounds"][1]["settings"]
            seen.add((e["address"], e["port"]))
        self.assertEqual(seen, {("1.1.1.1", 2408), ("2606::1", 500), ("3.3.3.3", 443)})

    def test_per_user_pick_is_stable(self):
        chain = dict(CHAIN, pick="per_user")
        a = run(chain, subid="same")[0][1]["outbounds"][1]["settings"]
        b = run(chain, subid="same")[0][1]["outbounds"][1]["settings"]
        self.assertEqual(a, b)

    def test_no_user_id_is_an_error_not_a_crash(self):
        out, rep = run(panel=[dummy(DE)])
        self.assertEqual(out, [])
        self.assertTrue(rep["errors"])

    def test_most_frequent_id_wins(self):
        out, _ = run(panel=[vless("a", "x"), vless("b", UID), vless("c", UID), dummy(DE)])
        self.assertEqual(next(c for c in out if c["remarks"] == DE + "TypeM")["outbounds"][0]["settings"]["id"], UID)

    def test_validation(self):
        _, p = normalize({"chains": [dict(CHAIN, mode="x", pick="y", exit={"bad": 1})]})
        self.assertEqual(len([x for x in p if "skipped" not in x]), 3)


if __name__ == "__main__":
    unittest.main()


SOLO = {"id": "s", "mode": "exit_first", "exit": False, "exit_when": {"remark": {"iregex": "^ir$"}}, "name": "Solo",
        "entry": "{account.masque.outbound}", "endpoints": "{account.masque.endpoints}",
        "before": [{"protocol": "vless", "tag": "decoy", "settings": {"address": "{entry.address}", "port": "{entry.port}", "id": "{user.id}"}}]}


class Solo(unittest.TestCase):
    def test_solo_with_front_outbound(self):
        out, rep = run(SOLO, panel=[vless("n1"), dummy("x")] + [dict(dummy("x"), remarks="IR")])
        solo = next(c for c in out if c["remarks"] == "Solo")
        self.assertEqual([o["tag"] for o in solo["outbounds"]], ["decoy", "s-0-entry"])
        decoy = solo["outbounds"][0]["settings"]
        self.assertEqual((decoy["id"], decoy["address"]), (UID, solo["outbounds"][1]["settings"]["address"]))
        self.assertEqual(solo["routing"]["rules"][0]["outboundTag"], "s-0-entry")
        self.assertNotIn("IR", [c["remarks"] for c in out])
        self.assertEqual(rep["errors"], [])

    def test_catchall_survives_replace_routing_and_marker_is_removed(self):
        conf, _ = normalize({"chains": [SOLO], "output": {"replace_routing": True}})
        out, _ = process([vless("n1"), dict(dummy("x"), remarks="IR")], conf, accounts={"default": ACCOUNT})
        rules = next(c for c in out if c["remarks"] == "Solo")["routing"]["rules"]
        self.assertEqual(rules, [{"type": "field", "network": "tcp,udp", "outboundTag": "s-0-entry"}])


class Pool(unittest.TestCase):
    def test_pool_account_is_stable_and_personal_wins(self):
        acc = dict(ACCOUNT, pool=[{"privateKey": "K%d" % i} for i in range(5)])
        conf, _ = normalize({"chains": [CHAIN]})
        keys = set()
        for i in range(30):
            out, _ = process([vless("n1"), dummy(DE)], conf, subid="u%d" % i, accounts={"default": acc})
            keys.add(out[1]["outbounds"][1]["streamSettings"]["masqueSettings"]["warp"]["privateKey"])
        self.assertEqual(keys, {"K%d" % i for i in range(5)})
        a = process([vless("n1"), dummy(DE)], conf, subid="same", accounts={"default": acc})[0][1]
        b = process([vless("n1"), dummy(DE)], conf, subid="same", accounts={"default": acc})[0][1]
        self.assertEqual(a["outbounds"][1]["streamSettings"]["masqueSettings"], b["outbounds"][1]["streamSettings"]["masqueSettings"])
        mine = process([vless("n1"), dummy(DE)], conf, subid="same",
                       accounts={"default": acc, "users": {"same": {"privateKey": "MINE"}}})[0][1]
        self.assertEqual(mine["outbounds"][1]["streamSettings"]["masqueSettings"]["warp"]["privateKey"], "MINE")


class OptionalPlaceholder(unittest.TestCase):
    def test_account_keys_fill_the_template_and_missing_ones_stay(self):
        chain = dict(CHAIN, entry_merge={"streamSettings": {"masqueSettings": {"warp": {
            "privateKey": "{account.privateKey?}", "publicKey": "{account.publicKey?}", "address": "{account.address?}"}}}})
        acc = copy.deepcopy(ACCOUNT)
        acc["masque"]["outbound"]["streamSettings"]["masqueSettings"]["warp"] = {"privateKey": "T", "publicKey": "PUB"}
        del acc["privateKey"]
        out, rep = run(chain, account=acc)                                  # no personal values: the template's own stay
        w = out[1]["outbounds"][1]["streamSettings"]["masqueSettings"]["warp"]
        self.assertEqual((w["privateKey"], w["publicKey"], rep["errors"]), ("T", "PUB", []))
        self.assertNotIn("address", w)
        conf, _ = normalize({"chains": [chain]})
        out, _ = process([vless("n1"), dummy(DE)], conf, subid="u", accounts={"default": acc, "users": {"u": {"privateKey": "MINE", "address": ["1.2.3.4"]}}})
        w = out[1]["outbounds"][1]["streamSettings"]["masqueSettings"]["warp"]
        self.assertEqual((w["privateKey"], w["publicKey"], w["address"]), ("MINE", "PUB", ["1.2.3.4"]))
