"""The block layout: the final subscription as an ordered list of blocks, each taking some kinds of configs.

    "blocks": {
      "rest": "keep",                                   # "top" or "hide": configs no block takes
      "list": [
        {"id": "fast", "name": "Fast", "type": "balancer", "per_country": true,
         "kinds": [{"remark": {"contains": "CF"}, "network": "xhttp"}],
         "settings": {"fragment": ["tlshello-0-len", "tlshello-6-98"], "cipher": ["semi-python"], "load": {"expected": 2, "maxRTT": "2500ms"},
                      "fingerprint": "chrome", "strategy": "leastLoad", "pool": ["a.example.com"],
                      "name": "{block} {country}"}},
        {"id": "gone", "type": "drop", "kinds": [{"remark": {"contains": "test"}}]}
      ]
    }

compile_blocks() turns this into ordinary rules, groups, patches and order items, so the engine itself does not change.
A config belongs to at most one list or drop block: the first such block (from the top) whose kinds match it.
Balancer blocks do not reserve their kinds: several balancers may use the same configs (for example the same
servers once plain and once with fragment); a list block further down does not get configs an earlier list or
drop block took.
"""
import copy
import re

from .matching import check_catchall, check_hops, check_member_patch, check_member_position, check_when

BLOCK_TYPES = ("list", "balancer", "warp", "chain", "drop")
BLOCK_KEYS = {"id", "name", "type", "kinds", "per_country", "flagless", "settings", "enabled", "advanced"}
# group keys a balancer block may carry as they are (kept when a classic group is turned into a block)
ADVANCED_GROUP_KEYS = {"params", "probe", "probe_kind", "member_cost", "min_members", "remove_members_from_output", "position",
                       "expand", "include_balanced", "member_position", "catchall_rules", "name", "split_by"}
LIST_SETTINGS = {"fragment", "cipher", "fingerprint", "name"}
MEMBER_TAG = "proxy"          # plain outbound tags in what a block builds: proxy01, proxy02, ... / balancer / warp
BALANCER_SETTINGS = LIST_SETTINGS | {"strategy", "pool", "load", "probe", "cost", "member_position", "member_patch", "catchall_rules", "expand",
                                          "min_members", "keep_members", "position", "include_balanced", "probe_kind"}
# leastLoad parameters ("load": the strategy's settings) and how members are probed ("probe"). Xray has two probes:
# leastLoad reads burstObservatory.pingConfig, leastPing reads observatory; leastPing has no strategy settings.
LOAD_KEYS = {"expected": int, "maxRTT": str, "tolerance": float, "baselines": list}
PROBE_KEYS = {"leastLoad": {"destination": str, "connectivity": str, "interval": str, "sampling": int, "timeout": str, "httpMethod": str},
              "leastPing": {"probeUrl": str, "probeInterval": str, "enableConcurrency": bool}}
WARP_SETTINGS = {"warp", "pick", "name", "decoy", "entry_merge", "position", "remove_exit", "choices", "entry", "endpoints", "account", "rules"}
# a chain block: its configs go through the hops in settings.hops (client -> hop 1 -> hop 2 -> the internet)
CHAIN_SETTINGS = {"hops", "name", "decoy", "choices", "rules"}
DEFAULT_HOPS = [{"from": "warp"}, {"from": "block"}]
# "decoy": "vless" puts an unused vless+TLS outbound in front of a WARP-only entry (some apps only load a masque config then)
WARP_DECOY = [{"protocol": "vless", "tag": "decoy",
               "settings": {"address": "{entry.address}", "port": "{entry.port}", "id": "{user.id}", "encryption": "none"},
               "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "www.cloudflare.com"}}}]
# chain keys a WARP block may carry as they are (kept when a classic chain is turned into a block)
ADVANCED_CHAIN_KEYS = {"entry", "endpoints", "exit", "entry_merge", "before", "choices", "remove_exit_from_output", "position", "name", "split_by"}
PATCH_KEYS = {"stage", "target", "when", "merge", "random", "routing_prepend", "routing_append"}
STRATEGIES = ("leastLoad", "leastPing", "random", "roundRobin")
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "unsafe")
PREFIX = "blk-"
FRAG_PATH = "streamSettings.finalmask.tcp"
CIPHER_PATH = "streamSettings.tlsSettings.cipherSuites"
DEFAULT_PROBE = {"destination": "https://www.gstatic.com/generate_204", "interval": "30s"}          # leastLoad (burstObservatory)
DEFAULT_PING_PROBE = {"probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s"}   # leastPing (observatory)
_ID = re.compile(r"^[A-Za-z0-9_-]{1,40}$")

# the shared preset names (the same ones 3x-ui offers for hosts)
_TAIL = {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}


def _head(a, b):
    return {"type": "fragment", "settings": {"packets": "tlshello", "lengths": [a, b, "1"], "delays": ["0"], "maxSplit": "0"}}


FRAGMENT_PRESETS = {
    "tlshello-0-len": [_head("0", "104"), _TAIL],
    "tlshello-6-98": [_head("6", "98"), _TAIL],
}
CIPHER_PRESETS = {
    "semi-python": ":".join([
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"]),
    "real-firefox": ":".join([
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"]),
}


def fragment_value(item):
    """A fragment choice -> the finalmask.tcp list, or None. A preset name, a raw list of masks,
    or "packets, lengths, delays[, maxSplit]" (lengths and delays may hold several values separated by spaces)."""
    if isinstance(item, list) and item and all(isinstance(m, dict) for m in item):
        return item
    if not isinstance(item, str):
        return None
    if item in FRAGMENT_PRESETS:
        return FRAGMENT_PRESETS[item]
    parts = [p.strip() for p in item.split(",")]
    if len(parts) not in (3, 4) or not all(parts):
        return None
    st = {"packets": parts[0], "lengths": parts[1].split(), "delays": parts[2].split()}
    if len(parts) == 4:
        st["maxSplit"] = parts[3]
    return [{"type": "fragment", "settings": st}]


def cipher_value(item):
    """A cipher choice -> the colon-separated list, or None. A preset name or the list itself."""
    if not isinstance(item, str) or not item.strip():
        return None
    if item in CIPHER_PRESETS:
        return CIPHER_PRESETS[item]
    names = [n for n in re.split(r"[:\s,]+", item) if n]
    return ":".join(names) if names and all(re.fullmatch(r"[A-Z0-9_]+", n) for n in names) else None


def _check_block(b, where):
    p = []
    for k in b:
        if k not in BLOCK_KEYS and not k.startswith("_"):
            p.append("%s: unknown key %r" % (where, k))
    if b.get("type", "list") not in BLOCK_TYPES:
        p.append("%s.type: must be one of %s" % (where, ", ".join(BLOCK_TYPES)))
    if "enabled" in b and not isinstance(b["enabled"], bool):
        p.append("%s.enabled: must be true or false" % where)
    if "name" in b and not isinstance(b["name"], str):
        p.append("%s.name: must be a string" % where)
    if "per_country" in b and not isinstance(b["per_country"], bool):
        p.append("%s.per_country: must be true or false" % where)
    if b.get("flagless", "own") not in ("own", "single"):
        p.append('%s.flagless: must be "own" (one balancer of their own) or "single" (left as they are)' % where)
    kinds = b.get("kinds", [])
    if not isinstance(kinds, list):
        p.append("%s.kinds: must be a list of conditions" % where)
    else:
        for i, w in enumerate(kinds):
            if not isinstance(w, dict):
                p.append("%s.kinds[%d]: must be a condition object" % (where, i))
            else:
                p += check_when(w, "%s.kinds[%d]" % (where, i))
    adv = b.get("advanced")
    btype = b.get("type", "list")
    allowed_adv = {"balancer": ("group", "member_patch"), "list": ("patches",), "warp": ("chain",)}.get(btype, ())
    if adv is not None:
        if not isinstance(adv, dict) or not allowed_adv:
            p.append("%s.advanced: must be an object (not for drop blocks)" % where)
        else:
            for k in adv:
                if k not in allowed_adv:
                    p.append("%s.advanced: %r is not available for a %s block (only %s)" % (where, k, btype, ", ".join(allowed_adv)))
            g = adv.get("group", {})
            if not isinstance(g, dict) or any(k not in ADVANCED_GROUP_KEYS for k in g):
                p.append("%s.advanced.group: may hold only %s" % (where, ", ".join(sorted(ADVANCED_GROUP_KEYS))))
            c = adv.get("chain", {})
            if not isinstance(c, dict) or any(k not in ADVANCED_CHAIN_KEYS for k in c):
                p.append("%s.advanced.chain: may hold only %s" % (where, ", ".join(sorted(ADVANCED_CHAIN_KEYS))))
            if not isinstance(adv.get("member_patch", []), list):
                p.append("%s.advanced.member_patch: must be a list" % where)
            pt = adv.get("patches", [])
            if not (isinstance(pt, list) and all(isinstance(x, dict) and all(k in PATCH_KEYS for k in x) for x in pt)):
                p.append("%s.advanced.patches: a list of patches (%s)" % (where, ", ".join(sorted(PATCH_KEYS))))
    s = b.get("settings", {})
    if not isinstance(s, dict):
        return p + ["%s.settings: must be an object" % where]
    allowed = {"balancer": BALANCER_SETTINGS, "list": LIST_SETTINGS | {"patches", "rules"}, "warp": WARP_SETTINGS, "chain": CHAIN_SETTINGS}.get(btype, set())
    for k in s:
        if k not in allowed:
            p.append("%s.settings.%s: not available for a %s block" % (where, k, b.get("type", "list")))
    for key, conv in (("fragment", fragment_value), ("cipher", cipher_value)):
        if key in s:
            v = s[key]
            if not (isinstance(v, list) and v and all(conv(x) is not None for x in v)):
                p.append("%s.settings.%s: must be a list of preset names (%s) or your own values"
                         % (where, key, ", ".join(FRAGMENT_PRESETS if key == "fragment" else CIPHER_PRESETS)))
    if "fingerprint" in s and s["fingerprint"] not in FINGERPRINTS:
        p.append("%s.settings.fingerprint: must be one of %s" % (where, ", ".join(FINGERPRINTS)))
    if "strategy" in s and s["strategy"] not in STRATEGIES:
        p.append("%s.settings.strategy: must be one of %s" % (where, ", ".join(STRATEGIES)))
    strat = s.get("strategy", "leastLoad")
    for key, spec in (("load", LOAD_KEYS), ("probe", PROBE_KEYS.get(strat))):
        if key not in s:
            continue
        if spec is None or (key == "load" and strat != "leastLoad"):
            p.append("%s.settings.%s: not used by the %s strategy" % (where, key, strat))
            continue
        v = s[key]
        if not isinstance(v, dict):
            p.append("%s.settings.%s: must be an object" % (where, key))
            continue
        for k, x in v.items():
            typ = spec.get(k)
            if typ is None:
                p.append("%s.settings.%s.%s: unknown key" % (where, key, k))
                continue
            if typ is list:
                ok = isinstance(x, list) and all(isinstance(y, str) and y.strip() for y in x)
            elif typ is bool:
                ok = isinstance(x, bool)
            else:
                ok = isinstance(x, (int, float) if typ is float else typ) and not isinstance(x, bool) \
                    and (typ is not int or x >= 0) and (typ is not str or bool(x.strip()))
            if not ok:
                p.append("%s.settings.%s.%s: wrong value" % (where, key, k))
    if "cost" in s:
        c = s["cost"]
        if strat != "leastLoad":
            p.append("%s.settings.cost: only the leastLoad strategy uses costs" % where)
        elif not (isinstance(c, list) and all(isinstance(e, dict) and set(e) <= {"when", "value"} and isinstance(e.get("value"), (int, float))
                                              and not isinstance(e.get("value"), bool) and e["value"] >= 0 for e in c)):
            p.append('%s.settings.cost: must be a list of {"when": {...}, "value": number}; the first rule that matches a member wins, a rule without "when" is the default' % where)
        else:
            for n, e in enumerate(c):
                p += check_when(e.get("when"), "%s.settings.cost[%d].when" % (where, n)) if "when" in e else []
    for key, check in (("member_position", check_member_position), ("member_patch", check_member_patch), ("catchall_rules", check_catchall)):
        if key in s:
            p += check(s[key], "%s.settings.%s" % (where, key))
    if "min_members" in s and not (isinstance(s["min_members"], int) and not isinstance(s["min_members"], bool) and s["min_members"] >= 1):
        p.append("%s.settings.min_members: must be a whole number, 1 or more" % where)
    for key in ("keep_members", "include_balanced", "remove_exit"):
        if key in s and not isinstance(s[key], bool):
            p.append("%s.settings.%s: must be true or false" % (where, key))
    if "position" in s and s["position"] not in ("top", "bottom"):
        p.append('%s.settings.position: must be "top" or "bottom"' % where)
    if "probe_kind" in s and s["probe_kind"] not in ("burst", "observatory"):
        p.append('%s.settings.probe_kind: must be "burst" or "observatory"' % where)
    if "patches" in s:
        pt = s["patches"]
        if not (isinstance(pt, list) and all(isinstance(x, dict) and all(k in PATCH_KEYS for k in x) for x in pt)):
            p.append("%s.settings.patches: a list of patches (%s)" % (where, ", ".join(sorted(PATCH_KEYS))))
    if "choices" in s and not (isinstance(s["choices"], dict) and all(isinstance(v, list) and v for v in s["choices"].values())):
        p.append("%s.settings.choices: must be an object of non-empty lists" % where)
    if "entry" in s and not ((isinstance(s["entry"], dict) and s["entry"]) or (isinstance(s["entry"], str) and re.fullmatch(r"\{account\.[A-Za-z0-9_.\-]+\}", s["entry"]))):
        p.append("%s.settings.entry: an outbound object, or one {account.x} placeholder" % where)
    if "endpoints" in s and not ((isinstance(s["endpoints"], list) and s["endpoints"] and all(isinstance(x, str) for x in s["endpoints"]))
                                 or (isinstance(s["endpoints"], str) and s["endpoints"].startswith("{account."))):
        p.append("%s.settings.endpoints: a list of addresses, or one {account.x} placeholder" % where)
    for key in ("expand", "entry_merge"):
        if key in s and not isinstance(s[key], dict):
            p.append("%s.settings.%s: must be an object" % (where, key))
    if "pool" in s and not (isinstance(s["pool"], list) and s["pool"] and all(isinstance(a, str) and a.strip() for a in s["pool"])):
        p.append("%s.settings.pool: must be a list of addresses" % where)
    if "name" in s and not isinstance(s["name"], str):
        p.append("%s.settings.name: must be a string" % where)
    if "warp" in s and s["warp"] not in ("exit", "only"):
        p.append('%s.settings.warp: must be "exit" (WARP, then the exit) or "only" (WARP alone)' % where)
    if "decoy" in s and s["decoy"] != "vless":
        p.append('%s.settings.decoy: must be "vless"' % where)
    if "hops" in s:
        p += check_hops(s["hops"], "%s.settings.hops" % where)
    if "account" in s and s["account"] not in ("personal", "shared"):
        p.append('%s.settings.account: must be "personal" (each user their own account) or "shared" (the default account)' % where)
    if "rules" in s and not (isinstance(s["rules"], list) and s["rules"] and all(isinstance(r, dict) for r in s["rules"])):
        p.append("%s.settings.rules: must be a non-empty list of routing rules" % where)
    elif "rules" in s:
        for r in s["rules"]:
            if r.get("position", "end") not in ("end", "early"):
                p.append('%s.settings.rules: "position" must be "end" (default) or "early" (before the private / domestic rules, after the DNS rules)' % where)
                break
    if "pick" in s and s["pick"] not in ("random", "per_user"):
        p.append('%s.settings.pick: must be "random" or "per_user"' % where)
    return p


def _tuning(s, claim=None):
    """The fingerprint / cipher / fragment settings as patch-like steps: [(when, merge, random)]."""
    steps = []
    fp = s.get("fingerprint")
    if fp:
        steps.append(({"security": "tls"}, {"streamSettings": {"tlsSettings": {"fingerprint": fp}}}, None))
        steps.append(({"security": "reality"}, {"streamSettings": {"realitySettings": {"fingerprint": fp}}}, None))
    if s.get("cipher"):
        steps.append(({"security": "tls"}, None, {CIPHER_PATH: [cipher_value(x) for x in s["cipher"]]}))
    if s.get("fragment"):
        steps.append((None, None, {FRAG_PATH: [fragment_value(x) for x in s["fragment"]]}))
    return steps


def _name(template, block_name, per_country):
    t = template or ("{block} {country}" if per_country else "{block}")
    return t.replace("{block}", block_name).replace("{country}", "{split}" if per_country else "").strip()


def compile_blocks(raw):
    """raw `blocks` value -> (clean blocks, {"rules": [...], "groups": [...], "patches": [...], "order": [...]}, problems)."""
    out = {"rules": [], "groups": [], "chains": [], "patches": [], "order": []}
    if raw is None:
        return {"rest": "keep", "list": []}, out, []
    if not isinstance(raw, dict):
        return {"rest": "keep", "list": []}, out, ["blocks: must be an object; ignored"]
    problems = []
    for k in raw:
        if k not in ("rest", "list") and not k.startswith("_"):
            problems.append("blocks.%s: unknown key; ignored" % k)
    rest = raw.get("rest", "keep")
    if rest not in ("keep", "top", "hide"):
        problems.append('blocks.rest: must be "keep", "top" or "hide"; using "keep"')
        rest = "keep"
    items = raw.get("list", [])
    if not isinstance(items, list):
        return {"rest": rest, "list": []}, out, problems + ["blocks.list: must be a list; ignored"]

    clean, seen, taken, everything = [], set(), [], []
    for n, b in enumerate(items, 1):
        if not isinstance(b, dict):
            problems.append("blocks.list[%d]: must be an object; skipped" % n)
            continue
        bid = b.get("id", "block%d" % n)
        where = "blocks[%s]" % bid
        if not isinstance(bid, str) or not _ID.match(bid):
            problems.append("blocks.list[%d].id: letters, digits, - and _ only (at most 40); skipped" % n)
            continue
        if bid in seen:
            problems.append("%s: duplicate id; skipped" % where)
            continue
        found = _check_block(b, where)
        problems += found
        if [x for x in found if "unknown key" not in x]:
            problems.append("%s: skipped" % where)
            continue
        seen.add(bid)
        clean.append(dict(b, id=bid))
        if not b.get("enabled", True):
            continue

        kinds = list(b.get("kinds") or [])
        claim = {"all": [{"any": kinds}, {"not": {"any": list(taken)}}]} if taken else {"any": kinds}
        everything += kinds
        if b.get("type", "list") != "balancer":     # balancers share; list, WARP and drop blocks reserve
            taken += kinds
        rank = len(out["order"]) + 1
        s, btype, gid = b.get("settings") or {}, b.get("type", "list"), PREFIX + bid
        not_ours = {"made_by": {"exists": False}}       # a config of the panel, not one a group or chain built

        def own_rules(when, s=s, gid=gid):              # settings.rules: routing rules in front; no target = this block's proxy
            if s.get("rules"):
                rules = [dict({"type": "field"}, **{k: copy.deepcopy(v) for k, v in r.items() if v not in ([], "", None)}) for r in s["rules"]]
                for r in rules:
                    if not r.get("outboundTag") and not r.get("balancerTag"):
                        r["outboundTag"] = "{main}"
                early = [r for r in rules if r.get("position") == "early"]     # "position" is ours, not an Xray key
                for r in rules:
                    r.pop("position", None)
                patch = {"id": gid + "-rules", "stage": "output", "when": when,
                         "routing_append": [r for r in rules if not any(r is e for e in early)]}
                if early:
                    patch["routing_early"] = early
                out["patches"].append(patch)

        if btype == "drop":
            out["rules"].append({"id": gid, "when": claim, "do": "drop"})
            continue
        if btype == "list":
            for i, (w, merge, rnd) in enumerate(_tuning(s), 1):
                patch = {"id": "%s-%d" % (gid, i), "stage": "source", "target": "outbound",
                         "when": {"all": [claim, w]} if w else claim}
                if merge:
                    patch["merge"] = merge
                if rnd:
                    patch["random"] = rnd
                out["patches"].append(patch)
            for i, extra in enumerate(copy.deepcopy(s.get("patches") or []) + list((b.get("advanced") or {}).get("patches") or []), 1):
                patch = dict(extra, id="%s-adv%d" % (gid, i))
                patch["when"] = {"all": [claim, extra["when"]]} if extra.get("when") else claim
                out["patches"].append(patch)
            if s.get("name"):    # {name} = the config's own name, {country} = its flag, {n} = its number in the block
                out["patches"].append({"id": gid + "-name", "stage": "output", "when": {"all": [claim, not_ours]},
                                       "rename": s["name"].replace("{block}", b.get("name") or bid)})
            own_rules({"all": [claim, not_ours]})
            out["order"].append({"id": gid, "when": {"all": [claim, not_ours]}, "rank": rank})
            continue
        if btype == "chain":
            hops = copy.deepcopy(s.get("hops") or DEFAULT_HOPS)
            tmpl = s.get("name") or ("{block} {country}" if b.get("per_country") else "{name}")
            chain = {"id": gid, "mode": "hops", "exit_when": claim, "hops": hops,
                     "name": tmpl.replace("{block}", b.get("name") or bid)}
            if b.get("per_country"):
                chain["split_by"] = {"field": "flag", "regex": "(.+)"}
            if s.get("decoy") == "vless":
                chain["before"] = copy.deepcopy(WARP_DECOY)
            if s.get("choices"):
                chain["choices"] = copy.deepcopy(s["choices"])
            out["chains"].append(chain)
            own_rules({"made_by": gid})
            out["order"].append({"id": gid, "when": {"made_by": gid}, "rank": rank})
            continue
        if btype == "warp":
            chain = {"id": gid, "mode": "exit_first", "exit_when": claim, "entry": "{account.masque.outbound}",
                     "endpoints": "{account.masque.endpoints}", "pick": s.get("pick", "random"),
                     "entry_tag": "warp", "exit_tag": MEMBER_TAG + "01",
                     "name": _name(s.get("name"), b.get("name") or bid, b.get("per_country", False))}
            if b.get("per_country"):
                chain["split_by"] = {"field": "flag", "regex": "(.+)"}
            if s.get("warp") == "only":
                chain["exit"] = False
                if s.get("decoy") == "vless":
                    chain["before"] = copy.deepcopy(WARP_DECOY)
            for key in ("choices", "entry", "endpoints"):
                if s.get(key):
                    chain[key] = copy.deepcopy(s[key])
            if s.get("position"):
                chain["position"] = s["position"]
            if s.get("remove_exit"):
                chain["remove_exit_from_output"] = True
            if s.get("account") == "shared":
                chain["account"] = "shared"
            if isinstance(s.get("entry_merge"), dict) and s["entry_merge"]:
                chain["entry_merge"] = copy.deepcopy(s["entry_merge"])
            chain.update((b.get("advanced") or {}).get("chain") or {})
            out["chains"].append(chain)
            own_rules({"made_by": gid})
            out["order"].append({"id": gid, "when": {"made_by": gid}, "rank": rank})
            continue

        strategy = s.get("strategy", "leastLoad")
        group = {"id": gid, "when": claim, "type": strategy, "member_tag": MEMBER_TAG,
                 "name": _name(s.get("name"), b.get("name") or bid, b.get("per_country", False))}
        if strategy == "leastLoad":
            group["probe"] = dict(DEFAULT_PROBE)
        elif strategy == "leastPing":
            group["probe"] = dict(DEFAULT_PING_PROBE)
        if s.get("probe") and "probe" in group:
            group["probe"].update(s["probe"])
        if s.get("load"):
            group["params"] = dict(s["load"])
        if s.get("cost"):
            group["member_cost"] = copy.deepcopy(s["cost"])
        if b.get("per_country"):
            group["split_by"] = {"field": "flag", "regex": "(.+)"}
        steps = []
        for w, merge, rnd in _tuning(s):
            step = {}
            if w:
                step["when"] = w
            if merge:
                step["merge"] = merge
            if rnd:
                step["random"] = rnd
            steps.append(step)
        steps += copy.deepcopy(s.get("member_patch") or [])
        if steps:
            group["member_patch"] = steps
        if s.get("member_position"):
            group["member_position"] = copy.deepcopy(s["member_position"])
        if s.get("catchall_rules"):
            group["catchall_rules"] = copy.deepcopy(s["catchall_rules"])
        if s.get("pool"):
            group["expand"] = {"addresses": list(s["pool"]), "copies": len(s["pool"]), "pick": "random"}
        if s.get("min_members"):
            group["min_members"] = s["min_members"]
        if s.get("keep_members"):
            group["remove_members_from_output"] = False
        if s.get("position"):
            group["position"] = s["position"]
        if s.get("include_balanced"):
            group["include_balanced"] = True
        if s.get("probe_kind"):
            group["probe_kind"] = s["probe_kind"]
        if isinstance(s.get("expand"), dict) and s["expand"]:
            group["expand"] = copy.deepcopy(s["expand"])      # the full form wins over the plain address pool
        adv = b.get("advanced") or {}
        group.update(adv.get("group") or {})            # kept as they were (a converted classic group)
        if adv.get("member_patch"):
            group["member_patch"] = list(group.get("member_patch") or []) + list(adv["member_patch"])
        out["groups"].append(group)
        if b.get("per_country") and b.get("flagless", "own") == "own":   # configs without a flag: a balancer of their own
            rest_group = dict(group, id=gid + "--noflag", when={"all": [claim, {"flag": {"exists": False}}]},
                              name=_name(s.get("name"), b.get("name") or bid, False) if not s.get("name") else
                              s["name"].replace("{block}", b.get("name") or bid).replace("{country}", "").strip())
            rest_group.pop("split_by")
            out["groups"].append(rest_group)
        out["order"].append({"id": gid, "when": {"made_by": {"in": [gid, gid + "--noflag"]}}, "rank": rank})
        out["order"].append({"id": gid + "-single", "when": {"all": [claim, not_ours]}, "rank": rank})

    if rest == "top" and clean:
        out["order"].append({"id": PREFIX + "rest", "when": {"all": [{"not": {"any": list(everything)}},
                                                                     {"made_by": {"exists": False}}]}, "rank": 0})
    if rest == "hide" and clean:
        out["rules"].append({"id": PREFIX + "rest", "when": {"not": {"any": list(everything)}}, "do": "drop"})
    return {"rest": rest, "list": clean}, out, problems
