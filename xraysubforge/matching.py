"""Reading facts about a config and evaluating `when` conditions.

A `when` object is a set of tests that must ALL pass (an empty or missing `when` matches everything):

    {"remark": {"contains": "fast"}, "network": "xhttp"}          # field tests (a plain value means "equals")
    {"any": [ {...}, {...} ]}   {"all": [ {...} ]}   {"not": {...}}   # combinators

Nothing here knows any naming scheme: it only looks at what the panel sent.
"""
import re
from functools import lru_cache

# a "main" outbound is the first one that actually carries traffic to a server
NON_PROXY = ("freedom", "blackhole", "dns", "loopback")
FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")

# fields that are always available in `when` / `split_by` (anything else can be reached with a dotted path)
FIELDS = ("remark", "protocol", "tag", "address", "port", "network", "security", "sni", "host", "path", "flag", "made_by")


@lru_cache(maxsize=512)
def _rx(pattern, flags=0):
    return re.compile(pattern, flags)


def dig(obj, path):
    """obj['a']['b'][0]['c'] from 'a.b.0.c'; None when anything is missing."""
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
        if cur is None:
            return None
    return cur


def main_index(cfg):
    obs = cfg.get("outbounds")
    if isinstance(obs, list):
        for i, ob in enumerate(obs):
            if isinstance(ob, dict) and ob.get("protocol") not in NON_PROXY:
                return i
    return None


def _first(*vals):
    for v in vals:
        if v not in (None, ""):
            return v
    return None


def fields_of(cfg):
    """The facts a rule can test, read from the config's main outbound."""
    f = {"remark": str(cfg.get("remarks") or "")}
    m = FLAG_RE.search(f["remark"])
    f["flag"] = m.group(0) if m else None
    f["made_by"] = cfg.get("_by")      # the group or chain that built this config (None for the panel's own configs)
    i = main_index(cfg)
    if i is None:
        return f
    ob = cfg["outbounds"][i]
    s = ob.get("settings") if isinstance(ob.get("settings"), dict) else {}
    vnext = (s.get("vnext") or [{}])[0] if isinstance(s.get("vnext"), list) and s.get("vnext") else {}
    servers = (s.get("servers") or [{}])[0] if isinstance(s.get("servers"), list) and s.get("servers") else {}
    st = ob.get("streamSettings") if isinstance(ob.get("streamSettings"), dict) else {}
    net = st.get("network") or "tcp"
    sec = st.get("security") or "none"
    net_s = st.get(net + "Settings") if isinstance(st.get(net + "Settings"), dict) else {}
    tls = st.get("tlsSettings") if isinstance(st.get("tlsSettings"), dict) else {}
    rea = st.get("realitySettings") if isinstance(st.get("realitySettings"), dict) else {}
    headers = net_s.get("headers") if isinstance(net_s.get("headers"), dict) else {}
    f.update({
        "protocol": ob.get("protocol"),
        "tag": ob.get("tag"),
        "address": _first(s.get("address"), vnext.get("address"), servers.get("address")),
        "port": _first(s.get("port"), vnext.get("port"), servers.get("port")),
        "network": net,
        "security": sec,
        "sni": _first(tls.get("serverName"), rea.get("serverName")),
        "host": _first(net_s.get("host"), headers.get("Host"), headers.get("host")),
        "path": _first(net_s.get("path"), net_s.get("serviceName")),
    })
    return f


def get_value(cfg, fields, name):
    if name in fields:
        return fields[name]
    if "." in name:
        return dig(cfg, name)
    return None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _s(v):
    return "" if v is None else str(v)


# operator -> function(value, argument) -> bool; `value` is None when the field is missing
OPS = {
    "equals": lambda v, a: v is not None and _s(v) == _s(a),
    "not_equals": lambda v, a: v is None or _s(v) != _s(a),
    "contains": lambda v, a: v is not None and _s(a) in _s(v),
    "icontains": lambda v, a: v is not None and _s(a).lower() in _s(v).lower(),
    "not_contains": lambda v, a: v is None or _s(a) not in _s(v),
    "startswith": lambda v, a: v is not None and _s(v).startswith(_s(a)),
    "endswith": lambda v, a: v is not None and _s(v).endswith(_s(a)),
    "regex": lambda v, a: v is not None and _rx(_s(a)).search(_s(v)) is not None,
    "iregex": lambda v, a: v is not None and _rx(_s(a), re.I).search(_s(v)) is not None,
    "in": lambda v, a: v is not None and _s(v) in [_s(x) for x in a],
    "not_in": lambda v, a: v is None or _s(v) not in [_s(x) for x in a],
    "exists": lambda v, a: (v not in (None, "")) == bool(a),
    "gt": lambda v, a: _num(v) is not None and _num(v) > _num(a),
    "gte": lambda v, a: _num(v) is not None and _num(v) >= _num(a),
    "lt": lambda v, a: _num(v) is not None and _num(v) < _num(a),
    "lte": lambda v, a: _num(v) is not None and _num(v) <= _num(a),
}


def match(when, cfg, fields=None):
    if not when:
        return True
    fields = fields if fields is not None else fields_of(cfg)
    for key, val in when.items():
        if key.startswith("_"):
            continue
        if key == "all":
            ok = all(match(w, cfg, fields) for w in val)
        elif key == "any":
            ok = any(match(w, cfg, fields) for w in val)
        elif key == "not":
            ok = not match(val, cfg, fields)
        else:
            value = get_value(cfg, fields, key)
            cond = val if isinstance(val, dict) else {"equals": val}
            ok = all(OPS[op](value, arg) for op, arg in cond.items())
        if not ok:
            return False
    return True


def check_when(when, where):
    """Problems found in a `when` object (empty list = fine)."""
    if when is None:
        return []
    if not isinstance(when, dict):
        return ["%s: must be an object" % where]
    problems = []
    for key, val in when.items():
        if key.startswith("_"):
            continue
        if key in ("all", "any"):
            if not isinstance(val, list):
                problems.append("%s.%s: must be a list" % (where, key))
            else:
                for i, w in enumerate(val):
                    problems += check_when(w, "%s.%s[%d]" % (where, key, i))
        elif key == "not":
            problems += check_when(val, "%s.not" % where)
        else:
            cond = val if isinstance(val, dict) else {"equals": val}
            for op, arg in cond.items():
                if op not in OPS:
                    problems.append("%s.%s: unknown operator %r (known: %s)" % (where, key, op, ", ".join(OPS)))
                elif op in ("regex", "iregex"):
                    try:
                        re.compile(str(arg))
                    except re.error as e:
                        problems.append("%s.%s: bad regex (%s)" % (where, key, e))
                elif op in ("in", "not_in") and not isinstance(arg, list):
                    problems.append("%s.%s.%s: must be a list" % (where, key, op))
    return problems


def check_member_position(mp, where):
    """[{"when": {...}, "at": "first"|"last"}] -> list of problems."""
    if not isinstance(mp, list):
        return ["%s: must be a list" % where]
    p = []
    for i, e in enumerate(mp):
        if not (isinstance(e, dict) and e.get("at") in ("first", "last")):
            p.append('%s[%d]: needs {"when": {...}, "at": "first" or "last"}' % (where, i))
        else:
            p += check_when(e.get("when"), "%s[%d].when" % (where, i))
    return p


def check_member_patch(mpt, where):
    """[{"when", "merge", "random"}] -> list of problems."""
    if not isinstance(mpt, list):
        return ["%s: must be a list" % where]
    p = []
    for i, e in enumerate(mpt):
        w = "%s[%d]" % (where, i)
        if not isinstance(e, dict):
            p.append("%s: must be an object" % w)
            continue
        for k in e:
            if k not in ("when", "merge", "random") and not k.startswith("_"):
                p.append("%s: unknown key %r" % (w, k))
        p += check_when(e.get("when"), w + ".when")
        if "merge" in e and not isinstance(e["merge"], dict):
            p.append("%s.merge: must be an object" % w)
        rnd = e.get("random")
        if rnd is not None and not (isinstance(rnd, dict) and all(isinstance(v, list) and v for v in rnd.values())):
            p.append('%s.random: must be {"dotted.path": [option, ...]}' % w)
    return p


def check_catchall(cr, where):
    if not (isinstance(cr, list) and cr and all(isinstance(r, dict) for r in cr)):
        return ["%s: must be a non-empty list of routing rules (the balancer tag is filled in)" % where]
    if any(r.get("position", "end") not in ("end", "early") for r in cr):
        return ['%s: "position" must be "end" (default) or "early"' % where]
    return []


HOP_KEYS = {
    "block": set(),
    "warp": {"account", "pick", "entry", "endpoints", "merge"},
    "outbound": {"outbound"},
    "config": {"when"},
}


def check_hops(hops, where):
    """The hops of a chain in "hops" mode: client -> hops[0] -> hops[1] -> ... -> the internet."""
    if not (isinstance(hops, list) and 1 <= len(hops) <= 4 and all(isinstance(h, dict) for h in hops)):
        return ["%s: must be a list of 1 to 4 hops" % where]
    p = []
    for n, hop in enumerate(hops):
        w = "%s[%d]" % (where, n)
        kind = hop.get("from")
        if kind not in HOP_KEYS:
            p.append("%s.from: must be one of %s" % (w, ", ".join(sorted(HOP_KEYS))))
            continue
        for k in hop:
            if k != "from" and k not in HOP_KEYS[kind] and not k.startswith("_"):
                p.append("%s: unknown key %r" % (w, k))
        if kind == "warp":
            if hop.get("account", "personal") not in ("personal", "shared"):
                p.append('%s.account: must be "personal" or "shared"' % w)
            if hop.get("pick", "random") not in ("random", "per_user"):
                p.append('%s.pick: must be "random" or "per_user"' % w)
            en = hop.get("entry")
            if en is not None and not ((isinstance(en, dict) and en) or (isinstance(en, str) and re.fullmatch(r"\{account\.[A-Za-z0-9_.\-]+\}", en))):
                p.append("%s.entry: an outbound object, or one {account.x} placeholder" % w)
            ep = hop.get("endpoints")
            if ep is not None and not ((isinstance(ep, list) and ep and all(isinstance(x, str) for x in ep)) or (isinstance(ep, str) and ep.startswith("{account."))):
                p.append("%s.endpoints: a list of addresses, or one {account.x} placeholder" % w)
            if "merge" in hop and not isinstance(hop["merge"], dict):
                p.append("%s.merge: must be an object" % w)
        elif kind == "outbound":
            ob = hop.get("outbound")
            one = isinstance(ob, dict) and isinstance(ob.get("protocol"), str) and ob["protocol"]
            many = isinstance(ob, dict) and ob and not ob.get("protocol") and all(
                isinstance(k, str) and k and isinstance(v, dict) and isinstance(v.get("protocol"), str) and v["protocol"] for k, v in ob.items())
            if not (one or many):
                p.append('%s.outbound: required; an Xray outbound object with a protocol, or {"<flag>": outbound, ..., "default": outbound}' % w)
        elif kind == "config":
            if not (isinstance(hop.get("when"), dict) and hop["when"]):
                p.append("%s.when: required; which config of the subscription to use" % w)
            else:
                p += check_when(hop["when"], w + ".when")
    if sum(1 for h in hops if h.get("from") == "block") > 1:
        p.append("%s: only one hop can be the block's own configs" % where)
    return p
