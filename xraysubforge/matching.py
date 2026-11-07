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
FIELDS = ("remark", "protocol", "tag", "address", "port", "network", "security", "sni", "host", "path", "flag")


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
