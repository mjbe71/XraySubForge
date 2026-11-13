"""Loading, checking and hot-reloading config.json.

Every behaviour of the service comes from this file; with an empty file the service passes subscriptions
through unchanged. A broken value is ignored (and reported), a broken file keeps the previous settings.
Keys starting with an underscore are comments and are ignored anywhere.
"""
import copy
import json
import os
import re
import sys
import threading

from .matching import check_catchall, check_hops, check_member_patch, check_member_position, check_when

CONFIG_ENV = "XRAYSUBFORGE_CONFIG"

DEFAULTS = {
    "server": {
        "host": "127.0.0.1", "port": 8080,
        "route": "/sub/",                        # public path; the subscription id is appended
        "raw_route": "/raw/", "clash_route": "/clash/",  # public paths of the pass-through formats (empty = off)
        "subid_regex": r"^[A-Za-z0-9_-]{4,64}$",  # ids that don't match get a 404 without asking the panel
        "workers": 2, "threads": 4,              # used by gunicorn.conf.py
        "tls_cert": "", "tls_key": "",           # serve HTTPS directly: paths of the certificate (fullchain) and key
        "hosts": [],                             # host names that choose this profile when several profiles share a path (see profiles.py)
        "domains": [],                           # more names, each with its own certificate: [{"name", "cert", "key"}] (see tlsctx.py)
    },
    "panel": {
        "mode": "engine",                        # "engine": apply your rules; "proxy": hand the panel's reply through unchanged
        "url": "",                               # JSON-subscription URL of your panel, the id is appended
        "raw_url": "", "clash_url": "",          # the panel's raw / clash subscription URLs; when set they are passed through as they are
        "source": "json",                        # "json": read panel.url; "raw": build the JSON configs from the links at panel.raw_url
        "raw_mode": "pass",                      # the raw route: "pass" hands the panel's links through, "engine" applies the rules to them
        "json_template": {},                     # source "raw": the client config each link is put into (empty = a built-in one)
        "page_url": "",                          # optional: browsers (Accept: text/html) are redirected here
        "timeout": 10, "verify_tls": True, "headers": {},
        "pass_headers": ["Profile-Title", "Profile-Update-Interval", "Subscription-Userinfo",
                         "Profile-Web-Page-Url", "Support-Url", "Announce", "Content-Disposition"],
    },
    "admin": {
        "path": "/admin",                        # web admin panel; it stays OFF until a password is set
        "password": "", "password_hash": "",      # use password_hash (python -m xraysubforge hash-password)
        "session_hours": 12,
        "max_failed_logins": 5, "lockout_seconds": 300,
    },
    "accounts": {
        "file": "",                              # JSON file with account values for {account.*} placeholders
        "default": {},                           # ...or put a shared account right here
        "register": {                            # optional: create a Cloudflare WARP account for each user automatically
            "enabled": False,                    # needs accounts.file (the accounts are saved there under "users")
            "api": "", "client_version": "",     # empty = built-in values (the unofficial Cloudflare client API)
            "retry_seconds": 600,                # after a failed attempt wait this long before trying again
            "background": False,                 # true: register in a background thread; the request never waits for the API
            "min_interval_seconds": 0,           # least time between two registrations (be gentle with the API)
            "max_users": 0,                      # stop creating personal accounts at this many (0 = no limit)
        },
        "prune": {                               # optional: remove the personal accounts of users the panel no longer has
            "enabled": False,                    # true: check about once per `interval_hours` (needs accounts.file)
            "after_days": 3,                     # remove an account once its user has been missing this many days (0 = at once)
            "max_percent": 50,                   # with 10+ users: more than this share missing in one check = remove nothing
            "interval_hours": 24,                # time between two automatic checks
        },
    },
    "rules": [],
    "groups": [],
    "chains": [],
    "patches": [],
    "output": {},
    "order": [],
    "blocks": {"rest": "keep", "list": []},          # the block layout (see blocks.py); compiled into the lists above
}

RULE_ACTIONS = ("keep", "drop", "pin_top", "pin_bottom")


def _log(msg):
    print("[config] " + msg, file=sys.stderr, flush=True)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _regex_ok(v):
    try:
        re.compile(v)
        return isinstance(v, str)
    except (re.error, TypeError):
        return False


def _url_ok(v):
    return isinstance(v, str) and (v == "" or v.startswith(("http://", "https://")))


SECTION_CHECKS = {
    "server": {
        "host": (lambda v: isinstance(v, str) and v != "", "a non-empty string"),
        "port": (lambda v: _is_int(v) and 1 <= v <= 65535, "an integer 1-65535"),
        "route": (lambda v: isinstance(v, str) and v.startswith("/"), "a string starting with /"),
        "raw_route": (lambda v: isinstance(v, str) and (v == "" or v.startswith("/")), "a string starting with / (or empty)"),
        "clash_route": (lambda v: isinstance(v, str) and (v == "" or v.startswith("/")), "a string starting with / (or empty)"),
        "subid_regex": (_regex_ok, "a valid regular expression"),
        "workers": (lambda v: _is_int(v) and v >= 1, "an integer >= 1"),
        "threads": (lambda v: _is_int(v) and v >= 1, "an integer >= 1"),
        "tls_cert": (lambda v: isinstance(v, str), "a file path (string)"),
        "tls_key": (lambda v: isinstance(v, str), "a file path (string)"),
        "hosts": (lambda v: isinstance(v, list) and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9.-]+", x) for x in v),
                  "a list of host names"),
        "domains": (lambda v: isinstance(v, list) and all(
            isinstance(d, dict) and isinstance(d.get("name"), str) and re.fullmatch(r"(\*\.)?[A-Za-z0-9.-]+", d["name"] or "")
            and set(d) <= {"name", "cert", "key"} and bool(d.get("cert")) == bool(d.get("key"))
            and all(isinstance(d.get(k, ""), str) for k in ("cert", "key")) for d in v),
            'a list of {"name": "sub.example.com", "cert": "...", "key": "..."} (cert and key both or neither)'),
    },
    "panel": {
        "mode": (lambda v: v in ("engine", "proxy"), '"engine" or "proxy"'),
        "url": (_url_ok, "an http(s) URL or an empty string"),
        "raw_url": (_url_ok, "an http(s) URL or an empty string"),
        "source": (lambda v: v in ("json", "raw"), '"json" or "raw"'),
        "raw_mode": (lambda v: v in ("pass", "engine"), '"pass" or "engine"'),
        "json_template": (lambda v: isinstance(v, dict) and (not v or isinstance(v.get("outbounds", []), list)), "an object (a client config)"),
        "clash_url": (_url_ok, "an http(s) URL or an empty string"),
        "page_url": (_url_ok, "an http(s) URL or an empty string"),
        "timeout": (lambda v: _is_num(v) and v > 0, "a number > 0"),
        "verify_tls": (lambda v: isinstance(v, bool), "true or false"),
        "headers": (lambda v: isinstance(v, dict) and all(isinstance(a, str) and isinstance(b, str) for a, b in v.items()),
                    "an object of strings"),
        "pass_headers": (lambda v: isinstance(v, list) and all(isinstance(a, str) for a in v), "a list of strings"),
    },
    "admin": {
        "path": (lambda v: isinstance(v, str) and v.startswith("/") and len(v) > 1, "a string starting with /"),
        "password": (lambda v: isinstance(v, str), "a string"),
        "password_hash": (lambda v: isinstance(v, str), "a string"),
        "session_hours": (lambda v: _is_num(v) and v > 0, "a number > 0"),
        "max_failed_logins": (lambda v: _is_int(v) and v >= 1, "an integer >= 1"),
        "lockout_seconds": (lambda v: _is_num(v) and v > 0, "a number > 0"),
    },
    "accounts": {
        "file": (lambda v: isinstance(v, str), "a file path (string)"),
        "default": (lambda v: isinstance(v, dict), "an object"),
        "register": (lambda v: isinstance(v, dict), "an object"),
        "prune": (lambda v: isinstance(v, dict), "an object"),
    },
}

PRUNE_CHECKS = {
    "enabled": (lambda v: isinstance(v, bool), "true or false"),
    "after_days": (lambda v: _is_num(v) and v >= 0, "a number >= 0"),
    "max_percent": (lambda v: _is_num(v) and 0 < v <= 100, "a number from 1 to 100"),
    "interval_hours": (lambda v: _is_num(v) and v >= 1, "a number >= 1"),
}

REGISTER_CHECKS = {
    "enabled": (lambda v: isinstance(v, bool), "true or false"),
    "api": (lambda v: isinstance(v, str), "a string"),
    "client_version": (lambda v: isinstance(v, str), "a string"),
    "retry_seconds": (lambda v: _is_num(v) and v >= 0, "a number >= 0"),
    "background": (lambda v: isinstance(v, bool), "true or false"),
    "min_interval_seconds": (lambda v: _is_num(v) and v >= 0, "a number >= 0"),
    "max_users": (lambda v: _is_int(v) and v >= 0, "an integer >= 0"),
}

ITEM_KEYS = {
    "rules": {"id", "enabled", "when", "do"},
    "groups": {"id", "enabled", "when", "split_by", "name", "type", "params", "probe", "probe_kind",
               "member_cost", "min_members", "remove_members_from_output", "position", "expand", "include_balanced", "member_position", "catchall_rules", "member_patch",
               "member_tag", "balancer_tag"},
    "chains": {"id", "enabled", "exit_when", "split_by", "name", "entry", "choices", "through_exit",
               "remove_exit_from_output", "position", "mode", "exit", "endpoints", "pick", "entry_merge", "before",
               "entry_tag", "exit_tag", "account", "hops", "each"},
    "order": {"id", "enabled", "when", "rank"},
    "patches": {"id", "enabled", "stage", "target", "when", "merge", "random", "rename", "routing_prepend", "routing_append", "routing_early"},
}


def _section(name, raw, conf, problems):
    if raw is None:
        return
    if not isinstance(raw, dict):
        problems.append("%s: must be an object; ignored" % name)
        return
    for k, v in raw.items():
        if k.startswith("_"):
            continue
        check = SECTION_CHECKS[name].get(k)
        if check is None:
            problems.append("%s.%s: unknown key; ignored" % (name, k))
        elif not check[0](v):
            problems.append("%s.%s: must be %s; ignored" % (name, k, check[1]))
        else:
            conf[name][k] = copy.deepcopy(v)


def _check_item(kind, item, where):
    p = []
    for k in item:
        if k not in ITEM_KEYS[kind] and not k.startswith("_"):
            p.append("%s: unknown key %r" % (where, k))
    if "enabled" in item and not isinstance(item["enabled"], bool):
        p.append("%s.enabled: must be true or false" % where)
    p += check_when(item.get("when"), where + ".when")
    if kind == "chains":
        p += check_when(item.get("exit_when"), where + ".exit_when")
    if kind == "rules":
        if item.get("do") not in RULE_ACTIONS:
            p.append("%s.do: must be one of %s" % (where, ", ".join(RULE_ACTIONS)))
    elif kind == "groups":
        if not isinstance(item.get("type"), str) or not item.get("type"):
            p.append("%s.type: required (e.g. leastLoad, leastPing, random, roundRobin)" % where)
        sb = item.get("split_by")
        if sb is not None:
            if not (isinstance(sb, dict) and isinstance(sb.get("field"), str) and _regex_ok(sb.get("regex"))):
                p.append('%s.split_by: must be {"field": "...", "regex": "..."} with a valid regex' % where)
        for k in ("params", "probe"):
            if k in item and not isinstance(item[k], dict):
                p.append("%s.%s: must be an object" % (where, k))
        if "name" in item and not isinstance(item["name"], str):
            p.append("%s.name: must be a string" % where)
        if item.get("probe_kind") not in (None, "burst", "observatory"):
            p.append('%s.probe_kind: must be "burst" or "observatory"' % where)
        if "min_members" in item and not (_is_int(item["min_members"]) and item["min_members"] >= 1):
            p.append("%s.min_members: must be an integer >= 1" % where)
        if "remove_members_from_output" in item and not isinstance(item["remove_members_from_output"], bool):
            p.append("%s.remove_members_from_output: must be true or false" % where)
        if item.get("position") not in (None, "top", "bottom"):
            p.append('%s.position: must be "top" or "bottom"' % where)
        if "include_balanced" in item and not isinstance(item["include_balanced"], bool):
            p.append("%s.include_balanced: must be true or false" % where)
        for key, check in (("member_position", check_member_position), ("member_patch", check_member_patch), ("catchall_rules", check_catchall)):
            if item.get(key) is not None:
                p += check(item[key], "%s.%s" % (where, key))
        ex = item.get("expand")
        if ex is not None:
            w = where + ".expand"
            if not isinstance(ex, dict):
                p.append("%s: must be an object" % w)
            else:
                for k in ex:
                    if k not in ("copies", "server_by", "addresses", "address_regex", "when", "pick", "layout") and not k.startswith("_"):
                        p.append("%s: unknown key %r" % (w, k))
                if not (_is_int(ex.get("copies")) and ex["copies"] >= 1):
                    p.append("%s.copies: required, an integer >= 1" % w)
                sb = ex.get("server_by")
                if sb is not None and not (isinstance(sb, dict) and isinstance(sb.get("field"), str) and _regex_ok(sb.get("regex"))):
                    p.append('%s.server_by: must be {"field": "...", "regex": "..."} with a valid regex' % w)
                ad = ex.get("addresses")
                if ad is not None and not (isinstance(ad, list) and ad and all(isinstance(a, str) and a for a in ad)):
                    p.append("%s.addresses: must be a non-empty list of strings" % w)
                if ex.get("address_regex") is not None and not _regex_ok(ex.get("address_regex")):
                    p.append("%s.address_regex: must be a valid regex" % w)
                if ex.get("layout") not in (None, "grouped", "blocks"):
                    p.append('%s.layout: must be "grouped" or "blocks"' % w)
                if ex.get("pick") not in (None, "random", "per_user"):
                    p.append('%s.pick: must be "random" or "per_user"' % w)
                p += check_when(ex.get("when"), w + ".when")
        mc = item.get("member_cost")
        if mc is not None:
            if not isinstance(mc, list):
                p.append("%s.member_cost: must be a list" % where)
            else:
                for i, e in enumerate(mc):
                    if not (isinstance(e, dict) and _is_num(e.get("value"))):
                        p.append('%s.member_cost[%d]: needs {"when": {...}, "value": number}' % (where, i))
                    else:
                        p += check_when(e.get("when"), "%s.member_cost[%d].when" % (where, i))
    elif kind == "chains":
        en = item.get("entry")
        if item.get("mode") == "hops":
            p += check_hops(item.get("hops"), where + ".hops")
        elif not ((isinstance(en, dict) and en) or (isinstance(en, str) and re.fullmatch(r"\{account\.[A-Za-z0-9_.\-]+\}", en))):
            p.append("%s.entry: required; the outbound (JSON object, or one {account.x} placeholder) to dial through the exit" % where)
        if item.get("mode") not in (None, "entry_first", "exit_first", "hops"):
            p.append('%s.mode: must be "entry_first", "exit_first" or "hops"' % where)
        if "each" in item and not isinstance(item["each"], bool):
            p.append("%s.each: must be true or false" % where)
        if item.get("pick") not in (None, "random", "per_user"):
            p.append('%s.pick: must be "random" or "per_user"' % where)
        ex = item.get("exit")
        if ex is not None and ex is not False and not (isinstance(ex, dict) and all(k in ("from_account", "default_account", "user_id") for k in ex)):
            p.append('%s.exit: must be false (entry only) or {"from_account": "exits", "default_account": "exit", "user_id": true}' % where)
        if "before" in item and not (isinstance(item["before"], list) and all(isinstance(o, dict) for o in item["before"])):
            p.append("%s.before: must be a list of outbounds" % where)
        if "entry_merge" in item and not isinstance(item["entry_merge"], dict):
            p.append("%s.entry_merge: must be an object" % where)
        epv = item.get("endpoints")
        if epv is not None and not (isinstance(epv, list) or (isinstance(epv, str) and epv.startswith("{account."))):
            p.append("%s.endpoints: must be a list or one {account.x} placeholder" % where)
        sb = item.get("split_by")
        if sb is not None and not (isinstance(sb, dict) and isinstance(sb.get("field"), str) and _regex_ok(sb.get("regex"))):
            p.append('%s.split_by: must be {"field": "...", "regex": "..."} with a valid regex' % where)
        if "name" in item and not isinstance(item["name"], str):
            p.append("%s.name: must be a string" % where)
        ch = item.get("choices")
        if ch is not None and not (isinstance(ch, dict) and all(isinstance(v, list) and v for v in ch.values())):
            p.append('%s.choices: must be an object of non-empty lists, e.g. {"endpoint": ["1.2.3.4", "5.6.7.8"]}' % where)
        for k in ("through_exit", "remove_exit_from_output"):
            if k in item and not isinstance(item[k], bool):
                p.append("%s.%s: must be true or false" % (where, k))
        if item.get("position") not in (None, "top", "bottom"):
            p.append('%s.position: must be "top" or "bottom"' % where)
    elif kind == "order":
        if not _is_num(item.get("rank")):
            p.append("%s.rank: required, a number (smaller = higher in the list)" % where)
    elif kind == "patches":
        if item.get("stage", "source") not in ("source", "output"):
            p.append('%s.stage: must be "source" or "output"' % where)
        if item.get("target", "config") not in ("config", "outbound"):
            p.append('%s.target: must be "config" or "outbound"' % where)
        if "merge" in item and not isinstance(item["merge"], dict):
            p.append("%s.merge: must be an object" % where)
        if "rename" in item and not isinstance(item["rename"], str):
            p.append("%s.rename: must be a string ({name}, {country}, {n})" % where)
        rnd = item.get("random")
        if rnd is not None and not (isinstance(rnd, dict) and all(isinstance(v, list) and v for v in rnd.values())):
            p.append("%s.random: must be an object of non-empty lists (path -> choices)" % where)
        for k in ("routing_prepend", "routing_append", "routing_early"):
            if k in item and not (isinstance(item[k], list) and all(isinstance(r, dict) for r in item[k])):
                p.append("%s.%s: must be a list of objects" % (where, k))
    return p


def _items(kind, raw, conf, problems):
    if raw is None:
        return
    if not isinstance(raw, list):
        problems.append("%s: must be a list; ignored" % kind)
        return
    seen = set()
    for n, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            problems.append("%s[%d]: must be an object; skipped" % (kind, n))
            continue
        item = copy.deepcopy(item)
        item.setdefault("id", "%s%d" % (kind[:-1], n))
        where = "%s[%s]" % (kind, item["id"])
        if not isinstance(item["id"], str) or not item["id"]:
            problems.append("%s[%d].id: must be a non-empty string; skipped" % (kind, n))
            continue
        if item["id"] in seen:
            problems.append("%s: duplicate id; skipped" % where)
            continue
        found = _check_item(kind, item, where)
        fatal = [x for x in found if "unknown key" not in x]
        problems += found
        if fatal:
            problems.append("%s: skipped" % where)
            continue
        seen.add(item["id"])
        conf[kind].append(item)


def normalize(raw):
    """raw JSON value -> (clean configuration, list of problem messages)."""
    conf, problems = copy.deepcopy(DEFAULTS), []
    if not isinstance(raw, dict):
        return conf, ["the top level must be a JSON object; using defaults"]
    for k in raw:
        if k not in DEFAULTS and not k.startswith("_"):
            problems.append("%s: unknown key; ignored" % k)
    _section("server", raw.get("server"), conf, problems)
    if bool(conf["server"]["tls_cert"]) != bool(conf["server"]["tls_key"]):
        problems.append("server.tls_cert and server.tls_key: set both or neither; HTTPS stays off")
        conf["server"]["tls_cert"] = conf["server"]["tls_key"] = ""
    _section("panel", raw.get("panel"), conf, problems)
    _section("admin", raw.get("admin"), conf, problems)
    _section("accounts", raw.get("accounts"), conf, problems)
    taken = {conf["server"]["route"].rstrip("/"), conf["admin"]["path"].rstrip("/")}
    for key in ("raw_route", "clash_route"):                       # each public path must be its own
        path = conf["server"][key].rstrip("/")
        if path and path in taken:
            problems.append("server.%s: already used by another path; this format stays off" % key)
            conf["server"][key] = ""
        elif path:
            taken.add(path)
    def sub_section(name, checks):
        out = dict(DEFAULTS["accounts"][name])
        given = conf["accounts"][name]
        if isinstance(given, dict) and given is not DEFAULTS["accounts"][name]:
            for k, v in given.items():
                check = checks.get(k)
                if check is None:
                    if not k.startswith("_"):
                        problems.append("accounts.%s.%s: unknown key; ignored" % (name, k))
                elif not check[0](v):
                    problems.append("accounts.%s.%s: must be %s; ignored" % (name, k, check[1]))
                else:
                    out[k] = v
        conf["accounts"][name] = out
        return out
    reg = sub_section("register", REGISTER_CHECKS)
    prune = sub_section("prune", PRUNE_CHECKS)
    if prune["enabled"] and not conf["accounts"]["file"]:
        problems.append("accounts.prune: needs accounts.file; it stays off")
        prune["enabled"] = False
    if reg["enabled"] and not conf["accounts"]["file"]:
        problems.append("accounts.register: needs accounts.file to save the accounts; automatic registration stays off")
        reg["enabled"] = False
    if conf["admin"]["password"] and not conf["admin"]["password_hash"]:
        problems.append("admin.password: stored in plain text; consider admin.password_hash "
                        "(python -m xraysubforge hash-password)")
    for kind in ("rules", "groups", "chains", "patches", "order"):
        _items(kind, raw.get(kind), conf, problems)
    from .blocks import compile_blocks
    conf["blocks"], made, bproblems = compile_blocks(raw.get("blocks"))
    problems += bproblems
    extra = {k: [] for k in made}
    for kind, generated in made.items():   # checked like hand-written items; they run after your own ones
        _items(kind, generated, extra, problems)
    for kind in ("rules", "groups", "chains", "patches"):
        conf[kind] += extra[kind]
    conf["order"] = extra["order"] + conf["order"]
    out = raw.get("output")
    if out is not None:
        if not isinstance(out, dict):
            problems.append("output: must be an object; ignored")
        else:
            from .output import check_output
            problems += check_output(out)
            conf["output"] = copy.deepcopy({k: v for k, v in out.items() if not k.startswith("_")})
    for g in conf["groups"]:
        if g["type"] in ("leastLoad", "leastPing") and not g.get("probe"):
            problems.append("groups[%s]: type %s normally needs a `probe` (observatory); clients may reject it without"
                            % (g["id"], g["type"]))
    return conf, problems


def is_warning(problem):
    """Problems that do not stop anything from working (everything else means something was ignored/skipped)."""
    return "unknown key" in problem or "normally needs" in problem or "plain text" in problem


def split_problems(problems):
    return [p for p in problems if not is_warning(p)], [p for p in problems if is_warning(p)]


class ConfigStore:
    """Holds the current configuration and re-reads the file when it changes (checked on every get())."""

    def __init__(self, path=None):
        self.path = path or os.environ.get(CONFIG_ENV) or "config.json"
        self._lock = threading.Lock()
        self._sig = None
        self._conf, self.problems = normalize({})
        self.load(force=True)

    def get(self):
        self.load()
        return self._conf

    def load(self, force=False):
        with self._lock:
            try:
                st = os.stat(self.path)
            except OSError:
                if force:
                    _log("%s not found; using defaults (subscriptions pass through unchanged)" % self.path)
                return
            sig = (st.st_mtime_ns, st.st_size)
            if sig == self._sig and not force:
                return
            self._sig = sig
            try:
                with open(self.path, encoding="utf-8") as f:
                    raw = json.load(f)
            except (OSError, ValueError) as e:
                _log("cannot read %s (%s); keeping the previous settings" % (self.path, e))
                return
            conf, problems = normalize(raw)
            for p in problems:
                _log(p)
            self._conf, self.problems = conf, problems
            _log("loaded %s (%d rule(s), %d group(s), %d chain(s), %d patch(es))" % (
                self.path, len(conf["rules"]), len(conf["groups"]), len(conf["chains"]), len(conf["patches"])))
