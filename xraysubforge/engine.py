"""Applies the admin's rules, groups, chains and patches to the configs the panel returned.

Order of work:  patches(stage "source")  ->  rules  ->  groups  ->  chains  ->  patches(stage "output")

Nothing here is specific to any naming scheme or provider. With an empty configuration the input comes
back unchanged.
"""
import copy
import hashlib
import random
import re
import sys

from .matching import NON_PROXY, dig, fields_of, get_value, main_index, match

SHOWN = ("protocol", "address", "port", "network", "security", "sni", "flag")


def _log(msg):
    print("[engine] " + msg, file=sys.stderr, flush=True)


def deep_merge(dst, src):
    """Merge dict `src` into `dst`. A null value deletes the key; lists and scalars are replaced."""
    for k, v in src.items():
        if v is None:
            dst.pop(k, None)
        elif isinstance(v, dict):
            fresh = not isinstance(dst.get(k), dict)
            if fresh:
                dst[k] = {}
            deep_merge(dst[k], v)
            if fresh and not dst[k] and v:  # only deletions were asked for: do not leave an empty object behind
                del dst[k]
        else:
            dst[k] = copy.deepcopy(v)
    return dst


def set_path(obj, path, value):
    """obj["a"]["b"] = value for 'a.b', creating the objects on the way."""
    parts = str(path).split(".")
    for part in parts[:-1]:
        if not isinstance(obj.get(part), dict):
            obj[part] = {}
        obj = obj[part]
    obj[parts[-1]] = value


def slug(text):
    return re.sub(r"[^A-Za-z0-9]+", "-", str(text)).strip("-") or "g"


def render(template, **values):
    for k, v in values.items():
        template = template.replace("{" + k + "}", str(v))
    return template


def apply_patch(cfg, patch):
    merge = patch.get("merge") or {}
    rnd = patch.get("random") or {}
    if patch.get("target", "config") == "outbound":
        for ob in cfg.get("outbounds") or []:
            if isinstance(ob, dict) and ob.get("protocol") not in NON_PROXY:
                deep_merge(ob, merge)
                for path, options in rnd.items():  # one random pick per outbound
                    set_path(ob, path, copy.deepcopy(random.choice(options)))
    else:
        deep_merge(cfg, merge)
        for path, options in rnd.items():
            set_path(cfg, path, copy.deepcopy(random.choice(options)))
    pre, post = patch.get("routing_prepend"), patch.get("routing_append")
    if pre or post:
        routing = cfg.get("routing") if isinstance(cfg.get("routing"), dict) else {}
        rules = routing.get("rules") if isinstance(routing.get("rules"), list) else []
        routing["rules"] = copy.deepcopy(pre or []) + rules + copy.deepcopy(post or [])
        cfg["routing"] = routing


def _rename(cfg, patch, counter):
    """A patch's `rename`: {name} = the config's own name, {country} = its flag, {n} = 1, 2, ... in the order it is applied."""
    if not patch.get("rename"):
        return
    counter[0] += 1
    old = str(cfg.get("remarks") or "")
    flag = fields_of(cfg).get("flag") or ""
    cfg["remarks"] = render(patch["rename"], name=old, country=flag, n=counter[0]).strip()


def _addr_holder(ob):
    """(dict, key) holding the server address of an outbound, or None."""
    st = ob.get("settings") if isinstance(ob.get("settings"), dict) else {}
    if isinstance(st.get("address"), str):
        return st, "address"
    for k in ("vnext", "servers"):
        v = st.get(k)
        if isinstance(v, list) and v and isinstance(v[0], dict) and isinstance(v[0].get("address"), str):
            return v[0], "address"
    return None


def _server_key(expand, st, work):
    sb = expand.get("server_by")
    if sb:
        v = get_value(work[st["i"]], st["fields"], sb["field"])
        mo = re.search(sb["regex"], str(v)) if v is not None else None
        if mo:
            return mo.group(1) if mo.re.groups else mo.group(0)
    return st["i"]  # no key: every config is its own server


def expand_members(group, key, members, work, subid):
    """-> [(state, address or None)]. Without `expand` it is one member per config. With it, every server gets
    `copies` members that alternate over the server's configs; each copy takes an address from the pool (random on every
    fetch, or fixed per user with pick "per_user"). A config whose address does not match `address_regex`
    keeps its own address. Configs not matching `expand.when` stay single."""
    ex = group.get("expand")
    if not ex:
        return [(m, None) for m in members]
    pool = list(ex.get("addresses") or [])
    keep = re.compile(ex["address_regex"]) if ex.get("address_regex") else None
    servers = {}
    for m in members:
        servers.setdefault(_server_key(ex, m, work) if match(ex.get("when"), work[m["i"]], m["fields"]) else ("single", m["i"]), []).append(m)
    out, per = [], {}
    for skey, sts in servers.items():
        if isinstance(skey, tuple):
            out.append((sts[0], None))
            continue
        rng = random
        if ex.get("pick") == "per_user":
            seed = "%s|%s|%s|%s" % (subid or "", group["id"], key, skey)
            rng = random.Random(int(hashlib.sha256(seed.encode()).hexdigest(), 16))
        copies = ex.get("copies", 1)
        addrs = []
        if pool:
            while len(addrs) < copies:
                addrs += rng.sample(pool, min(len(pool), copies - len(addrs)))
        for n in range(copies):
            st = sts[n % len(sts)]
            holder = _addr_holder(work[st["i"]]["outbounds"][main_index(work[st["i"]])])
            own = holder[0][holder[1]] if holder else ""
            replace = bool(pool) and holder is not None and not (keep and not keep.search(own))
            per.setdefault(skey, []).append((st, addrs[n] if replace else None))
    if ex.get("layout") == "blocks" and per:
        # `copies` blocks, each with one member of every server; the server order is shuffled once and, with an
        # even number of servers, rotated in every later block so one server's members are not next to each other
        rng = random
        if ex.get("pick") == "per_user":
            seed = "%s|%s|%s|layout" % (subid or "", group["id"], key)
            rng = random.Random(int(hashlib.sha256(seed.encode()).hexdigest(), 16))
        keys = list(per)
        rng.shuffle(keys)
        n = len(keys)
        for blk in range(ex.get("copies", 1)):
            shift = (blk % n) if n % 2 == 0 else 0
            out.extend(per[k][blk] for k in keys[shift:] + keys[:shift])
    else:
        for v in per.values():
            out.extend(v)
    return out


def build_group(group, key, members, work, index, subid=None):
    """One output config: the members' main outbounds + a balancer over them. Everything else
    (inbounds, dns, other outbounds, routing) comes from the first member."""
    members = [m for m in members if main_index(work[m["i"]]) is not None]
    if not members:
        return None
    placed = expand_members(group, key, members, work, subid)
    out = copy.deepcopy(work[members[0]["i"]])
    ti = main_index(out)
    old_tag = out["outbounds"][ti].get("tag")
    gid = slug(group["id"])
    prefix = "%s-%d-" % (gid, index)
    balancer_tag = "%s-%d-lb" % (gid, index)

    mp = group.get("member_position") or []
    if mp:  # stable: members matching a "first" entry go to the front, "last" ones to the back
        def rank(item):
            for e in mp:
                if match(e.get("when"), work[item[0]["i"]], item[0]["fields"]):
                    return 0 if e["at"] == "first" else 2
            return 1
        placed = sorted(placed, key=rank)

    outbounds, costs = [], []
    for n, (m, address) in enumerate(placed, 1):
        src = work[m["i"]]
        ob = copy.deepcopy(src["outbounds"][main_index(src)])
        ob["tag"] = "%s%d" % (prefix, n)
        if address:
            h = _addr_holder(ob)
            h[0][h[1]] = address
        for mp in group.get("member_patch") or []:
            if match(mp.get("when"), src, m["fields"]):
                deep_merge(ob, mp.get("merge") or {})
                for path, options in (mp.get("random") or {}).items():  # one random pick per member
                    set_path(ob, path, copy.deepcopy(random.choice(options)))
        ob["tag"] = "%s%d" % (prefix, n)
        outbounds.append(ob)
        for mc in group.get("member_cost") or []:
            if match(mc.get("when"), src, m["fields"]):
                costs.append({"regexp": True, "match": "^%s$" % re.escape(ob["tag"]), "value": mc["value"]})
                break
    out["outbounds"] = outbounds + [o for i, o in enumerate(out["outbounds"]) if i != ti]

    routing = out.get("routing") if isinstance(out.get("routing"), dict) else {}
    rules = routing.get("rules") if isinstance(routing.get("rules"), list) else []
    for r in rules:  # rules that pointed at the old single outbound now point at the balancer
        if isinstance(r, dict) and old_tag and r.get("outboundTag") == old_tag:
            r.pop("outboundTag")
            r["balancerTag"] = balancer_tag
    wanted = []
    for extra in group.get("catchall_rules") or [{"network": "tcp,udp"}]:
        rule = dict({"type": "field"}, **copy.deepcopy(extra))
        rule["balancerTag"] = balancer_tag
        wanted.append(rule)
    if group.get("catchall_rules"):  # explicit list: it decides the order (a rerouted original rule is re-added in place)
        rules[:] = [r for r in rules if r not in wanted]
    rules.extend(r for r in wanted if r not in rules)
    strategy = {"type": group["type"]}
    if group.get("params"):
        strategy["settings"] = copy.deepcopy(group["params"])
    if costs:
        strategy.setdefault("settings", {})
        strategy["settings"]["costs"] = list(strategy["settings"].get("costs") or []) + costs
    routing["rules"] = rules
    routing["balancers"] = [{"tag": balancer_tag, "selector": [prefix], "strategy": strategy}]
    out["routing"] = routing

    out.pop("observatory", None)  # these pointed at the old single outbound
    out.pop("burstObservatory", None)
    probe = group.get("probe")
    if probe:
        kind = group.get("probe_kind") or ("burst" if group["type"] == "leastLoad" else "observatory")
        if kind == "burst":
            out["burstObservatory"] = {"subjectSelector": [prefix], "pingConfig": copy.deepcopy(probe)}
        else:
            out["observatory"] = dict({"subjectSelector": [prefix]}, **copy.deepcopy(probe))

    default_name = "{split}" if group.get("split_by") else group["id"]
    out["remarks"] = render(group.get("name") or default_name, split=key, n=len(placed), group=group["id"])
    return out, members


_PLACEHOLDER = re.compile(r"\{(account|exit|choice|split|n|entry|user)(?:\.([A-Za-z0-9_.\-]+))?(\?)?\}")


def _lookup(m, values):
    kind, path = m.group(1), m.group(2)
    base = values.get(kind)
    val = (dig(base, path) if isinstance(base, dict) else None) if path else base
    if val is None or val == {}:
        raise ValueError("no value for {%s%s}" % (kind, "." + path if path else ""))
    return copy.deepcopy(val)


def substitute(obj, values):
    """Fill {account.x} {exit.field} {split} {n} placeholders. A string that is exactly one placeholder keeps the
    value's type (so lists and numbers work); inside longer text it is inserted as text."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            whole = _PLACEHOLDER.fullmatch(v) if isinstance(v, str) else None
            if whole and whole.group(3):  # {account.x?}: optional, the key is left out when there is no value
                try:
                    out[k] = _lookup(whole, values)
                except ValueError:
                    pass
                continue
            out[k] = substitute(v, values)
        return out
    if isinstance(obj, list):
        return [substitute(v, values) for v in obj]
    if isinstance(obj, str):
        whole = _PLACEHOLDER.fullmatch(obj)
        if whole:
            return _lookup(whole, values)
        return _PLACEHOLDER.sub(lambda m: str(_lookup(m, values)), obj)
    return obj


def bucketize(cands, split_by, work):
    """{bucket key: [states]}; without split_by everything is one bucket (key "")."""
    buckets = {}
    if split_by:
        rx = re.compile(split_by["regex"])
        for st in cands:
            v = get_value(work[st["i"]], st["fields"], split_by["field"])
            mo = rx.search(str(v)) if v is not None else None
            if mo:
                key = (mo.group(1) if mo.re.groups else mo.group(0)) or ""
                buckets.setdefault(key, []).append(st)
    elif cands:
        buckets[""] = list(cands)
    return buckets


def pick_choices(chain, subid):
    """{name: one value of the list} for a chain's `choices`. The pick depends only on the subscription id and the chain,
    so a user keeps the same value on every refresh (and different users spread over the list)."""
    out = {}
    for name, options in (chain.get("choices") or {}).items():
        if isinstance(options, list) and options:
            h = int(hashlib.sha256(("%s|%s|%s" % (subid or "", chain.get("id"), name)).encode()).hexdigest(), 16)
            out[name] = options[h % len(options)] if subid else options[0]
    return out


def build_chain(chain, key, sts, work, index, account, subid=None):
    """One output config: the admin's `entry` outbound, dialed through the first exit config's outbound."""
    first = sts[0]
    out = copy.deepcopy(work[first["i"]])
    mi = main_index(out)
    exit_ob = out["outbounds"][mi]
    old_tag = exit_ob.get("tag")
    gid = slug(chain["id"])
    entry_tag, exit_tag = "%s-%d-entry" % (gid, index), "%s-%d-exit" % (gid, index)
    values = {"account": account or {}, "exit": dict(first["fields"]), "choice": pick_choices(chain, subid),
              "split": key, "n": len(sts)}
    entry = substitute(chain["entry"], values)
    entry["tag"] = entry_tag
    others = [o for i, o in enumerate(out["outbounds"]) if i != mi]
    if chain.get("through_exit", True):
        exit_ob["tag"] = exit_tag
        stream = entry.get("streamSettings") if isinstance(entry.get("streamSettings"), dict) else {}
        sock = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
        sock["dialerProxy"] = exit_tag
        stream["sockopt"] = sock
        entry["streamSettings"] = stream
        out["outbounds"] = [entry, exit_ob] + others
    else:
        out["outbounds"] = [entry] + others
    routing = out.get("routing") if isinstance(out.get("routing"), dict) else {}
    rules = routing.get("rules") if isinstance(routing.get("rules"), list) else []
    for r in rules:
        if isinstance(r, dict) and old_tag and r.get("outboundTag") == old_tag:
            r["outboundTag"] = entry_tag
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": entry_tag})
    routing["rules"] = rules
    out["routing"] = routing
    out.pop("observatory", None)
    out.pop("burstObservatory", None)
    default_name = "{split}" if chain.get("split_by") else chain["id"]
    out["remarks"] = render(chain.get("name") or default_name, split=key, n=len(sts), group=chain["id"])
    return out


def split_endpoint(ep):
    """'ip' or 'ip:port' or '[v6]:port' -> (host, port string)."""
    ep = str(ep).strip()
    if ep.startswith("["):
        host, _, rest = ep[1:].partition("]")
        return host, rest.lstrip(":")
    if ep.count(":") == 1:
        host, _, port = ep.partition(":")
        return host, port
    return ep, ""


def find_user_id(cfgs):
    """The user's own id: the most frequent vless/vmess id among `cfgs` (the first one on a tie)."""
    found = []
    for c in cfgs:
        for ob in c.get("outbounds") or []:
            if not isinstance(ob, dict) or ob.get("protocol") not in ("vless", "vmess"):
                continue
            st = ob.get("settings") if isinstance(ob.get("settings"), dict) else {}
            vn = st.get("vnext")
            users = (vn[0].get("users") or [{}]) if isinstance(vn, list) and vn and isinstance(vn[0], dict) else [{}]
            uid = st.get("id") or (users[0].get("id") if users and isinstance(users[0], dict) else None)
            if isinstance(uid, str) and uid:
                found.append(uid)
    return max(found, key=lambda u: (found.count(u), -found.index(u))) if found else None


def set_user_id(ob, uid):
    st = ob.get("settings")
    if not isinstance(st, dict):
        return False
    vn = st.get("vnext")
    if isinstance(vn, list) and vn and isinstance(vn[0], dict) and isinstance(vn[0].get("users"), list) and vn[0]["users"]:
        vn[0]["users"][0]["id"] = uid
    else:
        st["id"] = uid
    return True


def _pick(options, seed, per_user):
    if per_user and seed is not None:
        return options[int(hashlib.sha256(seed.encode()).hexdigest(), 16) % len(options)]
    return random.choice(options)


def build_chain_exit_first(chain, key, sts, work, index, account, subid, user_cfgs):
    """Mode "exit_first": the matched config (for example a placeholder the panel hands out per country) becomes
    [exit, entry]. Traffic leaves through the exit, and the exit is dialed THROUGH the entry (client -> entry -> exit).
    The exit is a template from the account (picked by the config's flag) with the user's own id filled in."""
    first = sts[0]
    out = copy.deepcopy(work[first["i"]])
    for k in ("routing", "observatory", "burstObservatory"):
        out.pop(k, None)
    gid = slug(chain["id"])
    entry_tag, exit_tag = "%s-%d-entry" % (gid, index), "%s-%d-exit" % (gid, index)
    values = {"account": account or {}, "exit": dict(first["fields"]), "choice": pick_choices(chain, subid),
              "split": key, "n": len(sts)}
    entry = substitute(chain["entry"], values)
    if isinstance(chain["entry"], str):  # the account holds the outbound: its own {account.x} placeholders are filled too
        entry = substitute(entry, values)
    if isinstance(chain.get("entry_merge"), dict):
        deep_merge(entry, substitute(chain["entry_merge"], values))
    per_user = chain.get("pick") == "per_user"
    eps = substitute(chain["endpoints"], values) if chain.get("endpoints") else None
    if eps:
        host, port = split_endpoint(_pick(list(eps), "%s|%s|ep" % (subid, chain["id"]), per_user))
        st = entry.setdefault("settings", {})
        if host:
            st["address"] = host
            if port.isdigit():
                st["port"] = int(port)
    entry["tag"] = entry_tag
    sock = (entry.get("streamSettings") or {}).get("sockopt")
    if isinstance(sock, dict):
        sock.pop("dialerProxy", None)

    if chain.get("exit") is False:  # solo: the entry alone, no exit behind it
        out["outbounds"] = [entry]
        if chain.get("before"):  # extra outbounds in front (a harmless first outbound); all traffic still goes to the entry
            vals = dict(values, entry=entry.get("settings") or {}, user={"id": find_user_id(user_cfgs) or "00000000-0000-0000-0000-000000000000"})
            out["outbounds"] = substitute(chain["before"], vals) + [entry]
            out["routing"] = {"rules": [{"type": "field", "network": "tcp,udp", "outboundTag": entry_tag, "_keep": True}]}
        default_name = "{split}" if chain.get("split_by") else chain["id"]
        out["remarks"] = render(chain.get("name") or default_name, split=key, n=len(sts), group=chain["id"])
        return out
    spec = chain.get("exit") or {}
    flag = first["fields"].get("flag") or ""
    exits = account.get(spec.get("from_account", "exits")) if isinstance(account.get(spec.get("from_account", "exits")), dict) else {}
    tmpl = exits.get(flag) if flag else None
    if not tmpl:
        tmpl = account.get(spec.get("default_account", "exit"))
    if isinstance(tmpl, dict) and isinstance(tmpl.get("outbound"), dict):
        tmpl = tmpl["outbound"]
    if not (isinstance(tmpl, dict) and tmpl.get("protocol")):
        raise ValueError("no exit template in the account for %r" % flag)
    exit_ob = copy.deepcopy(tmpl)
    if spec.get("user_id", True):
        uid = find_user_id(user_cfgs)
        if not uid or not set_user_id(exit_ob, uid):
            raise ValueError("the user has no config with an id to put into the exit")
    exit_ob["tag"] = exit_tag
    stream = exit_ob.get("streamSettings") if isinstance(exit_ob.get("streamSettings"), dict) else {}
    sock = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
    sock["dialerProxy"] = entry_tag
    stream["sockopt"] = sock
    exit_ob["streamSettings"] = stream
    out["outbounds"] = [exit_ob, entry]
    default_name = "{split}" if chain.get("split_by") else chain["id"]
    out["remarks"] = render(chain.get("name") or default_name, split=key, n=len(sts), group=chain["id"])
    return out


def pick_from_pool(pool, subid):
    """A fixed account of the pool for a subscription id (rendezvous hashing: removing one account only moves its users)."""
    items = [a for a in pool if isinstance(a, dict) and a.get("privateKey")]
    if not items:
        return {}

    def score(a):
        ident = str(a.get("id") or a.get("privateKey") or "")
        return hashlib.sha256(("%s|%s" % (subid, ident)).encode()).digest()
    return max(items, key=score)


def process(configs, conf, subid=None, accounts=None, params=None):
    """-> (output configs, report). `conf` is a normalized configuration (see config.normalize).
    `accounts` is {"default": {...}, "users": {subid: {...}}} (see accounts.py); `subid` picks the user's entry."""
    accounts = accounts or {}
    account = dict(accounts.get("default") or {})
    personal = (accounts.get("users") or {}).get(subid)
    pool = account.pop("pool", None)
    if isinstance(personal, dict) and personal and (personal.get("privateKey") or not pool):
        account.update(personal)
    elif isinstance(pool, list) and pool and subid:  # shared accounts until the user has a personal one
        account.update(pick_from_pool(pool, subid))
    work = [copy.deepcopy(c) for c in configs if isinstance(c, dict)]
    report = {"configs": [], "outputs": [], "errors": []}

    def guarded(label, fn):
        try:
            return fn()
        except Exception as e:  # one bad rule must not break everyone's subscription
            msg = "%s failed: %s: %s" % (label, type(e).__name__, e)
            report["errors"].append(msg)
            _log(msg)

    def run_patches(stage, targets):
        for p in conf["patches"]:
            if not p.get("enabled", True) or p.get("stage", "source") != stage:
                continue
            n = [0]
            for c in targets:
                guarded("patch %s" % p.get("id"), lambda c=c, p=p: match(p.get("when"), c) and (apply_patch(c, p), _rename(c, p, n)))

    run_patches("source", work)

    # rules: the first matching rule decides what happens to a config
    state = []
    for i, c in enumerate(work):
        f = fields_of(c)
        st = {"i": i, "fields": f, "rule": None, "action": None, "groups": [], "chains": []}
        for r in conf["rules"]:
            if r.get("enabled", True) and guarded("rule %s" % r.get("id"), lambda: match(r.get("when"), c, f)):
                st["rule"], st["action"] = r.get("id"), r["do"]
                break
        state.append(st)
    alive = [st for st in state if st["action"] != "drop"]

    # groups
    group_ids = {g["id"] for g in conf["groups"]}
    removed, made = set(), []
    for g in conf["groups"]:
        if not g.get("enabled", True):
            continue

        def run_group(g=g):
            cands = [st for st in alive if match(g.get("when"), work[st["i"]], st["fields"])
                     and (g.get("include_balanced") or not (work[st["i"]].get("routing") or {}).get("balancers"))]
            buckets = bucketize(cands, g.get("split_by"), work)
            for bi, (key, sts) in enumerate(buckets.items()):
                if len(sts) < g.get("min_members", 1):
                    continue
                built = build_group(g, key, sts, work, bi, subid)
                if not built:
                    continue
                cfg, members = built
                for m in members:
                    m["groups"].append(g["id"])
                    if g.get("remove_members_from_output", True):
                        removed.add(m["i"])
                made.append((min(m["i"] for m in members), g.get("position"), cfg, g["id"], len(members)))

        guarded("group %s" % g.get("id"), run_group)

    # chains
    for ch in conf["chains"]:
        if not ch.get("enabled", True):
            continue

        def run_chain(ch=ch):
            cands = [st for st in alive if match(ch.get("exit_when"), work[st["i"]], st["fields"])
                     and (ch.get("mode") == "exit_first" or main_index(work[st["i"]]) is not None)]
            for bi, (key, sts) in enumerate(bucketize(cands, ch.get("split_by"), work).items()):
                if ch.get("mode") == "exit_first":
                    matched = {st["i"] for st in cands}
                    user_cfgs = [work[st["i"]] for st in alive if st["i"] not in matched]
                    cfg = guarded("chain %s" % ch["id"], lambda key=key, sts=sts, bi=bi: build_chain_exit_first(
                        ch, key, sts, work, bi, account, subid, user_cfgs))
                    if ch.get("remove_exit_from_output", True):
                        removed.update(st["i"] for st in sts)  # the placeholder never stays in the list
                else:
                    cfg = guarded("chain %s" % ch["id"], lambda key=key, sts=sts, bi=bi: build_chain(ch, key, sts, work, bi, account, subid))
                if cfg is None:
                    continue
                sts[0]["chains"].append(ch["id"])
                if ch.get("mode") != "exit_first" and ch.get("remove_exit_from_output", False):
                    removed.add(sts[0]["i"])
                made.append((sts[0]["i"], ch.get("position"), cfg, ch["id"], 1))

        guarded("chain %s" % ch.get("id"), run_chain)

    # assemble the output list
    entries = []
    for st in alive:
        if st["i"] in removed:
            continue
        order = st["i"] + {"pin_top": -10 ** 6, "pin_bottom": 10 ** 6}.get(st["action"], 0)
        entries.append((order, 0, work[st["i"]]))
    for first, pos, cfg, gid, n in made:
        order = {"top": -10 ** 6, "bottom": 10 ** 6}.get(pos, first)
        entries.append((order, -1, cfg))
    entries.sort(key=lambda e: (e[0], e[1]))
    output = [e[2] for e in entries]
    ranks = [o for o in conf.get("order", []) if o.get("enabled", True)]
    if ranks:  # a stable sort: configs with the same rank keep their natural order; unmatched ones go last
        def rank_of(c):
            for o in ranks:
                if match(o.get("when"), c):
                    return o["rank"]
            return 10 ** 6
        output.sort(key=rank_of)

    from . import output as output_mod
    output_mod.run(output, conf.get("output"), params or {}, {id(cfg) for _, _, cfg, gid, _ in made if gid in group_ids})

    for c in output:  # internal marker used by the output section; never part of the result
        for r in (c.get("routing") or {}).get("rules") or [] if isinstance(c.get("routing"), dict) else []:
            if isinstance(r, dict):
                r.pop("_keep", None)

    run_patches("output", output)

    for st in state:
        action = st["action"] or "keep"
        report["configs"].append({
            "index": st["i"], "remark": st["fields"].get("remark"),
            "fields": {k: st["fields"].get(k) for k in SHOWN if st["fields"].get(k) is not None},
            "rule": st["rule"], "action": action, "groups": st["groups"], "chains": st["chains"],
            "in_output": action != "drop" and st["i"] not in removed,
        })
    for first, pos, cfg, gid, n in made:
        report["outputs"].append({"remark": cfg.get("remarks"), "group": gid, "members": n})
    return output, report
