"""The `output` section: settings applied to every returned config after groups and chains were built.

Everything is off unless the admin turns it on, so an empty section changes nothing. Typical uses: separate socks/http
inbounds (some apps do not work with `mixed`), a `dns-out` outbound, base routing rules, a dedicated DNS for the
domains of the proxies themselves, blocking QUIC, and sizing the observatory/balancer settings from the member count.
"""
import copy
import re

from .matching import NON_PROXY, dig, match

QUIC_DOMAINS = ["googlevideo.com", "youtube.com", "ytimg.com", "ggpht.com", "gstatic.com", "gvt1.com",
                "googleusercontent.com", "googlesyndication.com", "instagram.com", "cdninstagram.com",
                "facebook.com", "fbcdn.net", "fbsbx.com"]

DIRECT_RULES = [
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
    {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
    {"type": "field", "domain": ["domain:ir", "geosite:category-ir"], "outboundTag": "direct"},
    {"type": "field", "ip": ["geoip:ir"], "outboundTag": "direct"},
]

SNIFFING = {"destOverride": ["http", "tls", "quic", "fakedns"], "enabled": True, "routeOnly": False}

KEYS = {"enabled", "when", "dns_out", "split_inbounds", "block_udp_443", "quic_domains", "sniff_override", "route_only", "socks_port", "http_port", "base_rules",
        "dedicated_dns", "direct_dns", "remark_rewrite", "sampling", "panel_balancers", "replace_routing", "domain_strategy"}


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def check_output(raw):
    """-> list of problem messages for the `output` section (the section itself is kept as given when it is an object)."""
    from .matching import check_when
    p = []
    for k, v in raw.items():
        if k not in KEYS and not k.startswith("_"):
            p.append("output.%s: unknown key; ignored" % k)
    for k in ("enabled", "dns_out", "split_inbounds", "block_udp_443", "replace_routing"):
        if k in raw and not isinstance(raw[k], bool):
            p.append("output.%s: must be true or false" % k)
    p += check_when(raw.get("when"), "output.when")
    if "sniff_override" in raw and not (isinstance(raw["sniff_override"], list) and all(isinstance(x, str) for x in raw["sniff_override"])):
        p.append("output.sniff_override: must be a list of strings (http, tls, quic, fakedns)")
    if "route_only" in raw and not isinstance(raw["route_only"], bool):
        p.append("output.route_only: must be true or false")
    for k in ("socks_port", "http_port"):
        if k in raw and not (_int(raw[k]) and 1 <= raw[k] <= 65535):
            p.append("output.%s: must be a port number 1-65535" % k)
    if "quic_domains" in raw and not (isinstance(raw["quic_domains"], list) and all(isinstance(x, str) for x in raw["quic_domains"])):
        p.append("output.quic_domains: must be a list of strings")
    br = raw.get("base_rules")
    if br is not None and not (isinstance(br, bool) or (isinstance(br, list) and all(isinstance(x, dict) for x in br))):
        p.append("output.base_rules: must be true, false or a list of routing rules")
    dd = raw.get("dedicated_dns")
    if dd is not None and not (isinstance(dd, bool) or (isinstance(dd, dict) and isinstance(dd.get("ip", "x"), str))):
        p.append('output.dedicated_dns: must be true, false or {"ip": "...", "tag": "..."}')
    dn = raw.get("direct_dns")
    if dn is not None and not (isinstance(dn, bool) or (isinstance(dn, dict) and _regex_ok(dn.get("tag_regex", "x")))):
        p.append('output.direct_dns: must be true, false or {"tag_regex": "..."}')
    rr = raw.get("remark_rewrite")
    if rr is not None:
        if not isinstance(rr, list):
            p.append('output.remark_rewrite: must be a list of {"regex": "...", "replace": "...", "if": "..."}')
        else:
            for i, e in enumerate(rr):
                if not (isinstance(e, dict) and _regex_ok(e.get("regex")) and isinstance(e.get("replace", ""), str)
                        and _regex_ok(e.get("if", "x"))):
                    p.append('output.remark_rewrite[%d]: needs {"regex": "...", "replace": "...", "if": "..."} with valid regexes' % i)
    if "domain_strategy" in raw and not isinstance(raw["domain_strategy"], str):
        p.append("output.domain_strategy: must be a string")
    sp = raw.get("sampling")
    if sp is not None and not (isinstance(sp, dict) and ((_int(sp.get("fixed")) and sp["fixed"] >= 1) or
                                                         (_int(sp.get("members_div")) and sp["members_div"] >= 1))):
        p.append('output.sampling: must be {"fixed": N} or {"members_div": D, "extra": N}')
    pb = raw.get("panel_balancers")
    if pb is not None and not isinstance(pb, dict):
        p.append("output.panel_balancers: must be an object")
    return p


def _regex_ok(v):
    try:
        re.compile(v)
        return isinstance(v, str)
    except (re.error, TypeError):
        return False


def count_members(outbounds, selector):
    n = 0
    for ob in outbounds or []:
        if not isinstance(ob, dict) or ob.get("protocol") in NON_PROXY + ("socks",):
            continue
        tag = str(ob.get("tag", ""))
        if not selector or any(tag.startswith(str(s)) for s in selector):
            n += 1
    return n


def _addr(ob):
    st = ob.get("settings") if isinstance(ob.get("settings"), dict) else {}
    if isinstance(st.get("address"), str):
        return st["address"]
    for k in ("vnext", "servers"):
        v = st.get(k)
        if isinstance(v, list) and v and isinstance(v[0], dict) and isinstance(v[0].get("address"), str):
            return v[0]["address"]
    return ""


def proxy_domains(cfg):
    """Names (not IPs) the proxies of this config connect to: address, and SNI/host when the stream uses TLS."""
    doms = []

    def add(d):
        d = str(d or "").strip().lower().rstrip(".")
        if d and "." in d and ":" not in d and not re.fullmatch(r"[0-9.]+", d) and d not in doms:
            doms.append(d)

    for ob in cfg.get("outbounds") or []:
        if not isinstance(ob, dict) or ob.get("protocol") in NON_PROXY + ("socks",):
            continue
        add(_addr(ob))
        ss = ob.get("streamSettings") if isinstance(ob.get("streamSettings"), dict) else {}
        if ss.get("security") == "tls":
            add(dig(ss, "tlsSettings.serverName"))
            add(dig(ss, "xhttpSettings.host"))
    return doms


def _ensure_outbound(cfg, tag, ob):
    obs = cfg.setdefault("outbounds", [])
    if not any(isinstance(o, dict) and o.get("tag") == tag for o in obs):
        obs.append(ob)


def apply_output(cfg, out, ours):
    """`ours` is True for configs built by a group (their balancers and observatory are ours; the panel's are not)."""
    if out.get("remark_rewrite") and isinstance(cfg.get("remarks"), str):
        r = cfg["remarks"]
        for e in out["remark_rewrite"]:  # for example drop the code before the flag, or a provider word
            if not e.get("if") or re.search(e["if"], r):
                r = re.sub(e["regex"], e.get("replace", ""), r)
        cfg["remarks"] = r.strip()
    routing = cfg.get("routing") if isinstance(cfg.get("routing"), dict) else {}

    pb = out.get("panel_balancers")
    if pb and not ours:
        few = pb.get("few_max_members", 2)
        for b in routing.get("balancers") or []:
            strat = b.get("strategy") if isinstance(b, dict) else None
            if not (isinstance(strat, dict) and strat.get("type") == "leastLoad"):
                continue
            if not isinstance(strat.get("settings"), dict):
                strat["settings"] = {}
            sett = strat["settings"]
            if pb.get("max_rtt"):
                sett["maxRTT"] = pb["max_rtt"]
            if "expected_few" in pb or "expected_many" in pb:
                n = count_members(cfg.get("outbounds"), b.get("selector"))
                sett["expected"] = pb.get("expected_few", 1) if n <= few else pb.get("expected_many", 2)

    sp = out.get("sampling")
    bo = cfg.get("burstObservatory")
    if sp and ours and isinstance(bo, dict) and isinstance(bo.get("pingConfig"), dict):
        n = count_members(cfg.get("outbounds"), bo.get("subjectSelector"))
        bo["pingConfig"]["sampling"] = sp["fixed"] if sp.get("fixed") else max(1, n // sp["members_div"] + sp.get("extra", 0))

    dns = cfg.get("dns") if isinstance(cfg.get("dns"), dict) else None
    dd = out.get("dedicated_dns")
    dd_tag = None
    if dd and dns is not None:
        doms = proxy_domains(cfg)
        spec = dd if isinstance(dd, dict) else {}
        dd_tag = spec.get("tag", "dedicated-dns")  # the direct rule is added even for a config with nothing to resolve
        if doms:
            if not isinstance(dns.get("servers"), list):
                dns["servers"] = []
            dns["servers"].insert(0, {"address": spec.get("ip", "8.8.8.8"), "domains": doms,
                                       "skipFallback": True, "tag": dd_tag})

    rules = routing.get("rules") if isinstance(routing.get("rules"), list) else []
    if out.get("replace_routing"):
        rules = [r for r in rules if isinstance(r, dict) and ("balancerTag" in r or r.get("_keep"))]  # balancer rules and rules a chain made stay
    head = []
    use_dns_out = bool(out.get("dns_out")) and dns is not None and bool(dns.get("servers"))
    if use_dns_out:
        head.append({"type": "field", "inboundTag": ["socks"], "port": "53", "outboundTag": "dns-out"})
    br = out.get("base_rules")
    if br:
        if dd_tag:
            head.append({"type": "field", "inboundTag": [dd_tag], "outboundTag": "direct"})
        head += copy.deepcopy(DIRECT_RULES if br is True else br)
    dn = out.get("direct_dns")
    if dn and dns is not None:
        rx = re.compile(dn.get("tag_regex", "^domestic-dns") if isinstance(dn, dict) else "^domestic-dns")
        tags = [x["tag"] for x in dns.get("servers") or [] if isinstance(x, dict) and isinstance(x.get("tag"), str) and rx.search(x["tag"])]
        if tags:  # queries of the panel's own domestic DNS servers must not go through the proxy
            head.append({"type": "field", "inboundTag": tags, "outboundTag": "direct"})
    if out.get("block_udp_443"):
        rule = {"type": "field", "network": "udp", "port": "443", "outboundTag": "block"}
        doms = out["quic_domains"] if "quic_domains" in out else QUIC_DOMAINS
        if doms:
            rule["domain"] = list(doms)
        head.append(rule)
    if head or out.get("replace_routing"):
        routing["rules"] = head + rules
    if out.get("domain_strategy"):
        routing["domainStrategy"] = out["domain_strategy"]
    if routing:
        cfg["routing"] = routing

    if br or out.get("direct_dns") or out.get("replace_routing") or out.get("block_udp_443"):
        _ensure_outbound(cfg, "direct", {"protocol": "freedom", "tag": "direct"})
    if out.get("block_udp_443"):
        _ensure_outbound(cfg, "block", {"protocol": "blackhole", "tag": "block"})
    if use_dns_out:
        _ensure_outbound(cfg, "dns-out", {"protocol": "dns", "tag": "dns-out"})

    if out.get("split_inbounds"):
        old = [i for i in cfg.get("inbounds") or [] if isinstance(i, dict)]
        port = next((i.get("port") for i in old if i.get("protocol") == "mixed"), None)
        socks = out.get("socks_port") or next((i.get("port") for i in old if i.get("protocol") == "socks"), port or 10808)
        http = out.get("http_port") or next((i.get("port") for i in old if i.get("protocol") == "http"), (port + 1) if isinstance(port, int) else 10809)
        sniffing = copy.deepcopy(SNIFFING)
        if "sniff_override" in out:
            sniffing["destOverride"] = list(out["sniff_override"])
        if "route_only" in out:
            sniffing["routeOnly"] = out["route_only"]
        cfg["inbounds"] = [
            {"listen": "127.0.0.1", "port": socks, "protocol": "socks", "tag": "socks",
             "settings": {"auth": "noauth", "udp": True}, "sniffing": copy.deepcopy(sniffing)},
            {"listen": "127.0.0.1", "port": http, "protocol": "http", "tag": "http",
             "settings": {}, "sniffing": copy.deepcopy(sniffing)},
        ]


def run(configs, out, params, ours_ids):
    if not out or out.get("enabled", True) is False:
        return
    for c in configs:
        if match(out.get("when"), c):
            apply_output(c, out, id(c) in ours_ids)
