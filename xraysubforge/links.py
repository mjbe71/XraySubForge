"""Share links (vless://, vmess://, trojan://, ss://) <-> Xray outbounds.

parse_raw()   a raw subscription (base64 or plain lines) -> list of links
link_to_config()  one link -> a complete Xray client config (the JSON-subscription shape), from a template
config_links()    an Xray config -> the links it can be written as (a balancer gives one link per member)

Only what a link can carry is converted. Anything else (fragment, cipher suites, balancers' strategy, chains through
another outbound) has no place in a link and is left out.
"""
import base64
import copy
import json
import re
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

NON_PROXY = ("freedom", "blackhole", "dns", "loopback")

DEFAULT_TEMPLATE = {
    "log": {"loglevel": "warning"},
    "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
    "inbounds": [
        {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
         "settings": {"auth": "noauth", "udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
        {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {}},
    ],
    "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}},
                  {"tag": "block", "protocol": "blackhole", "settings": {}}],
    "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]},
}


def _b64decode(text):
    s = re.sub(r"\s+", "", text)
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s.replace("-", "+").replace("_", "/")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def parse_raw(body):
    """The body of a raw subscription -> list of link strings (base64 or plain, one link per line)."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    text = body.strip()
    if "://" not in text.split("\n", 1)[0]:
        decoded = _b64decode(text)
        if decoded is not None:
            text = decoded
    return [ln.strip() for ln in text.splitlines() if "://" in ln]


def encode_raw(links):
    return base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")


def _one(q, key, default=None):
    v = q.get(key)
    return v[0] if v else default


def _stream_from_query(q):
    net = _one(q, "type", "tcp") or "tcp"
    if net == "splithttp":
        net = "xhttp"
    st = {"network": net}
    host, path = _one(q, "host"), _one(q, "path")
    if net == "ws":
        ws = {}
        if path is not None:
            ws["path"] = path
        if host:
            ws["host"] = host
        st["wsSettings"] = ws
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": _one(q, "serviceName", "") or "", "multiMode": _one(q, "mode") == "multi"}
        if _one(q, "authority"):
            st["grpcSettings"]["authority"] = _one(q, "authority")
    elif net == "xhttp":
        xs = {}
        if path is not None:
            xs["path"] = path
        if host:
            xs["host"] = host
        if _one(q, "mode"):
            xs["mode"] = _one(q, "mode")
        if _one(q, "extra"):
            try:
                xs["extra"] = json.loads(_one(q, "extra"))
            except ValueError:
                pass
        st["xhttpSettings"] = xs
    elif net == "httpupgrade":
        hu = {}
        if path is not None:
            hu["path"] = path
        if host:
            hu["host"] = host
        st["httpupgradeSettings"] = hu
    elif net == "kcp":
        st["kcpSettings"] = {"header": {"type": _one(q, "headerType", "none") or "none"}}
        if _one(q, "seed"):
            st["kcpSettings"]["seed"] = _one(q, "seed")
    elif net == "tcp" and _one(q, "headerType") == "http":
        req = {}
        if path:
            req["path"] = path.split(",")
        if host:
            req["headers"] = {"Host": host.split(",")}
        st["tcpSettings"] = {"header": {"type": "http", "request": req}}
    sec = _one(q, "security", "none") or "none"
    st["security"] = sec
    if sec == "tls":
        tls = {}
        if _one(q, "sni"):
            tls["serverName"] = _one(q, "sni")
        if _one(q, "fp"):
            tls["fingerprint"] = _one(q, "fp")
        if _one(q, "alpn"):
            tls["alpn"] = _one(q, "alpn").split(",")
        if _one(q, "allowInsecure") in ("1", "true"):
            tls["allowInsecure"] = True
        if _one(q, "ech"):
            tls["echConfigList"] = _one(q, "ech")
        st["tlsSettings"] = tls
    elif sec == "reality":
        rs = {}
        for key, name in (("sni", "serverName"), ("fp", "fingerprint"), ("pbk", "publicKey"), ("sid", "shortId"),
                          ("spx", "spiderX"), ("pqv", "mldsa65Verify")):
            if _one(q, key):
                rs[name] = _one(q, key)
        st["realitySettings"] = rs
    return st


def _query_from_stream(st):
    q = {}
    net = st.get("network") or "tcp"
    q["type"] = net
    sub = st.get(net + "Settings") if isinstance(st.get(net + "Settings"), dict) else {}
    if net in ("ws", "httpupgrade", "xhttp"):
        if sub.get("path") is not None:
            q["path"] = sub["path"]
        host = sub.get("host") or (sub.get("headers") or {}).get("Host")
        if host:
            q["host"] = host
        if net == "xhttp":
            if sub.get("mode"):
                q["mode"] = sub["mode"]
            if sub.get("extra"):
                q["extra"] = json.dumps(sub["extra"], separators=(",", ":"))
    elif net == "grpc":
        q["serviceName"] = sub.get("serviceName", "")
        if sub.get("multiMode"):
            q["mode"] = "multi"
        if sub.get("authority"):
            q["authority"] = sub["authority"]
    elif net == "kcp":
        q["headerType"] = (sub.get("header") or {}).get("type", "none")
        if sub.get("seed"):
            q["seed"] = sub["seed"]
    elif net == "tcp":
        hdr = sub.get("header") or {}
        if hdr.get("type") == "http":
            q["headerType"] = "http"
            req = hdr.get("request") or {}
            if req.get("path"):
                q["path"] = ",".join(req["path"])
            hosts = (req.get("headers") or {}).get("Host")
            if hosts:
                q["host"] = ",".join(hosts) if isinstance(hosts, list) else hosts
    sec = st.get("security") or "none"
    q["security"] = sec
    if sec == "tls":
        tls = st.get("tlsSettings") or {}
        if tls.get("serverName"):
            q["sni"] = tls["serverName"]
        if tls.get("fingerprint"):
            q["fp"] = tls["fingerprint"]
        if tls.get("alpn"):
            q["alpn"] = ",".join(tls["alpn"])
        if tls.get("allowInsecure"):
            q["allowInsecure"] = "1"
        if tls.get("echConfigList"):
            q["ech"] = tls["echConfigList"]
    elif sec == "reality":
        rs = st.get("realitySettings") or {}
        for key, name in (("sni", "serverName"), ("fp", "fingerprint"), ("pbk", "publicKey"), ("sid", "shortId"),
                          ("spx", "spiderX"), ("pqv", "mldsa65Verify")):
            if rs.get(name):
                q[key] = rs[name]
    return q


def parse_link(link):
    """One share link -> (outbound, remark), or None when the link is not understood."""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            return _parse_vmess(link)
        if scheme in ("vless", "trojan"):
            u = urlsplit(link)
            q = parse_qs(u.query, keep_blank_values=True)
            remark = unquote(u.fragment)
            user, host, port = unquote(u.username or ""), u.hostname, u.port
            if not (user and host and port):
                return None
            st = _stream_from_query(q)
            if scheme == "vless":
                acct = {"id": user, "encryption": _one(q, "encryption", "none") or "none"}
                if _one(q, "flow"):
                    acct["flow"] = _one(q, "flow")
                ob = {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [acct]}]}}
            else:
                ob = {"protocol": "trojan", "settings": {"servers": [{"address": host, "port": port, "password": user}]}}
            ob["streamSettings"] = st
            return ob, remark
        if scheme == "ss":
            return _parse_ss(link)
    except (ValueError, KeyError, TypeError):
        return None
    return None


def _parse_vmess(link):
    raw = _b64decode(link[len("vmess://"):])
    if raw is None:
        return None
    v = json.loads(raw)
    q = {"type": [v.get("net") or "tcp"], "security": ["tls" if v.get("tls") == "tls" else v.get("tls") or "none"]}
    for src, dst in (("host", "host"), ("path", "path"), ("sni", "sni"), ("alpn", "alpn"), ("fp", "fp")):
        if v.get(src):
            q[dst] = [str(v[src])]
    if v.get("type") and v.get("type") != "none":
        q["headerType" if (v.get("net") or "tcp") in ("tcp", "kcp") else "mode"] = [v["type"]]
    if v.get("net") == "grpc" and v.get("path"):
        q["serviceName"] = [v["path"]]
    st = _stream_from_query(q)
    user = {"id": v["id"], "alterId": int(v.get("aid") or 0), "security": v.get("scy") or "auto"}
    ob = {"protocol": "vmess", "settings": {"vnext": [{"address": v["add"], "port": int(v["port"]), "users": [user]}]},
          "streamSettings": st}
    return ob, str(v.get("ps") or "")


def _parse_ss(link):
    body = link[len("ss://"):]
    body, _, frag = body.partition("#")
    body = body.split("?", 1)[0].rstrip("/")
    remark = unquote(frag)
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        decoded = _b64decode(unquote(userinfo))
        creds = decoded if decoded and ":" in decoded else unquote(userinfo)
    else:
        decoded = _b64decode(body)
        if not decoded or "@" not in decoded:
            return None
        creds, _, hostport = decoded.rpartition("@")
    method, _, password = creds.partition(":")
    host, _, port = hostport.rpartition(":")
    host = host.strip("[]")
    if not (method and host and port):
        return None
    ob = {"protocol": "shadowsocks", "settings": {"servers": [{"address": host, "port": int(port), "method": method, "password": password}]},
          "streamSettings": {"network": "tcp", "security": "none"}}
    return ob, remark


def outbound_link(ob, remark):
    """An outbound -> a share link, or None (another protocol, or dialed through another outbound)."""
    if not isinstance(ob, dict):
        return None
    st = ob.get("streamSettings") if isinstance(ob.get("streamSettings"), dict) else {}
    if (st.get("sockopt") or {}).get("dialerProxy") or ob.get("proxySettings"):
        return None
    s = ob.get("settings") if isinstance(ob.get("settings"), dict) else {}
    proto = ob.get("protocol")
    frag = "#" + quote(remark or "", safe="")
    try:
        if proto in ("vless", "vmess"):
            srv = s["vnext"][0]
            user = srv["users"][0]
            host, port = srv["address"], int(srv["port"])
            if proto == "vmess":
                q = _query_from_stream(st)
                v = {"v": "2", "ps": remark or "", "add": host, "port": str(port), "id": user["id"], "aid": str(user.get("alterId", 0)),
                     "scy": user.get("security", "auto"), "net": q.get("type", "tcp"), "type": q.get("headerType", "none"),
                     "host": q.get("host", ""), "path": q.get("path", q.get("serviceName", "")), "tls": "tls" if q.get("security") == "tls" else "",
                     "sni": q.get("sni", ""), "alpn": q.get("alpn", ""), "fp": q.get("fp", "")}
                return "vmess://" + base64.b64encode(json.dumps(v, ensure_ascii=False).encode("utf-8")).decode("ascii")
            q = _query_from_stream(st)
            q = dict({"encryption": user.get("encryption", "none")}, **q)
            if user.get("flow"):
                q["flow"] = user["flow"]
            return "vless://%s@%s:%d?%s%s" % (quote(user["id"], safe=""), _host(host), port, urlencode(q, quote_via=quote), frag)
        if proto == "trojan":
            srv = s["servers"][0]
            q = _query_from_stream(st)
            return "trojan://%s@%s:%d?%s%s" % (quote(srv["password"], safe=""), _host(srv["address"]), int(srv["port"]),
                                                urlencode(q, quote_via=quote), frag)
        if proto == "shadowsocks":
            srv = s["servers"][0]
            cred = base64.urlsafe_b64encode(("%s:%s" % (srv["method"], srv["password"])).encode("utf-8")).decode("ascii").rstrip("=")
            return "ss://%s@%s:%d%s" % (cred, _host(srv["address"]), int(srv["port"]), frag)
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return None


def _host(h):
    return "[%s]" % h if ":" in str(h) and not str(h).startswith("[") else str(h)


def link_to_config(link, template=None):
    """A share link -> a whole client config (main outbound tagged "proxy" first), or None."""
    parsed = parse_link(link)
    if not parsed:
        return None
    ob, remark = parsed
    ob = dict({"tag": "proxy"}, **ob)
    cfg = copy.deepcopy(template if isinstance(template, dict) and template else DEFAULT_TEMPLATE)
    others = [o for o in cfg.get("outbounds") or [] if isinstance(o, dict) and o.get("tag") != "proxy"]
    cfg["outbounds"] = [ob] + others
    cfg["remarks"] = remark
    return cfg


def config_links(cfg):
    """A client config -> its links: the main outbound, or one link per balancer member ("<name> 1", "<name> 2", ...)."""
    remark = str(cfg.get("remarks") or "")
    obs = [o for o in cfg.get("outbounds") or [] if isinstance(o, dict) and o.get("protocol") not in NON_PROXY]
    balancers = (cfg.get("routing") or {}).get("balancers") if isinstance(cfg.get("routing"), dict) else None
    if balancers:
        prefixes = [p for b in balancers for p in (b.get("selector") or [])]
        members = [o for o in obs if any(str(o.get("tag", "")).startswith(p) for p in prefixes)]
        links = [outbound_link(o, "%s %d" % (remark, n)) for n, o in enumerate(members, 1)]
        return [x for x in links if x]
    if not obs:
        return []
    one = outbound_link(obs[0], remark)
    return [one] if one else []
