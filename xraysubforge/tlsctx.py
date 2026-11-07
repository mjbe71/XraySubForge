"""HTTPS with one certificate per domain (SNI).

server.tls_cert / tls_key is the default certificate. server.domains adds more:
    [{"name": "sub.example.com", "cert": "/path/fullchain.pem", "key": "/path/privkey.pem"},
     {"name": "*.cdn.example.org", "cert": "...", "key": "..."}]
A client asking for one of these names gets that certificate; anything else gets the default one (or the first
domain's, when no default is set). Certificate files are re-read when they change (renewals), checked at most every
few seconds.
"""
import os
import ssl
import threading
import time

RECHECK_SECONDS = 10


def domain_certs(server):
    """[(name, cert, key)] of server.domains that have both files set."""
    out = []
    for d in server.get("domains") or []:
        if isinstance(d, dict) and d.get("name") and d.get("cert") and d.get("key"):
            out.append((str(d["name"]).lower().rstrip("."), d["cert"], d["key"]))
    return out


def default_cert(server):
    """(cert, key) of the default certificate, or None when HTTPS is off."""
    if server.get("tls_cert") and server.get("tls_key"):
        return server["tls_cert"], server["tls_key"]
    certs = domain_certs(server)
    return (certs[0][1], certs[0][2]) if certs else None


def tls_enabled(server):
    return default_cert(server) is not None


def _matches(pattern, name):
    if pattern == name:
        return True
    if pattern.startswith("*."):                 # one label, like certificates do
        head, _, rest = name.partition(".")
        return bool(head) and rest == pattern[2:]
    return False


class _Cache:
    """One SSLContext per (cert, key), rebuilt when a file changes."""

    def __init__(self, base_factory):
        self.base = base_factory
        self.lock = threading.Lock()
        self.items = {}

    def get(self, cert, key):
        now = time.monotonic()
        with self.lock:
            item = self.items.get((cert, key))
            if item and now - item["checked"] < RECHECK_SECONDS:
                return item["ctx"]
            try:
                sig = (os.stat(cert).st_mtime_ns, os.stat(key).st_mtime_ns)
            except OSError:
                return item["ctx"] if item else None
            if item and item["sig"] == sig:
                item["checked"] = now
                return item["ctx"]
            try:
                ctx = self.base()
                ctx.load_cert_chain(cert, key)
            except (OSError, ssl.SSLError):
                return item["ctx"] if item else None   # keep the last good one
            self.items[(cert, key)] = {"ctx": ctx, "sig": sig, "checked": now}
            return ctx


def attach_sni(ctx, server, base_factory):
    """Give `ctx` (already holding the default certificate) a callback that picks the domain's certificate."""
    certs = domain_certs(server)
    if not certs:
        return ctx
    cache = _Cache(base_factory)

    def pick(sock, name, _ctx):
        if not name:
            return None
        name = name.lower().rstrip(".")
        for pattern, cert, key in certs:
            if _matches(pattern, name):
                chosen = cache.get(cert, key)
                if chosen is not None:
                    sock.context = chosen
                return None
        return None

    ctx.sni_callback = pick
    return ctx


def new_context():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    return c


def server_context(server):
    """A complete server SSLContext (default certificate + SNI), or None when HTTPS is off."""
    default = default_cert(server)
    if not default:
        return None

    ctx = new_context()
    ctx.load_cert_chain(*default)
    return attach_sni(ctx, server, new_context)
