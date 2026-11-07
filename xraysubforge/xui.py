"""Best-effort detection of a 3x-ui panel installed on the same machine (used by install.sh).

It only READS 3x-ui's settings database (opened read-only) to suggest values: the certificate paths the panel
uses, and its JSON-subscription address. The setting names below come from memory of 3x-ui and are NOT verified
against every version; anything missing is simply reported as absent and the installer asks the user instead.
"""
import datetime
import glob
import json
import os
import re
import sqlite3
import subprocess

DB_CANDIDATES = ("/etc/x-ui/x-ui.db",)
ACME_GLOB = "/root/cert/*/fullchain.pem"       # where the `x-ui` menu's certificate option usually puts them
WANTED = ("webCertFile", "webKeyFile", "webPort", "webBasePath", "webDomain", "subEnable", "subJsonEnable",
          "subPort", "subPath", "subJsonPath", "subDomain", "subCertFile", "subKeyFile")


def find_db(explicit=None):
    cands = [explicit] if explicit else []
    folder = os.environ.get("XUI_DB_FOLDER")
    if folder:
        cands.append(os.path.join(folder, "x-ui.db"))
    cands.extend(DB_CANDIDATES)
    return next((c for c in cands if c and os.path.isfile(c)), None)


def read_settings(db):
    """{lower-case setting name: value} from every table that has `key` and `value` columns."""
    out = {}
    con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    try:
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        for t in tables:
            cols = [r[1].lower() for r in con.execute('pragma table_info("%s")' % t.replace('"', ""))]
            if "key" in cols and "value" in cols:
                for k, v in con.execute('select "key", "value" from "%s"' % t.replace('"', "")):
                    if isinstance(k, str):
                        out[k.lower()] = v
    finally:
        con.close()
    return out


def _s(settings, name):
    v = settings.get(name.lower())
    v = "" if v is None else str(v).strip()
    return v or None


def _slash(path):
    path = path or ""
    return "/" + path.strip("/") + "/" if path.strip("/") else "/"


def detect(db_path=None):
    """-> dict describing what was found. Never raises for a missing or unreadable database."""
    res = {"found": False, "db": None, "web": {}, "sub": {}, "certs": [], "suggest": None}
    db = find_db(db_path)
    settings = {}
    if db:
        try:
            settings = read_settings(db)
            res["found"], res["db"] = True, db
        except (sqlite3.Error, OSError):
            pass
    g = lambda n: _s(settings, n)
    res["web"] = {"cert": g("webCertFile"), "key": g("webKeyFile"), "port": g("webPort"),
                  "base_path": g("webBasePath"), "domain": g("webDomain")}
    res["sub"] = {"cert": g("subCertFile"), "key": g("subKeyFile"), "port": g("subPort"), "path": g("subPath"),
                  "json_path": g("subJsonPath"), "domain": g("subDomain"),
                  "enabled": g("subEnable"), "json_enabled": g("subJsonEnable")}

    pairs = [("3x-ui panel certificate", res["web"]["cert"], res["web"]["key"]),
             ("3x-ui subscription certificate", res["sub"]["cert"], res["sub"]["key"])]
    for cert in sorted(glob.glob(ACME_GLOB)):
        pairs.append(("certificate for %s (from the x-ui menu)" % os.path.basename(os.path.dirname(cert)),
                      cert, os.path.join(os.path.dirname(cert), "privkey.pem")))
    seen = set()
    for label, cert, key in pairs:
        if cert and key and (cert, key) not in seen and os.path.isfile(cert) and os.path.isfile(key):
            seen.add((cert, key))
            res["certs"].append({"label": label, "cert": cert, "key": key})

    sub = res["sub"]
    if sub["port"] and sub["json_path"]:
        tls = bool(sub["cert"] and sub["key"])
        host = sub["domain"] or res["web"]["domain"]
        if tls and host:
            res["suggest"] = {"url": "https://%s:%s%s" % (host, sub["port"], _slash(sub["json_path"])), "verify_tls": True}
        elif tls:
            res["suggest"] = {"url": "https://127.0.0.1:%s%s" % (sub["port"], _slash(sub["json_path"])), "verify_tls": False}
        else:
            res["suggest"] = {"url": "http://127.0.0.1:%s%s" % (sub["port"], _slash(sub["json_path"])), "verify_tls": True}
    return res


# ---------------------------------------------------------------- scanning for certificates by domain
SCAN_DIRS = ("/root/cert", "/root/.acme.sh", "/root/.cert", "/etc/letsencrypt/live", "/etc/x-ui", "/usr/local/x-ui",
             "/opt/cert", "/etc/nginx/ssl", "/etc/caddy")
CERT_EXT = (".pem", ".crt", ".cer", ".cert")


def _openssl(args):
    try:
        r = subprocess.run(["openssl"] + args, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _head(path):
    try:
        with open(path, "rb") as f:
            return f.read(4096).decode("latin-1")
    except OSError:
        return ""


def cert_info(path):
    """{"names", "days", "pub"} of the first certificate in a file, or None."""
    text = _openssl(["x509", "-in", path, "-noout", "-text", "-enddate"])
    if not text:
        return None
    if re.search(r"CA:\s*TRUE", text) or "snakeoil" in path.lower():
        return None                     # CA / root certificates (the system's trust store) and the OS's dummy certificate
    names = [n.lower() for n in re.findall(r"DNS:([^,\s]+)", text)]
    cn = re.search(r"Subject:.*?CN\s*=\s*([^,\n/]+)", text)
    if cn and cn.group(1).strip().lower() not in names:
        names.append(cn.group(1).strip().lower())
    days = None
    m = re.search(r"notAfter=(.+)", text)
    if m:
        try:
            end = datetime.datetime.strptime(" ".join(m.group(1).split()), "%b %d %H:%M:%S %Y %Z")
            days = (end - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
        except ValueError:
            pass
    pub = _openssl(["x509", "-in", path, "-noout", "-pubkey"])
    return {"names": names, "days": days, "pub": (pub or "").strip()}


def covers(names, domain):
    domain = domain.lower().rstrip(".")
    for n in names:
        if n == domain:
            return True
        if n.startswith("*.") and "." in domain and domain.split(".", 1)[1] == n[2:]:
            return True
    return False


def scan_certs(domain, dirs=None, extra=()):
    """Look through the usual places (and the paths 3x-ui itself points at) for certificates; pair each with the private
    key that matches it. -> list of {"cert","key","names","days","covers"}, best candidates first."""
    dirs = dirs if dirs is not None else [d for d in (os.environ.get("XSF_CERT_DIRS", "").split(":") if os.environ.get("XSF_CERT_DIRS") else SCAN_DIRS) if d]
    files = []
    for d in dirs:
        for root, subdirs, names in os.walk(d, followlinks=False):
            if root[len(d):].count(os.sep) >= 3:
                subdirs[:] = []
            for n in names:
                if n.lower().endswith(CERT_EXT + (".key",)):
                    files.append(os.path.join(root, n))
            if len(files) > 400:
                break
    for c, k in extra:
        files += [f for f in (c, k) if f and os.path.isfile(f)]
    certs, keys = [], {}
    for f in dict.fromkeys(files):
        head = _head(f)
        if "BEGIN CERTIFICATE" in head:
            certs.append(f)
        elif "PRIVATE KEY" in head:
            pub = _openssl(["pkey", "-in", f, "-pubout"])
            if pub:
                keys.setdefault(pub.strip(), []).append(f)
    out, seen = [], set()
    for f in certs:
        info = cert_info(f)
        if not info or not info["names"]:
            continue
        cands = keys.get(info["pub"], [])
        key = next((k for k in cands if os.path.dirname(k) == os.path.dirname(f)), cands[0] if cands else "")
        ident = (tuple(info["names"]), info["pub"], info["days"])
        if ident in seen:
            continue
        seen.add(ident)
        out.append({"cert": f, "key": key, "names": info["names"], "days": info["days"],
                    "covers": covers(info["names"], domain) if domain else False})
    rank = lambda c: (not (c["covers"] and c["key"] and (c["days"] or 0) >= 1), not c["key"], -(c["days"] or 0))
    return sorted(out, key=rank)


def main(argv):
    """python -m xraysubforge detect-xui [--db PATH] [--certs | --suggest]"""
    db = argv[argv.index("--db") + 1] if "--db" in argv else None
    res = detect(db)
    if "--scan" in argv:           # tab-separated: certificate, key, covers (yes/no), days left, names
        res_found = [(c["cert"], c["key"]) for c in res["certs"]]
        for c in scan_certs(argv[argv.index("--scan") + 1], extra=res_found):
            print("%s\t%s\t%s\t%s\t%s" % (c["cert"], c["key"], "yes" if c["covers"] else "no",
                                          "" if c["days"] is None else c["days"], ",".join(c["names"])))
    elif "--certs" in argv:          # tab-separated: label, certificate path, key path
        for c in res["certs"]:
            print("%s\t%s\t%s" % (c["label"], c["cert"], c["key"]))
    elif "--suggest" in argv:      # tab-separated: url, verify_tls
        if res["suggest"]:
            print("%s\t%s" % (res["suggest"]["url"], "true" if res["suggest"]["verify_tls"] else "false"))
    else:
        print(json.dumps(res, indent=2))
    return 0
