"""Command line:

    python -m xraysubforge menu [--config FILE]        interactive terminal menu (also: just `xraysubforge`)
    python -m xraysubforge serve                       development server (use gunicorn in production)
    python -m xraysubforge check [config.json]         validate a configuration
    python -m xraysubforge hash-password               make a value for admin.password_hash
    python -m xraysubforge set-admin-password [--stdin]    set the admin password in config.json
    python -m xraysubforge config-get KEY              print a setting (e.g. server.port)
    python -m xraysubforge config-set KEY=VALUE ...    change settings in config.json (VALUE is JSON or text)
    python -m xraysubforge register-account [--subid ID]   create a WARP account now and save it in accounts.file
    python -m xraysubforge register-account --pool [--count N]   add shared accounts to the pool
    python -m xraysubforge prune-accounts [--dry-run]  remove the accounts of users the panel no longer has (accounts.prune)
    python -m xraysubforge detect-xui [--certs|--suggest]  look for a 3x-ui panel on this machine
    python -m xraysubforge preview panel.json [config.json] [--subid ID] [--full]
                                                      run the rules on a saved panel response, no network
"""
import argparse
import json
import logging
import os
import sys

from .accounts import AccountStore
from .admin import _write_atomic
from .config import CONFIG_ENV, ConfigStore, split_problems
from .engine import process
from .server import create_app


def _path(arg):
    return arg or os.environ.get(CONFIG_ENV) or "config.json"


def _load_raw(path):
    """The config file as a dict; {} if it does not exist; ValueError if it is not a JSON object (never overwrite it then)."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("%s is not a JSON object" % path)
    return raw


def _parse_value(text):
    try:
        return json.loads(text)
    except ValueError:
        return text


def _dotted_set(obj, dotted, value):
    parts = dotted.split(".")
    for p in parts[:-1]:
        if not isinstance(obj.get(p), dict):
            obj[p] = {}
        obj = obj[p]
    if value is _UNSET:
        obj.pop(parts[-1], None)
    else:
        obj[parts[-1]] = value


_UNSET = object()


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["detect-xui"]:
        from . import xui
        return xui.main(argv[1:])
    ap = argparse.ArgumentParser(prog="xraysubforge")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("config", nargs="?")
    c = sub.add_parser("check")
    c.add_argument("config", nargs="?")
    sub.add_parser("hash-password", help="make a value for admin.password_hash")
    sa = sub.add_parser("set-admin-password")
    sa.add_argument("--config")
    sa.add_argument("--stdin", action="store_true", help="read the password from the first line of stdin")
    cg = sub.add_parser("config-get")
    cg.add_argument("key")
    cg.add_argument("--config")
    cs = sub.add_parser("config-set")
    cs.add_argument("items", nargs="+", help="KEY=VALUE (VALUE is JSON or plain text); with --unset: KEYs")
    cs.add_argument("--unset", action="store_true")
    cs.add_argument("--config")
    sub.add_parser("detect-xui")
    mn = sub.add_parser("menu")
    mn.add_argument("--config")
    ra = sub.add_parser("register-account")
    ra.add_argument("--subid", help="save it as this subscription id's account (default: the shared account)")
    ra.add_argument("--force", action="store_true", help="replace an existing account")
    ra.add_argument("--pool", action="store_true", help="add one more SHARED account to the pool (accounts.default.pool)")
    ra.add_argument("--count", type=int, default=1, help="with --pool: how many accounts to add")
    ra.add_argument("--delay", type=int, default=30, help="with --pool and --count: seconds between registrations")
    ra.add_argument("--config")
    pa = sub.add_parser("prune-accounts")
    pa.add_argument("--dry-run", action="store_true", help="only count; change nothing")
    pa.add_argument("--config")
    p = sub.add_parser("preview")
    p.add_argument("panel_json")
    p.add_argument("config", nargs="?")
    p.add_argument("--subid", help="use this subscription id's personal account values")
    p.add_argument("--full", action="store_true", help="print the resulting configs too")
    a = ap.parse_args(argv)

    if a.cmd == "menu":
        from . import tui
        return tui.run(_path(a.config))

    if a.cmd == "hash-password":
        import getpass
        from werkzeug.security import generate_password_hash
        pw = getpass.getpass("Admin password: ")
        if not pw or pw != getpass.getpass("Again: "):
            print("Empty or different passwords; nothing done.", file=sys.stderr)
            return 1
        print(generate_password_hash(pw))
        return 0

    if a.cmd == "set-admin-password":
        from werkzeug.security import generate_password_hash
        path = _path(a.config)
        if a.stdin:
            pw = sys.stdin.readline().rstrip("\n")
        else:
            from .tui import ask_password
            pw = ask_password("New admin password (at least 8 characters)") or ""
        if len(pw) < 8:
            print("Use at least 8 characters; nothing changed.", file=sys.stderr)
            return 1
        try:
            raw = _load_raw(path)
        except (OSError, ValueError) as e:
            print("Cannot use %s: %s" % (path, e), file=sys.stderr)
            return 1
        admin = raw.get("admin") if isinstance(raw.get("admin"), dict) else {}
        admin["password_hash"] = generate_password_hash(pw)
        admin.pop("password", None)
        raw["admin"] = admin
        _write_atomic(path, raw)
        print("Admin password set in %s" % path)
        return 0

    if a.cmd == "config-set":
        path = _path(a.config)
        try:
            raw = _load_raw(path)
        except (OSError, ValueError) as e:
            print("Cannot use %s: %s" % (path, e), file=sys.stderr)
            return 1
        for item in a.items:
            if a.unset:
                _dotted_set(raw, item, _UNSET)
            elif "=" in item:
                k, v = item.split("=", 1)
                _dotted_set(raw, k, _parse_value(v))
            else:
                print("Expected KEY=VALUE, got %r" % item, file=sys.stderr)
                return 1
        _write_atomic(path, raw)
        return 0

    store = ConfigStore(_path(getattr(a, "config", None)) if a.cmd in ("config-get", "register-account", "prune-accounts") else a.config)
    if a.cmd == "prune-accounts":
        rep = AccountStore(store).prune(dry=a.dry_run)
        print("%d users with an account, %d missing on the panel, %d %s, %d waiting for accounts.prune.after_days"
              % (rep["users"], rep["missing"], rep["removed"], "would be removed" if a.dry_run else "removed", rep["waiting"]))
        if rep["error"]:
            print(rep["error"], file=sys.stderr)
            return 1
        return 0
    if a.cmd == "register-account" and a.pool:
        import time
        from .warp import ApiError
        done = 0
        for i in range(max(1, a.count)):
            try:
                AccountStore(store).register(pool=True)
            except (ApiError, ValueError, OSError) as e:
                print("Could not create the account: %s (%d added)" % (e, done), file=sys.stderr)
                return 1
            done += 1
            print("[%d/%d] shared account added to the pool" % (done, a.count))
            if i + 1 < a.count:
                time.sleep(a.delay)
        return 0
    if a.cmd == "register-account":
        from .warp import ApiError
        try:
            new_id = AccountStore(store).register(a.subid, force=a.force)
        except (ApiError, ValueError, OSError) as e:
            print("Could not create the account: %s" % e, file=sys.stderr)
            return 1
        print("Already has an account (use --force to replace it)." if new_id is None
              else "Account created (device %s)." % new_id)
        return 0
    if a.cmd == "config-get":
        cur = store.get()
        for part in a.key.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur is None:
            return 1
        print(cur if isinstance(cur, str) else json.dumps(cur))
        return 0
    if a.cmd == "check":
        errors = split_problems(store.problems)[0]
        print("OK" if not errors else "%d problem(s) listed above" % len(errors))
        return 1 if errors else 0
    if a.cmd == "serve":
        logging.getLogger("werkzeug").setLevel(logging.ERROR)   # the URL contains the secret id: no request log
        srv = store.get()["server"]
        from .tlsctx import server_context
        tls = server_context(srv)
        create_app(store).run(host=os.environ.get("XRAYSUBFORGE_HOST") or srv["host"], port=srv["port"], threaded=True,
                              ssl_context=tls)
        return 0

    with open(a.panel_json, encoding="utf-8") as f:
        data = json.load(f)
    out, report = process(data if isinstance(data, list) else [data], store.get(), subid=a.subid,
                         accounts=AccountStore(store).get())
    for c in report["configs"]:
        where = ("-> " + ", ".join(c["groups"])) if c["groups"] else ""
        print("%2d  %-9s %-28s %s %s" % (c["index"], c["action"] + ("*" if c["rule"] else ""),
                                         c["remark"], c["fields"].get("network", ""), where))
    print("\n(* = decided by rule; drop = removed; groups listed after ->)\n")
    for o in report["outputs"]:
        print("group %-14s -> %s  (%d members)" % (o["group"], o["remark"], o["members"]))
    print("\noutput order:")
    for i, cfg in enumerate(out):
        print("  %2d  %s" % (i, cfg.get("remarks")))
    for e in report["errors"]:
        print("ERROR:", e, file=sys.stderr)
    if a.full:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
