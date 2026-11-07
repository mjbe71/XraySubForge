"""The HTTP service: fetch the panel's JSON subscription, apply the rules, return the result."""
import json
import re
import sys

from flask import Flask, Response, redirect, request

from . import admin
from .accounts import AccountStore
from .config import ConfigStore
from .engine import process
from .matching import match
from .panel import PanelError, fetch_panel


def needs_account(conf, configs):
    """True when one of this user's configs is matched by an enabled chain (only then is an account of any use)."""
    chains = [c for c in conf["chains"] if c.get("enabled", True)]
    return any(match(c.get("exit_when"), cfg) for c in chains for cfg in configs if isinstance(cfg, dict))


def create_app(store=None):
    store = store or ConfigStore()
    accounts = AccountStore(store)
    app = Flask(__name__)
    app.config["JSON_AS_ASCII"] = False
    app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
    route = store.get()["server"]["route"]          # the route is fixed at startup (restart to change it)

    def text(msg, code):
        return Response(msg + "\n", status=code, mimetype="text/plain")

    @app.get("/healthz")
    def healthz():
        return text("ok", 200)

    def sub(subid):
        conf = store.get()
        if not re.search(conf["server"]["subid_regex"], subid):
            return text("not found", 404)
        panel = conf["panel"]
        if not panel["url"]:
            return text("panel.url is not set in config.json", 503)
        if panel["page_url"] and "text/html" in request.headers.get("Accept", ""):
            return redirect(panel["page_url"].rstrip("/") + "/" + subid, code=302)
        try:
            r, configs, data = fetch_panel(panel, subid)
        except PanelError as e:
            return text(e.message, e.status)
        try:
            if conf["accounts"]["register"]["enabled"] and needs_account(conf, configs):
                accounts.ensure(subid)
            out, _ = process(configs, conf, subid=subid, accounts=accounts.get(), params=request.args.to_dict())
        except Exception as e:   # better to hand out the panel's own configs than nothing
            print("[server] processing failed (%s: %s); passing the panel's response through"
                  % (type(e).__name__, e), file=sys.stderr, flush=True)
            out = configs
        body = out[0] if isinstance(data, dict) and len(out) == 1 else out
        resp = Response(json.dumps(body, ensure_ascii=False), mimetype="application/json")
        for name in panel["pass_headers"]:
            if name in r.headers:
                resp.headers[name] = r.headers[name]
        return resp

    app.add_url_rule(route.rstrip("/") + "/<subid>", "sub", sub)
    admin.register(app, store)
    app.store = store
    app.accounts = accounts
    return app
