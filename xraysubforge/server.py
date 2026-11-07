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
from .panel import PanelError, fetch_panel, fetch_raw


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

    def pass_through(panel, r):
        """The panel's reply exactly as it came (body and content type), plus the headers listed in panel.pass_headers."""
        resp = Response(r.content, status=200)
        resp.headers["Content-Type"] = r.headers.get("Content-Type", "application/octet-stream")
        for name in panel["pass_headers"]:
            if name in r.headers:
                resp.headers[name] = r.headers[name]
        return resp

    def checked(subid):
        """-> (conf, panel, error response or None): the id check and the browser redirect shared by every format."""
        conf = store.get()
        if not re.search(conf["server"]["subid_regex"], subid):
            return conf, None, text("not found", 404)
        panel = conf["panel"]
        if panel["page_url"] and "text/html" in request.headers.get("Accept", ""):
            return conf, panel, redirect(panel["page_url"].rstrip("/") + "/" + subid, code=302)
        return conf, panel, None

    def sub(subid):
        conf, panel, early = checked(subid)
        if early is not None:
            return early
        if panel["mode"] != "proxy" and not panel["url"]:
            return text("panel.url is not set in config.json", 503)
        if panel["mode"] == "proxy":                     # each format is optional: an empty URL turns that format off
            try:
                return pass_through(panel, fetch_raw(panel["url"], panel, subid))
            except PanelError as e:
                return text(e.message, e.status)
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

    def other_format(url_key):
        def view(subid):
            conf, panel, early = checked(subid)
            if early is not None:
                return early
            try:
                return pass_through(panel, fetch_raw(panel[url_key], panel, subid))
            except PanelError as e:
                return text(e.message, e.status)
        return view

    app.add_url_rule(route.rstrip("/") + "/<subid>", "sub", sub)
    for key, url_key in (("raw_route", "raw_url"), ("clash_route", "clash_url")):   # fixed at startup; 404 while the panel URL is empty
        path = store.get()["server"][key].rstrip("/")
        if path:
            app.add_url_rule(path + "/<subid>", key, other_format(url_key))
    admin.register(app, store)
    app.store = store
    app.accounts = accounts
    return app
