"""Terminal menu for the admin (English only, standard library only):  xraysubforge   (or: python -m xraysubforge menu)

Everything the web admin panel can do for the basics: service control, panel/network/HTTPS settings, the admin password,
rules/groups/chains/patches (guided questions, or the item as JSON in your editor), a live preview and WARP accounts.
Every change is validated first and written atomically to config.json; the running service picks it up by itself.
"""
import copy
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

from .accounts import AccountStore
from .admin import _write_atomic
from .config import CONFIG_ENV, ConfigStore, normalize, split_problems
from .engine import process
from .matching import FIELDS, OPS
from .panel import PanelError, fetch_panel
from .profiles import NAME_RE

KINDS = (("rules", "Rules (keep / drop / pin configs)"), ("groups", "Groups (balancers)"),
         ("chains", "Chains (dial an outbound through an exit)"), ("patches", "Patches (merge your own JSON)"))
RULE_DO = ("keep", "drop", "pin_top", "pin_bottom")
NUMERIC = ("gt", "gte", "lt", "lte")


class Quit(Exception):
    pass


def say(text=""):
    print(text)


def ask(prompt, default=None):
    try:
        v = input("%s%s: " % (prompt, " [%s]" % default if default not in (None, "") else "")).strip()
    except EOFError:
        raise Quit()
    return v if v != "" else (default if default is not None else "")


def yes(prompt, default=True):
    v = ask("%s (%s)" % (prompt, "Y/n" if default else "y/N")).lower()
    return default if v == "" else v.startswith("y")


def choose(title, options, back="Back"):
    """options: list of labels -> index, or None for back."""
    say("\n" + title)
    for i, o in enumerate(options, 1):
        say("  %d) %s" % (i, o))
    say("  0) %s" % back)
    while True:
        v = ask("Choose")
        if v in ("0", "q", ""):
            return None
        if v.isdigit() and 1 <= int(v) <= len(options):
            return int(v) - 1
        say("Enter a number from the list.")


def ask_password(prompt="New password (at least 8 characters)"):
    """The password is typed in the open on purpose (typos are easier to spot); say so. -> str, or None if too short."""
    say("Note: the password is shown on screen while you type it. Make sure nobody is watching.")
    pw = ask(prompt)
    if len(pw) < 8:
        say("Too short (8 or more characters); nothing changed.")
        return None
    return pw


class Menu:
    def __init__(self, path=None):
        self.path = path or os.environ.get(CONFIG_ENV) or "config.json"
        self.default_path = self.path                      # profiles/<name>.json sit next to it
        self.ctl = os.environ.get("XSF_CTL", "")          # the `sforge` wrapper (set by the installer)

    # ---------- config file ----------
    def raw(self):
        if not os.path.exists(self.path):
            return {}
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("%s is not a JSON object" % self.path)
        return data

    def store(self):
        if getattr(self, "_store", None) is None:        # one store: it re-reads the file when it changes, and logs once
            self._store = ConfigStore(self.path)
        return self._store

    def save(self, raw):
        """Validate, then write. Returns True if written."""
        errors, warnings = split_problems(normalize(raw)[1])
        if errors:
            say("Not saved. Problems:")
            for e in errors:
                say("  - " + e)
            return False
        _write_atomic(self.path, raw)
        for w in warnings:
            say("  note: " + w)
        say("Saved. The service picks the change up by itself.")
        return True

    def update(self, fn):
        """fn(raw) edits the dict in place; then validate and save."""
        try:
            raw = self.raw()
        except (OSError, ValueError) as e:
            say("Cannot use %s: %s" % (self.path, e))
            return False
        try:
            fn(raw)
        except OSError as e:
            say("Error: %s" % e)
            return False
        try:
            return self.save(raw)
        except OSError as e:
            say("Cannot write %s: %s (run with sudo?)" % (self.path, e.strerror or e))
            return False

    # ---------- helpers ----------
    def run_ctl(self, *args):
        if not self.ctl or not os.path.exists(self.ctl):
            say("Not available: this works when installed with install.sh (the `sforge` command).")
            return
        subprocess.call([self.ctl] + list(args))

    def editor(self, text, suffix=".json"):
        ed = os.environ.get("VISUAL") or os.environ.get("EDITOR") or next(
            (e for e in ("nano", "vim", "vi") if subprocess.call(["which", e], stdout=subprocess.DEVNULL,
                                                                 stderr=subprocess.DEVNULL) == 0), None)
        if not ed:
            return None
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as f:
            f.write(text)
            tmp = f.name
        try:
            subprocess.call(shlex.split(ed) + [tmp])
            with open(tmp, encoding="utf-8") as f:
                return f.read()
        finally:
            os.unlink(tmp)

    def edit_json(self, obj, hint=""):
        """Let the admin edit `obj` as JSON (editor if present, else paste). Returns the new value or None (cancelled)."""
        text = json.dumps(obj, indent=2, ensure_ascii=False)
        while True:
            if hint:
                say(hint)
            out = self.editor(text)
            if out is None:
                say("No editor found (set $EDITOR). Paste the JSON, finish with an empty line, or just an empty line to cancel:")
                lines = []
                while True:
                    line = input()
                    if not line.strip():
                        break
                    lines.append(line)
                out = "\n".join(lines)
                if not out.strip():
                    return None
            try:
                return json.loads(out)
            except ValueError as e:
                say("Not valid JSON: %s" % e)
                if not yes("Edit again?"):
                    return None
                text = out

    def conditions(self, title="Conditions (all must match)"):
        """Guided `when` builder. Returns a dict (maybe empty = matches everything)."""
        when = {}
        say("\n%s. Fields: %s, or a JSON path like streamSettings.network" % (title, ", ".join(FIELDS)))
        while True:
            f = ask("Field (empty = done)")
            if not f:
                return when
            ops = sorted(OPS)
            i = choose("Operator for %s" % f, ops, back="Cancel this condition")
            if i is None:
                continue
            op, val = ops[i], None
            if op == "exists":
                val = yes("Must exist?", True)
            else:
                text = ask("Value" + (" (comma separated list)" if op in ("in", "not_in") else ""))
                if op in ("in", "not_in"):
                    val = [t.strip() for t in text.split(",") if t.strip()]
                elif op in NUMERIC:
                    try:
                        val = float(text) if "." in text else int(text)
                    except ValueError:
                        say("A number is needed.")
                        continue
                else:
                    val = text
                if op in ("regex", "iregex"):
                    try:
                        re.compile(val)
                    except re.error as e:
                        say("Invalid regex: %s" % e)
                        continue
            when.setdefault(f, {})[op] = val
            say("  added: %s %s %s" % (f, op, json.dumps(val, ensure_ascii=False)))

    # ---------- screens ----------
    def header(self):
        try:
            conf = self.store().get()
        except Exception as e:
            say("(config unreadable: %s)" % e)
            return
        s, p = conf["server"], conf["panel"]
        scheme = "https" if s["tls_cert"] else "http"
        say("\n=== XraySubForge ===")
        say("config: %s%s" % (self.path, "" if self.path == self.default_path else "   (profile %s)" % os.path.basename(self.path)[:-5]))
        say("listens on %s://%s:%s%s   panel: %s" % (scheme, s["host"], s["port"], s["route"], p["url"] or "(not set)"))
        say("blocks %d   old-style items: rules %d, groups %d, chains %d, patches %d   web admin: %s" % (
            len(conf["blocks"]["list"]), len(conf["rules"]), len(conf["groups"]), len(conf["chains"]), len(conf["patches"]),
            "on" if (conf["admin"]["password"] or conf["admin"]["password_hash"]) else "off (no password)"))

    def main(self):
        items = [("Service (status, restart, logs, update)", self.service_menu),
                 ("Panel and subscription link", self.panel_menu),
                 ("Network and HTTPS", self.network_menu),
                 ("Web admin panel (password)", self.admin_menu),
                 ("Blocks (the final subscription, as JSON in your editor)", self.blocks_menu),
                 ("Rules, groups, chains, patches (the old way)", self.items_menu),
                 ("Preview the result for a subscription id", self.preview),
                 ("WARP accounts", self.accounts_menu),
                 ("Edit the whole config.json in your editor", self.edit_all),
                 ("Check the configuration", self.check),
                 ("Profiles (switch to another service, or add one)", self.profile_menu),
                 ("Uninstall XraySubForge from this server", self.uninstall)]
        while True:
            self.header()
            i = choose("Main menu", [x[0] for x in items], back="Quit")
            if i is None:
                return 0
            try:
                items[i][1]()
            except (OSError, ValueError) as e:
                say("Error: %s" % e)

    # ---------- profiles ----------
    def profile_names(self):
        d = os.path.join(os.path.dirname(os.path.abspath(self.default_path)), "profiles")
        try:
            return ["default"] + sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json") and NAME_RE.match(f[:-5]))
        except OSError:
            return ["default"]

    def profile_menu(self):
        names = self.profile_names()
        cur = "default" if self.path == self.default_path else os.path.basename(self.path)[:-5]
        i = choose("Profiles (now: %s). Rename and delete are in the web admin (Advanced > Profile)." % cur,
                   ["Switch to %s" % n + ("  (current)" if n == cur else "") for n in names] + ["Add a profile"])
        if i is None:
            return
        d = os.path.join(os.path.dirname(os.path.abspath(self.default_path)), "profiles")
        if i < len(names):
            self.path = self.default_path if names[i] == "default" else os.path.join(d, names[i] + ".json")
            self._store = None
            say("Now working on profile %s." % names[i])
            return
        name = ask("Name of the new profile (lowercase letters, digits, - or _)").strip()
        if not NAME_RE.match(name) or name == "default" or name in names:
            say("Not created: use a new name of lowercase letters, digits, - or _ (not 'default').")
            return
        copy_from = None
        if choose("Start from", ["An empty profile", "A copy of %s (its accounts are not copied)" % cur], back="Cancel") == 1:
            copy_from = self.raw()
        new = dict(copy_from or {})
        new.pop("admin", None)
        new.pop("accounts", None)
        if isinstance(new.get("server"), dict):
            new["server"] = {k: v for k, v in new["server"].items() if k != "hosts"}
        os.makedirs(d, exist_ok=True)
        _write_atomic(os.path.join(d, name + ".json"), new)
        say("Profile %s created. Restart the service so its routes are active; switch to it here to edit it." % name)

    def service_menu(self):
        acts = [("Status", ("status",)), ("Restart", ("restart",)), ("Show logs (Ctrl+C to stop)", ("logs",)),
                ("Update to the newest version", ("update",)), ("Stop", ("stop",)), ("Start", ("start",))]
        while True:
            i = choose("Service", [a[0] for a in acts])
            if i is None:
                return
            try:
                self.run_ctl(*acts[i][1])
            except KeyboardInterrupt:
                say()

    def panel_menu(self):
        while True:
            conf = self.store().get()
            p, s = conf["panel"], conf["server"]
            scheme = "https" if s["tls_cert"] else "http"
            i = choose("Panel and subscription", [
                "Show the subscription link format", "Panel JSON-subscription URL: %s" % (p["url"] or "(not set)"),
                "Panel raw-subscription URL: %s" % (p["raw_url"] or "(not set)"),
                "Where the configs come from: %s" % ("the raw links (JSON built here)" if p["source"] == "raw" else "the JSON subscription"),
                "Raw link for users: %s" % ("with the rules and blocks" if p["raw_mode"] == "engine" else "the panel's links, unchanged"),
                "Verify the panel's TLS certificate: %s" % ("yes" if p["verify_tls"] else "no"),
                "Panel timeout: %ss" % p["timeout"], "Test the panel with a subscription id"])
            if i is None:
                return
            if i == 0:
                say("  %s://<your-domain>:%s%s<subscription id>" % (scheme, s["port"], s["route"]))
            elif i == 1:
                v = ask("New URL (e.g. https://panel.example.com:2096/json/)", p["url"])
                self.update(lambda r: r.setdefault("panel", {}).__setitem__("url", v))
            elif i == 2:
                v = ask("New URL (e.g. https://panel.example.com:2096/sub/), empty = off", p["raw_url"])
                self.update(lambda r: r.setdefault("panel", {}).__setitem__("raw_url", v))
            elif i == 3:
                say("  The JSON subscription is the better source: it carries everything the panel knows. Raw links lose")
                say("  fragment / Final Mask, mux, sockopt and the panel's DNS and routing, and some types (masque, hysteria2,")
                say("  tuic, wireguard) are not read at all. Use raw links only when you cannot turn the JSON subscription on.")
                v = "raw" if yes("Build the JSON from the raw links?", p["source"] == "raw") else "json"
                self.update(lambda r: r.setdefault("panel", {}).__setitem__("source", v))
            elif i == 4:
                v = "engine" if yes("Apply the rules and blocks to the raw link too?", p["raw_mode"] == "engine") else "pass"
                self.update(lambda r: r.setdefault("panel", {}).__setitem__("raw_mode", v))
            elif i == 5:
                v = yes("Verify the certificate?", p["verify_tls"])
                self.update(lambda r: r.setdefault("panel", {}).__setitem__("verify_tls", v))
            elif i == 6:
                v = ask("Timeout in seconds", p["timeout"])
                try:
                    num = float(v)
                except ValueError:
                    say("A number is needed.")
                    continue
                self.update(lambda r: r.setdefault("panel", {}).__setitem__("timeout", int(num) if num == int(num) else num))
            elif i == 7:
                sid = ask("Subscription id")
                if sid:
                    try:
                        _, cfgs, _ = fetch_panel(p, sid)
                        say("OK: the panel returned %d config(s)." % len(cfgs))
                    except PanelError as e:
                        say("Failed: %s" % e.message)

    def network_menu(self):
        while True:
            s = self.store().get()["server"]
            i = choose("Network and HTTPS", [
                "Port: %s" % s["port"], "Listen address: %s" % s["host"], "Route: %s" % s["route"],
                "HTTPS: %s" % (("on (%s)" % s["tls_cert"]) if s["tls_cert"] else "off"),
                "Set up or change HTTPS (certificate files or Let's Encrypt)"])
            if i is None:
                return
            if i in (0, 1, 2):
                key = ("port", "host", "route")[i]
                v = ask(key, s[key])
                if key == "port":
                    if not v.isdigit():
                        say("A number is needed.")
                        continue
                    v = int(v)
                self.update(lambda r: r.setdefault("server", {}).__setitem__(key, v))
                say("Restart the service for this to take effect (Service > Restart).")
            elif i == 3:
                say("Use the last option to change HTTPS.")
            elif i == 4:
                self.run_ctl("tls")

    def admin_menu(self):
        i = choose("Web admin panel", ["Set or change the password (turns the web admin on)",
                                       "Turn the web admin off (remove the password)"])
        if i == 0:
            from werkzeug.security import generate_password_hash
            pw = ask_password()
            if pw is None:
                return

            def setpw(r):
                a = r.get("admin") if isinstance(r.get("admin"), dict) else {}
                a["password_hash"] = generate_password_hash(pw)
                a.pop("password", None)
                r["admin"] = a
            if self.update(setpw):
                say("Admin address: <your link base>%s" % self.store().get()["admin"]["path"])
        elif i == 1 and yes("Really turn the web admin off?", False):
            def off(r):
                a = r.get("admin") if isinstance(r.get("admin"), dict) else {}
                a.pop("password", None)
                a.pop("password_hash", None)
                r["admin"] = a
            self.update(off)

    # ---------- rules / groups / chains / patches ----------
    @staticmethod
    def summarize(kind, it):
        flag = "" if it.get("enabled", True) else " [off]"
        w = it.get("when") or it.get("exit_when")
        extra = {"rules": it.get("do", ""), "groups": it.get("type", ""), "chains": "through exit",
                 "patches": "%s/%s" % (it.get("stage", "source"), it.get("target", "config"))}[kind]
        return "%s%s  (%s)  when: %s" % (it.get("id", "?"), flag, extra,
                                         json.dumps(w, ensure_ascii=False) if w else "everything")

    def items_menu(self):
        i = choose("What do you want to edit?", [k[1] for k in KINDS])
        if i is not None:
            self.kind_menu(KINDS[i][0])

    def kind_menu(self, kind):
        while True:
            items = [x for x in (self.raw().get(kind) or []) if isinstance(x, dict)]
            say("\n%s (%d)" % (kind, len(items)))
            for n, it in enumerate(items, 1):
                say("  %d. %s" % (n, self.summarize(kind, it)))
            if kind == "rules":
                say("  (the first matching rule decides, so order matters)")
            i = choose("Actions", ["Add (guided)", "Edit one as JSON", "Turn one on/off", "Move one", "Delete one", "Show one"])
            if i is None:
                return
            if i == 0:
                self.add(kind, items)
                continue
            if not items:
                say("Nothing here yet.")
                continue
            n = ask("Which number?")
            if not (n.isdigit() and 1 <= int(n) <= len(items)):
                say("Not a valid number.")
                continue
            idx = int(n) - 1
            ident = items[idx].get("id")
            if i == 1:
                new = self.edit_json(items[idx])
                if isinstance(new, dict):
                    self.update(lambda r: self._replace(r, kind, ident, new))
            elif i == 2:
                self.update(lambda r: self._find(r, kind, ident).__setitem__("enabled", not self._find(r, kind, ident).get("enabled", True)))
            elif i == 3:
                to = ask("Move to position (1-%d)" % len(items))
                if to.isdigit() and 1 <= int(to) <= len(items):
                    self.update(lambda r: r[kind].insert(int(to) - 1, r[kind].pop(idx)))
            elif i == 4:
                if yes("Delete %r?" % ident, False):
                    self.update(lambda r: r[kind].pop(idx))
            elif i == 5:
                say(json.dumps(items[idx], indent=2, ensure_ascii=False))

    @staticmethod
    def _find(raw, kind, ident):
        return next(x for x in raw[kind] if isinstance(x, dict) and x.get("id") == ident)

    def _replace(self, raw, kind, ident, new):
        lst = raw[kind]
        lst[lst.index(self._find(raw, kind, ident))] = new

    def add(self, kind, items):
        used = {x.get("id") for x in items}
        base = {"rules": "rule", "groups": "group", "chains": "chain", "patches": "patch"}[kind]
        n = 1
        while "%s-%d" % (base, n) in used:
            n += 1
        ident = ask("Id (a short name)", "%s-%d" % (base, n))
        if ident in used:
            say("That id is already used.")
            return
        item = {"id": ident}
        if kind == "rules":
            item["when"] = self.conditions()
            i = choose("What should happen to matching configs?", [
                "keep (stop here, nothing later can drop them)", "drop (remove them)", "pin_top (move to the top)",
                "pin_bottom (move to the bottom)"], back="Cancel")
            if i is None:
                return
            item["do"] = RULE_DO[i]
        elif kind == "groups":
            item["when"] = self.conditions("Which configs become members (all must match)")
            item["type"] = ask("Balancer type (leastLoad, leastPing, random, roundRobin, ...)", "leastLoad")
            if yes("Make one balancer per group of configs (split by a regex on a field)?", False):
                item["split_by"] = {"field": ask("Field", "remark"), "regex": ask("Regex; the first (group) is the bucket name")}
            name = ask("Name of the resulting config (use {split}, {n}, {group}; empty = default)")
            if name:
                item["name"] = name
            if item["type"] in ("leastLoad", "leastPing"):
                say("This type needs a probe. Defaults are not assumed: set it in the JSON editor next.")
        elif kind == "chains":
            item["exit_when"] = self.conditions("Which configs are the exit (all must match)")
            say("Next: the entry outbound as JSON. Placeholders: {account.KEY}, {exit.FIELD}, {split}, {n}.")
            entry = self.edit_json({"protocol": "", "settings": {}, "streamSettings": {}})
            if not isinstance(entry, dict):
                return
            item["entry"] = entry
        else:
            item["when"] = self.conditions("Which configs are changed (empty = all)")
            item["stage"] = "output" if choose("Apply at which stage?", [
                "source (before rules and groups)", "output (after everything)"], back="source") == 1 else "source"
            item["target"] = "outbound" if choose("What to change?", [
                "the whole config", "its main outbound"], back="the whole config") == 1 else "config"
            merge = self.edit_json({}, "Write the JSON to merge in (null deletes a key).")
            if not isinstance(merge, dict):
                return
            item["merge"] = merge
        if kind in ("groups",) and item["type"] in ("leastLoad", "leastPing"):
            full = self.edit_json(item, "Add a \"probe\" object (and \"params\" if you want), then save.")
            if isinstance(full, dict):
                item = full
        for k in ("when", "exit_when"):
            if k in item and not item[k]:
                del item[k]                       # empty conditions = matches everything: leave the key out
        self.update(lambda r: r.setdefault(kind, []).append(item))

    # ---------- preview / accounts / whole file ----------
    def preview(self):
        sid = ask("Subscription id")
        if not sid:
            return
        store = self.store()
        conf = store.get()
        try:
            _, cfgs, _ = fetch_panel(conf["panel"], sid)
        except PanelError as e:
            say("Cannot fetch from the panel: %s" % e.message)
            return
        out, report = process(cfgs, conf, subid=sid, accounts=AccountStore(store).get())
        say("\nFrom the panel (%d configs):" % len(cfgs))
        for c in report["configs"]:
            say("  %2d  %-9s %s %s" % (c["index"], c["action"] + ("*" if c["rule"] else ""), c["remark"],
                                       ("-> " + ", ".join(c["groups"])) if c["groups"] else ""))
        say("\nWhat the user gets (%d):" % len(out))
        for k, c in enumerate(out):
            say("  %2d  %s" % (k, c.get("remarks")))
        for e in report["errors"]:
            say("PROBLEM: " + e)
        if yes("Show the full JSON?", False):
            say(json.dumps(out, indent=2, ensure_ascii=False))

    def accounts_menu(self):
        conf = self.store().get()["accounts"]
        say("\nAccounts file: %s   automatic registration: %s" % (conf["file"] or "(not set)",
                                                                   "on" if conf["register"]["enabled"] else "off"))
        i = choose("WARP accounts", ["Set the accounts file", "Turn automatic registration on or off",
                                     "Create an account now"])
        if i == 0:
            self.update(lambda r: r.setdefault("accounts", {}).__setitem__("file", ask("File name or path", conf["file"] or "accounts.json")))
        elif i == 1:
            on = yes("Create a WARP account automatically for each new user? (uses Cloudflare's unofficial API)",
                     conf["register"]["enabled"])

            def toggle(r):
                a = r.setdefault("accounts", {})
                if on and not (a.get("file") or conf["file"]):
                    a["file"] = "accounts.json"
                a.setdefault("register", {})["enabled"] = on
            self.update(toggle)
        elif i == 2:
            from .warp import ApiError
            sid = ask("Subscription id (empty = the shared account)") or None
            try:
                new_id = AccountStore(self.store()).register(sid)
                say("Already has an account." if new_id is None else "Account created (device %s)." % new_id)
            except (ApiError, ValueError, OSError) as e:
                say("Could not create the account: %s" % e)

    def uninstall(self):
        if not self.ctl:
            say("Not available: this works when installed with install.sh. (Otherwise just delete the folder.)")
            return
        i = choose("Uninstall", ["Remove the program and the service, KEEP my settings and certificates (config.json)",
                                 "Remove EVERYTHING (program, service, settings, certificate copies, service user)"])
        if i is None:
            return
        say("\nThis stops the subscription service: users will no longer get their subscriptions from this server.")
        say("Not touched: the 3x-ui panel, and certificates that Let's Encrypt/certbot or 3x-ui keep for themselves.")
        if ask("Type 'yes' to continue") != "yes":
            say("Nothing removed.")
            return
        self.run_ctl("uninstall", "--yes", *(["--purge"] if i == 1 else []))
        raise Quit()

    def blocks_menu(self):
        blocks = self.store().get()["blocks"]
        say("\nBlocks, from the top (the web admin panel's Blocks tab edits them with drag and drop):")
        for b in blocks["list"]:
            say("  %-10s %-24s %d kind(s)%s" % (b.get("type", "list"), b.get("name") or b["id"], len(b.get("kinds") or []),
                                                "  [off]" if b.get("enabled") is False else ""))
        if not blocks["list"]:
            say("  (none)")
        say("  everything else: %s" % blocks["rest"])
        if not yes("Edit them as JSON?", False):
            return
        raw = self.raw()
        new = self.edit_json(raw.get("blocks", {"rest": "keep", "list": []}), "The block layout (see docs/config-reference.md, `blocks`).")
        if isinstance(new, dict):
            raw["blocks"] = new
            self.save(raw)

    def edit_all(self):
        new = self.edit_json(self.raw(), "Editing the whole config.json (the admin section included).")
        if isinstance(new, dict):
            self.save(new)

    def check(self):
        store = self.store()
        errors, warnings = split_problems(store.problems)
        for e in errors:
            say("ERROR: " + e)
        for w in warnings:
            say("note: " + w)
        say("OK" if not errors else "%d problem(s)" % len(errors))


def run(path=None):
    if not sys.stdin.isatty():
        print("The menu needs an interactive terminal.", file=sys.stderr)
        return 1
    try:
        return Menu(path).main()
    except (Quit, KeyboardInterrupt):
        print()
        return 0
