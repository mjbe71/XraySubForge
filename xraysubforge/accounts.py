"""Values for the {account.*} placeholders of `chains` (for example the keys of a WARP account).

Source: the file named by `accounts.file` and/or the inline `accounts.default`; the file wins on conflicts.
The file is JSON, in one of two shapes:

    {"privateKey": "...", "address": ["172.16.0.2"]}                       one account for everybody
    {"default": {...}, "users": {"<subscription id>": {...}, ...}}         plus a personal account per user

The file is re-read when it changes. Account values are secrets: keep the file out of git (accounts*.json is in .gitignore). The web admin panel
never lists the file's contents, but a preview of a chain shows the filled-in outbound.
"""
import json
import os
import sys
import threading
import time

try:
    import fcntl
except ImportError:          # not on Windows: no cross-process lock there
    fcntl = None


def _log(msg):
    print("[accounts] " + msg, file=sys.stderr, flush=True)


def parse(raw):
    """-> {"default": dict, "users": {id: dict}} from either file shape."""
    if not isinstance(raw, dict):
        return {"default": {}, "users": {}}
    if "default" in raw or "users" in raw:
        default = raw.get("default") if isinstance(raw.get("default"), dict) else {}
        users = raw.get("users") if isinstance(raw.get("users"), dict) else {}
        return {"default": default, "users": {k: v for k, v in users.items() if isinstance(v, dict)}}
    return {"default": {k: v for k, v in raw.items() if not k.startswith("_")}, "users": {}}


class AccountStore:
    def __init__(self, config_store, registrar=None):
        self.config_store = config_store
        self.registrar = registrar                     # tests plug a fake in; default: warp.register_account
        self._busy = {}                                # subscription id -> its lock (one registration at a time)
        self._failed = {}                              # subscription id -> time of the last failed attempt
        self._pending = set()                          # background mode: ids waiting for an account
        self._worker = None                            # background mode: the running thread
        self._last_reg = 0.0                           # time of the last registration attempt
        self._lock = threading.Lock()
        self._sig = None
        self._file_data = {"default": {}, "users": {}}

    def _file_path(self, file):
        if not file:
            return ""
        base = os.path.dirname(os.path.abspath(self.config_store.path))
        return file if os.path.isabs(file) else os.path.join(base, file)      # relative to config.json

    def get(self):
        conf = self.config_store.get()["accounts"]
        path = self._file_path(conf["file"])
        with self._lock:
            if path:
                try:
                    st = os.stat(path)
                    sig = (path, st.st_mtime_ns, st.st_size)
                    if sig != self._sig:
                        self._sig = sig
                        try:
                            with open(path, encoding="utf-8") as f:
                                self._file_data = parse(json.load(f))
                            _log("loaded %s" % os.path.basename(path))
                        except (OSError, ValueError) as e:
                            _log("cannot read %s (%s); keeping the previous values" % (os.path.basename(path), e))
                except OSError:
                    if self._sig != (path, None, None):
                        _log("%s not found" % os.path.basename(path))
                    self._sig, self._file_data = (path, None, None), {"default": {}, "users": {}}
            else:
                self._sig, self._file_data = None, {"default": {}, "users": {}}
            data = self._file_data
        default = dict(conf["default"])
        default.update(data["default"])
        return {"default": default, "users": data["users"]}

    # ---- automatic registration (accounts.register) ----
    def _registrar(self):
        if self.registrar:
            return self.registrar
        from .warp import register_account
        return register_account

    def _locked_update(self, path, fn):
        """Read-modify-write the accounts file under a lock shared by all worker processes."""
        from .admin import _write_atomic
        lock = open(path + ".lock", "a") if path else None
        try:
            if lock and fcntl:
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                with open(path, encoding="utf-8") as f:
                    raw = json.load(f)
            except FileNotFoundError:
                raw = {}
            if not isinstance(raw, dict):
                raise ValueError("%s is not a JSON object" % os.path.basename(path))
            if "default" not in raw and "users" not in raw:      # flat file: keep it as the shared account
                raw = {"default": {k: v for k, v in raw.items() if not k.startswith("_")}}
            raw.setdefault("users", {})
            result = fn(raw)
            _write_atomic(path, raw)
            return result
        finally:
            if lock:
                lock.close()

    def register(self, subid=None, force=False, pool=False):
        """Create an account and save it for `subid` (or as the shared one when None). Returns the account's id.
        Raises warp.ApiError / OSError / ValueError on failure. Already registered and not `force`: returns None."""
        conf = self.config_store.get()["accounts"]
        path = self._file_path(conf["file"])
        if not path:
            raise ValueError("accounts.file is not set; there is nowhere to save accounts")
        reg = conf["register"]
        have = self.get()
        if pool:
            entry = self._registrar()(api=reg["api"], client_version=reg["client_version"])

            def add(raw):  # one more shared account in default.pool (users without a personal account share these)
                raw.setdefault("default", {}).setdefault("pool", []).append(entry)
                return entry.get("id", "")
            return self._locked_update(path, add)
        if not force and ((subid in have["users"]) if subid else bool(have["default"])):
            return None                                # already has one: do not ask the API for nothing
        entry = self._registrar()(api=reg["api"], client_version=reg["client_version"])

        def put(raw):
            if subid is None:
                if raw.get("default") and not force:
                    return None
                raw["default"] = entry
            else:
                if subid in raw["users"] and not force:
                    return None
                raw["users"][subid] = entry
            return entry.get("id", "")
        return self._locked_update(path, put)

    def ensure(self, subid):
        """Called for a subscription request that needs an account: make a personal account when automatic registration
        is on and this user has none yet. Never raises. A failure is remembered for `retry_seconds` so the registration API
        is not hammered; `min_interval_seconds` and `max_users` limit the pace and the total. With `background` the
        request never waits: the id is queued and a worker thread registers it (the user meanwhile gets a shared account)."""
        conf = self.config_store.get()["accounts"]
        reg = conf["register"]
        if not reg["enabled"] or not subid:
            return
        users = self.get()["users"]
        if subid in users or (reg["max_users"] and len(users) >= reg["max_users"]):
            return
        if reg["background"]:
            with self._lock:
                if subid in self._pending:
                    return
                self._pending.add(subid)
                if self._worker and self._worker.is_alive():
                    return
                self._worker = threading.Thread(target=self._work, name="warp-register", daemon=True)
                self._worker.start()
            return
        if time.time() - self._last_reg < reg["min_interval_seconds"]:
            return                                     # too soon after the last one: the next fetch tries again
        self._try_register(subid, reg)

    def _try_register(self, subid, reg):
        now = time.time()
        with self._lock:
            if now - self._failed.get(subid, 0) < reg["retry_seconds"]:
                return
            lock = self._busy.setdefault(subid, threading.Lock())
        if not lock.acquire(blocking=False):
            return                                     # another request is already registering this user
        try:
            if subid in self.get()["users"]:
                return
            self._last_reg = time.time()
            new_id = self.register(subid)
            if new_id is not None:
                _log("created an account for a new user (device %s)" % (new_id or "?"))
        except Exception as e:
            with self._lock:
                self._failed[subid] = time.time()
            _log("could not create an account (%s: %s); will retry in %ds" % (
                type(e).__name__, e, reg["retry_seconds"]))
        finally:
            lock.release()

    def _work(self):
        while True:
            with self._lock:
                if not self._pending:
                    self._worker = None
                    return
                subid = self._pending.pop()
            reg = self.config_store.get()["accounts"]["register"]
            users = self.get()["users"]
            if not reg["enabled"] or subid in users or (reg["max_users"] and len(users) >= reg["max_users"]):
                continue
            wait = reg["min_interval_seconds"] - (time.time() - self._last_reg)
            if wait > 0:
                time.sleep(wait)
            self._try_register(subid, reg)
