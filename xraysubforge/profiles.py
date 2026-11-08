"""Profiles: several independent services in one install (each with its own panel, blocks, rules, accounts and output).

`config.json` is the default profile. Every `profiles/<name>.json` next to it is one more; it is a complete config of the
same shape. Profiles are read at startup (restart to add one). Which profile answers a request:

1. only one profile uses the requested path -> that one;
2. several share the path -> the one whose `server.hosts` holds the request's host name;
3. still several -> the profile whose panel knows the subscription id (the panels are asked at once; the answer is cached).
   An id known to more than one panel goes to the first profile (default first) and is logged once.
"""
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .accounts import AccountStore
from .config import ConfigStore
from .panel import PanelError, fetch_raw

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
CACHE_SECONDS = 3600


def _log(msg):
    print("[profiles] " + msg, file=sys.stderr, flush=True)


class Profile:
    def __init__(self, name, store):
        self.name = name
        self.store = store
        self.accounts = AccountStore(store)

    def hosts(self):
        return [h.lower() for h in self.store.get()["server"].get("hosts", [])]


def profile_dir(default_store):
    return os.path.join(os.path.dirname(os.path.abspath(default_store.path)), "profiles")


def load_profiles(default_store):
    """-> [Profile]: the default first, then profiles/*.json by name."""
    out = [Profile("default", default_store)]
    d = profile_dir(default_store)
    try:
        names = sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json"))
    except OSError:
        names = []
    for n in names:
        if not NAME_RE.match(n) or n == "default":
            _log("profiles/%s.json: the name must be lowercase letters, digits, - or _ (not 'default'); skipped" % n)
            continue
        out.append(Profile(n, ConfigStore(os.path.join(d, n + ".json"))))
    return out


def knows(profile, subid):
    """True when the profile's panel answers for this subscription id."""
    conf = profile.store.get()
    panel = conf["panel"]
    url = panel["raw_url"] if panel["source"] == "raw" else panel["url"]
    try:
        fetch_raw(url, panel, subid)
        return True
    except PanelError:
        return False
    except Exception:
        return False


class Resolver:
    def __init__(self, probe=knows):
        self.probe = probe
        self._cache = {}
        self._warned = set()
        self._lock = threading.Lock()

    def pick(self, candidates, subid):
        if len(candidates) == 1:
            return candidates[0]
        key = (subid, tuple(p.name for p in candidates))
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[1] < CACHE_SECONDS:
                return next((p for p in candidates if p.name == hit[0]), candidates[0])
        with ThreadPoolExecutor(max_workers=len(candidates)) as ex:
            found = list(ex.map(lambda p: self.probe(p, subid), candidates))
        owners = [p for p, ok in zip(candidates, found) if ok]
        if len(owners) > 1 and key not in self._warned:
            self._warned.add(key)
            _log("a subscription id exists in %d profiles (%s); using %s" % (len(owners), ", ".join(p.name for p in owners), owners[0].name))
        chosen = owners[0] if owners else candidates[0]
        if owners:                                  # only a found id is remembered; a miss may be a panel that is briefly down
            with self._lock:
                self._cache[key] = (chosen.name, now)
        return chosen
