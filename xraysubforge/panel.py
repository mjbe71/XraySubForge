"""Fetching a user's subscription from the panel (shared by the public route and the admin preview)."""
import sys

import requests


class PanelError(Exception):
    def __init__(self, message, status):
        super().__init__(message)
        self.message, self.status = message, status


def fetch_panel(panel, subid):
    """-> (response, list of configs, parsed JSON). Raises PanelError. Never prints the URL: it holds the secret id."""
    if not panel["url"]:
        raise PanelError("panel.url is not set in config.json", 503)
    base = panel["url"] if panel["url"].endswith("/") else panel["url"] + "/"
    try:
        r = requests.get(base + subid, headers=panel["headers"], timeout=panel["timeout"], verify=panel["verify_tls"])
    except requests.RequestException as e:
        print("[panel] unreachable: %s" % type(e).__name__, file=sys.stderr, flush=True)
        raise PanelError("panel unreachable", 502)
    if r.status_code == 404:
        raise PanelError("not found", 404)
    if r.status_code != 200:
        raise PanelError("panel returned %d" % r.status_code, 502)
    try:
        data = r.json()
    except ValueError:
        raise PanelError("panel did not return JSON", 502)
    configs = data if isinstance(data, list) else [data] if isinstance(data, dict) else None
    if configs is None:
        raise PanelError("unexpected panel response", 502)
    return r, configs, data
