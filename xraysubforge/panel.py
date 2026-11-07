"""Fetching a user's subscription from the panel (shared by the public route and the admin preview)."""
import sys

from urllib.parse import quote

import requests


class PanelError(Exception):
    def __init__(self, message, status):
        super().__init__(message)
        self.message, self.status = message, status


def with_id(url, subid):
    """The panel address for this id: "{id}" in the address is replaced by it, otherwise it is appended."""
    if "{id}" in url:
        return url.replace("{id}", quote(subid, safe=""))
    return (url if url.endswith("/") else url + "/") + subid


def fetch_raw(url, panel, subid):
    """The panel's reply for this id at `url` (any format) -> requests.Response. Raises PanelError. Never prints the URL."""
    if not url:
        raise PanelError("not found", 404)
    target = with_id(url, subid)
    try:
        r = requests.get(target, headers=panel["headers"], timeout=panel["timeout"], verify=panel["verify_tls"])
    except requests.RequestException as e:
        print("[panel] unreachable: %s" % type(e).__name__, file=sys.stderr, flush=True)
        raise PanelError("panel unreachable", 502)
    if r.status_code == 404:
        raise PanelError("not found", 404)
    if r.status_code != 200:
        raise PanelError("panel returned %d" % r.status_code, 502)
    return r


def raw_configs(panel, subid):
    """-> (response, configs built from the links of the raw subscription). Raises PanelError."""
    from .links import link_to_config, parse_raw
    if not panel.get("raw_url"):
        raise PanelError("panel.raw_url is not set in config.json", 503)
    r = fetch_raw(panel["raw_url"], panel, subid)
    configs = [c for c in (link_to_config(x, panel.get("json_template")) for x in parse_raw(r.content)) if c]
    return r, configs


def fetch_panel(panel, subid):
    """-> (response, list of configs, parsed JSON). Raises PanelError. Never prints the URL: it holds the secret id.
    With panel.source "raw" the configs are built from the raw subscription's links."""
    if panel.get("source") == "raw":
        r, configs = raw_configs(panel, subid)
        return r, configs, configs
    if not panel["url"]:
        raise PanelError("panel.url is not set in config.json", 503)
    r = fetch_raw(panel["url"], panel, subid)
    try:
        data = r.json()
    except ValueError:
        raise PanelError("panel did not return JSON", 502)
    configs = data if isinstance(data, list) else [data] if isinstance(data, dict) else None
    if configs is None:
        raise PanelError("unexpected panel response", 502)
    return r, configs, data
