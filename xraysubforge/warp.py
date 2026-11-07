"""Create a Cloudflare WARP (MASQUE) account: the optional source of `{account.*}` values.

This uses Cloudflare's *unofficial* client API (the same calls the WARP apps and tools such as usque make). It may
change or rate-limit without notice, which is why it is opt-in (`accounts.register.enabled`) and a failure never
breaks a subscription. Three requests:
  1. POST  /reg        register a device with an X25519 key (the API always wants this first)
  2. PATCH /reg/<id>   switch the device key to P-256 with tunnel_type=masque (the response carries the server key)
  3. PATCH /reg/<id>   warp_enabled=true
The result is {"id", "privateKey" (base64 SEC1 DER), "address" [..], "publicKey" (server, base64 SPKI)}; secrets
(the device token, private key) are never logged.
Needs the `cryptography` package.
"""
import base64
import datetime
import os
import sys

import requests

API = "https://api.cloudflareclient.com/v0a4005"
CLIENT_VERSION = "a-6.35-4005"


class ApiError(Exception):
    pass


def _b64(raw):
    return base64.b64encode(raw).decode()


def _call(api, client_version, method, path, body=None, token=None):
    headers = {"User-Agent": "WARP for Android", "CF-Client-Version": client_version,
               "Content-Type": "application/json; charset=UTF-8", "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        r = requests.request(method, api + path, headers=headers, json=body, timeout=25)
    except requests.RequestException as e:
        raise ApiError("%s %s: network error (%s)" % (method, path, type(e).__name__))
    try:
        data = r.json()
    except ValueError:
        data = None
    if r.status_code not in (200, 201, 204):
        raise ApiError("%s %s: HTTP %d" % (method, path, r.status_code))
    return data if isinstance(data, dict) else {}


def _pem_to_b64(pub):
    pub = (pub or "").strip()
    if "BEGIN" in pub:
        pub = "".join(l for l in pub.splitlines() if not l.startswith("-----"))
    return pub


def register_account(api="", client_version="", warn=None):
    """Create one account; raises ApiError on failure."""
    try:
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
    except ImportError:
        raise ApiError("the 'cryptography' package is not installed (pip install cryptography)")
    api = api or API
    client_version = client_version or CLIENT_VERSION
    warn = warn or (lambda m: print("[warp] " + m, file=sys.stderr, flush=True))

    x = x25519.X25519PrivateKey.generate()
    xpub = x.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    reg = _call(api, client_version, "POST", "/reg", {
        "key": _b64(xpub), "install_id": "", "fcm_token": "",
        "tos": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "model": "PC", "serial_number": "", "os_version": "", "key_type": "curve25519",
        "tunnel_type": "wireguard", "locale": "en_US"})
    dev_id, token = reg.get("id"), reg.get("token")
    if not dev_id or not token:
        raise ApiError("the registration reply had no id/token")

    ec_priv = ec.generate_private_key(ec.SECP256R1())
    spki = ec_priv.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
    enr = _call(api, client_version, "PATCH", "/reg/%s" % dev_id, {
        "key": _b64(spki), "key_type": "secp256r1", "tunnel_type": "masque",
        "name": "pc-" + os.urandom(3).hex()}, token=token)

    cfg = enr.get("config") or reg.get("config") or {}
    addrs = (cfg.get("interface") or {}).get("addresses") or {}
    peers = cfg.get("peers") or []
    server_pub = _pem_to_b64(peers[0].get("public_key") if peers and isinstance(peers[0], dict) else "")
    address = [a for a in (addrs.get("v4"), addrs.get("v6")) if a]
    if not address:
        raise ApiError("the reply had no tunnel address (interface.addresses)")
    try:
        raw_len = len(base64.b64decode(server_pub + "=" * (-len(server_pub) % 4)))
    except ValueError:
        raise ApiError("the server key in the reply is not valid base64")
    if server_pub and raw_len == 32:
        raise ApiError("the server key is still a WireGuard key (32 bytes); the switch to MASQUE did not happen")

    try:
        _call(api, client_version, "PATCH", "/reg/%s" % dev_id, {"warp_enabled": True}, token=token)
    except ApiError as e:
        warn("warning: %s" % e)

    private = ec_priv.private_bytes(ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption())
    entry = {"id": dev_id, "privateKey": _b64(private), "address": address}
    if server_pub:
        entry["publicKey"] = server_pub
    return entry
