# gunicorn reads this file automatically from the working directory: address and size come from config.json.
import os

from xraysubforge.config import ConfigStore

_server = ConfigStore().get()["server"]
# XRAYSUBFORGE_HOST (if set) overrides server.host; the Docker image sets it to 0.0.0.0
bind = "%s:%d" % (os.environ.get("XRAYSUBFORGE_HOST") or _server["host"], _server["port"])
workers = _server["workers"]
threads = _server["threads"]
if _server["tls_cert"]:                  # HTTPS straight from gunicorn (see server.tls_cert / tls_key)
    certfile = _server["tls_cert"]
    keyfile = _server["tls_key"]
accesslog = None     # no access log on purpose: URLs contain each user's secret subscription id
