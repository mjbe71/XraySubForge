# gunicorn reads this file automatically from the working directory: address and size come from config.json.
import os

from xraysubforge.config import ConfigStore
from xraysubforge.tlsctx import attach_sni, default_cert, new_context

_server = ConfigStore().get()["server"]
# XRAYSUBFORGE_HOST (if set) overrides server.host; the Docker image sets it to 0.0.0.0
bind = "%s:%d" % (os.environ.get("XRAYSUBFORGE_HOST") or _server["host"], _server["port"])
workers = _server["workers"]
threads = _server["threads"]
_default = default_cert(_server)
if _default:                             # HTTPS straight from gunicorn (server.tls_cert / tls_key, server.domains)
    certfile, keyfile = _default

    def ssl_context(conf, default_ssl_context_factory):     # one certificate per domain (SNI)
        return attach_sni(default_ssl_context_factory(), _server, new_context)
accesslog = None     # no access log on purpose: URLs contain each user's secret subscription id
