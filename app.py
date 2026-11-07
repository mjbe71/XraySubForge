"""WSGI entry point:  gunicorn app:app   (settings come from config.json, see README)."""
import logging
import os

from xraysubforge.server import create_app

app = create_app()

if __name__ == "__main__":      # development server
    logging.getLogger("werkzeug").setLevel(logging.ERROR)   # URLs contain secret ids: no request log
    server = app.store.get()["server"]
    tls = (server["tls_cert"], server["tls_key"]) if server["tls_cert"] else None
    app.run(host=os.environ.get("XRAYSUBFORGE_HOST") or server["host"], port=server["port"], threaded=True, ssl_context=tls)
