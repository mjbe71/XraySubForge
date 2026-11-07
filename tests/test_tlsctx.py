"""One certificate per domain (SNI) and the server.domains setting."""
import os
import ssl
import subprocess
import tempfile
import unittest

from xraysubforge.config import normalize
from xraysubforge.tlsctx import _matches, default_cert, domain_certs, server_context


def make_cert(d, name):
    crt, key = os.path.join(d, name + ".crt"), os.path.join(d, name + ".key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "2",
                    "-subj", "/CN=" + name], check=True, capture_output=True)
    return crt, key


class FakeSock:
    context = None


class Sni(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.default = make_cert(self.d, "default")
        self.a = make_cert(self.d, "a.example.test")
        self.server = {"tls_cert": self.default[0], "tls_key": self.default[1],
                       "domains": [{"name": "a.example.test", "cert": self.a[0], "key": self.a[1]}, {"name": "plain.example.test"}]}

    def test_matching(self):
        self.assertTrue(_matches("a.example.test", "a.example.test"))
        self.assertTrue(_matches("*.example.test", "x.example.test"))
        self.assertFalse(_matches("*.example.test", "x.y.example.test"))
        self.assertFalse(_matches("*.example.test", "example.test"))

    def test_picks_the_domain_certificate(self):
        ctx = server_context(self.server)
        self.assertEqual(domain_certs(self.server), [("a.example.test", self.a[0], self.a[1])])
        sock = FakeSock()
        ctx.sni_callback(sock, "A.Example.Test", ctx)
        self.assertIsInstance(sock.context, ssl.SSLContext)
        other = FakeSock()
        ctx.sni_callback(other, "unknown.test", ctx)
        self.assertIsNone(other.context)                       # stays on the default certificate

    def test_default_is_the_first_domain_without_tls_cert(self):
        self.assertEqual(default_cert({"domains": [{"name": "a.example.test", "cert": self.a[0], "key": self.a[1]}]}), self.a)
        self.assertIsNone(default_cert({"domains": [{"name": "plain.example.test"}]}))
        self.assertIsNone(server_context({}))

    def test_config_checks(self):
        conf, problems = normalize({"server": {"domains": [{"name": "a.example.test", "cert": "/c"}]}})
        self.assertTrue(any("server.domains" in p for p in problems))
        self.assertEqual(conf["server"]["domains"], [])
        conf, problems = normalize({"server": {"domains": [{"name": "*.cdn.example.test", "cert": "/c", "key": "/k"}, {"name": "x.example.test"}]}})
        self.assertEqual(len(conf["server"]["domains"]), 2)
        self.assertFalse(any("domains" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
