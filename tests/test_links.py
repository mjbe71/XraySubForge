"""Share links <-> Xray configs, and the raw source / raw engine routes."""
import base64
import json
import os
import tempfile
import unittest
from unittest import mock

from xraysubforge.config import ConfigStore, normalize
from xraysubforge.engine import process
from xraysubforge.links import config_links, encode_raw, link_to_config, outbound_link, parse_link, parse_raw
from xraysubforge.server import create_app

UUID = "11111111-2222-3333-4444-555555555555"
VLESS_REALITY = ("vless://%s@r.example.com:443?type=tcp&security=reality&sni=www.example.org&fp=chrome&pbk=PUBKEY&sid=ab12"
                 "&spx=%%2F&flow=xtls-rprx-vision&encryption=none#DE%%20Reality%%201" % UUID)
VLESS_WS = "vless://%s@w.example.com:443?type=ws&path=%%2Fws%%3Fed%%3D2048&host=cdn.example.com&security=tls&sni=cdn.example.com&alpn=h2%%2Chttp%%2F1.1&fp=firefox#WS" % UUID
VLESS_XHTTP = 'vless://%s@x.example.com:443?type=xhttp&path=%%2Fx&host=h.example.com&mode=auto&extra=%%7B%%22xPaddingBytes%%22%%3A%%22100-1000%%22%%7D&security=tls&sni=h.example.com#CF-1' % UUID
VLESS_GRPC = "vless://%s@g.example.com:443?type=grpc&serviceName=svc&mode=multi&security=tls&sni=g.example.com#GRPC" % UUID
TROJAN = "trojan://p%40ss@t.example.com:8443?type=tcp&security=tls&sni=t.example.com#Trojan"
VMESS = "vmess://" + base64.b64encode(json.dumps({"v": "2", "ps": "VM", "add": "v.example.com", "port": "443", "id": UUID, "aid": "0",
                                                   "scy": "auto", "net": "ws", "type": "none", "host": "v.example.com", "path": "/vm",
                                                   "tls": "tls", "sni": "v.example.com"}).encode()).decode()
SS = "ss://" + base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:secret").decode().rstrip("=") + "@s.example.com:8388#SS"
SS_OLD = "ss://" + base64.b64encode(b"aes-128-gcm:pw@o.example.com:8389").decode() + "#Old"
ALL = [VLESS_REALITY, VLESS_WS, VLESS_XHTTP, VLESS_GRPC, TROJAN, VMESS, SS, SS_OLD]


class Links(unittest.TestCase):
    def test_parse(self):
        ob, remark = parse_link(VLESS_REALITY)
        self.assertEqual(remark, "DE Reality 1")
        user = ob["settings"]["vnext"][0]["users"][0]
        self.assertEqual((user["id"], user["flow"]), (UUID, "xtls-rprx-vision"))
        rs = ob["streamSettings"]["realitySettings"]
        self.assertEqual((rs["publicKey"], rs["shortId"], rs["spiderX"], rs["fingerprint"]), ("PUBKEY", "ab12", "/", "chrome"))
        st = parse_link(VLESS_WS)[0]["streamSettings"]
        self.assertEqual((st["wsSettings"]["path"], st["wsSettings"]["host"]), ("/ws?ed=2048", "cdn.example.com"))
        self.assertEqual(st["tlsSettings"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(parse_link(VLESS_XHTTP)[0]["streamSettings"]["xhttpSettings"]["extra"], {"xPaddingBytes": "100-1000"})
        self.assertTrue(parse_link(VLESS_GRPC)[0]["streamSettings"]["grpcSettings"]["multiMode"])
        self.assertEqual(parse_link(TROJAN)[0]["settings"]["servers"][0]["password"], "p@ss")
        vm = parse_link(VMESS)[0]
        self.assertEqual((vm["protocol"], vm["streamSettings"]["wsSettings"]["path"]), ("vmess", "/vm"))
        self.assertEqual(parse_link(SS)[0]["settings"]["servers"][0]["method"], "chacha20-ietf-poly1305")
        self.assertEqual(parse_link(SS_OLD)[0]["settings"]["servers"][0]["address"], "o.example.com")
        self.assertIsNone(parse_link("hysteria2://x@h:1#H"))
        self.assertIsNone(parse_link("vless://broken"))

    def test_round_trip(self):
        for link in ALL:
            ob, remark = parse_link(link)
            again = parse_link(outbound_link(ob, remark))
            self.assertEqual(again, (ob, remark), link)

    def test_raw_body(self):
        plain = "\n".join(ALL) + "\n"
        self.assertEqual(parse_raw(plain), ALL)
        self.assertEqual(parse_raw(base64.b64encode(plain.encode())), ALL)
        self.assertEqual(parse_raw(encode_raw(ALL)), ALL)

    def test_config_and_back(self):
        c = link_to_config(VLESS_WS)
        self.assertEqual((c["remarks"], c["outbounds"][0]["tag"]), ("WS", "proxy"))
        self.assertEqual([o["tag"] for o in c["outbounds"]], ["proxy", "direct", "block"])
        self.assertEqual(config_links(c), [outbound_link(parse_link(VLESS_WS)[0], "WS")])
        tpl = {"outbounds": [{"tag": "proxy"}, {"tag": "out", "protocol": "freedom"}], "dns": {"servers": ["9.9.9.9"]}}
        c = link_to_config(VLESS_WS, tpl)
        self.assertEqual([o["tag"] for o in c["outbounds"]], ["proxy", "out"])
        chained = link_to_config(VLESS_WS)
        chained["outbounds"][0]["streamSettings"]["sockopt"] = {"dialerProxy": "x"}
        self.assertEqual(config_links(chained), [])

    def test_balancer_gives_its_members(self):
        configs = [link_to_config(VLESS_XHTTP.replace("#CF-1", "#CF-%d" % n)) for n in (1, 2)]
        conf, _ = normalize({"groups": [{"id": "g", "type": "random", "when": {"remark": {"startswith": "CF"}}, "name": "Fast"}]})
        out, _ = process(configs, conf)
        links = config_links(out[0])
        self.assertEqual([parse_link(x)[1] for x in links], ["Fast 1", "Fast 2"])


def panel_get(url, **kw):
    class R:
        status_code, headers = 200, {"Content-Type": "text/plain", "Subscription-Userinfo": "total=1"}
        content = encode_raw([VLESS_REALITY, VLESS_XHTTP, TROJAN]).encode()
    return R()


def client(panel, **extra):
    path = os.path.join(tempfile.mkdtemp(), "config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(dict({"panel": dict({"raw_url": "https://p.example/sub/"}, **panel)}, **extra), f)
    return create_app(ConfigStore(path)).test_client()


class RawRoutes(unittest.TestCase):
    def get(self, c, url):
        with mock.patch("xraysubforge.panel.requests.get", side_effect=panel_get):
            return c.get(url)

    def test_json_built_from_raw(self):
        c = client({"source": "raw"}, rules=[{"id": "t", "when": {"protocol": "trojan"}, "do": "drop"}])
        r = self.get(c, "/sub/abcd1234")
        body = json.loads(r.data)
        self.assertEqual([x["remarks"] for x in body], ["DE Reality 1", "CF-1"])
        self.assertEqual(r.headers["Subscription-Userinfo"], "total=1")

    def test_proxy_mode_with_raw_source_only_converts(self):
        c = client({"source": "raw", "mode": "proxy"}, rules=[{"id": "t", "when": {"protocol": "trojan"}, "do": "drop"}])
        self.assertEqual(len(json.loads(self.get(c, "/sub/abcd1234").data)), 3)

    def test_raw_engine(self):
        c = client({"raw_mode": "engine"}, rules=[{"id": "t", "when": {"protocol": "trojan"}, "do": "drop"}],
                   patches=[{"id": "fp", "target": "outbound", "merge": {"streamSettings": {"tlsSettings": {"fingerprint": "safari"}}},
                             "when": {"security": "tls"}}])
        r = self.get(c, "/raw/abcd1234")
        links = parse_raw(r.data)
        self.assertEqual([parse_link(x)[1] for x in links], ["DE Reality 1", "CF-1"])
        self.assertIn("fp=safari", links[1])
        self.assertEqual(r.headers["Subscription-Userinfo"], "total=1")

    def test_raw_pass_by_default(self):
        r = self.get(client({}), "/raw/abcd1234")
        self.assertEqual(len(parse_raw(r.data)), 3)


if __name__ == "__main__":
    unittest.main()
