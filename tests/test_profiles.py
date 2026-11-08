import json
import os
import tempfile
import threading
import unittest
import http.server

from xraysubforge.config import ConfigStore
from xraysubforge.profiles import Resolver, load_profiles
from xraysubforge.server import create_app


def panel(ids):
    """A fake panel: answers a JSON list for the known ids, 404 otherwise."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            sid = self.path.rstrip("/").split("/")[-1]
            if sid in ids:
                body = json.dumps([{"remarks": "from-" + ids[sid], "outbounds": []}]).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
            else:
                self.send_response(404); self.end_headers()

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class Profiles(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.servers = [panel({"aaaaaaaaaaaaaaaa": "one", "dupdupdupdupdupd": "one"}), panel({"bbbbbbbbbbbbbbbb": "two", "dupdupdupdupdupd": "two"}), panel({"cccccccccccccccc": "three"})]

    def tearDown(self):
        for s in self.servers:
            s.shutdown()

    def write(self, path, port, **server):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        json.dump({"panel": {"url": "http://127.0.0.1:%d/sub/{id}" % port}, "server": server}, open(path, "w"))

    def app(self):
        self.write(os.path.join(self.dir, "config.json"), self.servers[0].server_port, route="/sub/")
        self.write(os.path.join(self.dir, "profiles", "two.json"), self.servers[1].server_port, route="/sub/", hosts=["two.example.com"])
        self.write(os.path.join(self.dir, "profiles", "three.json"), self.servers[2].server_port, route="/other/")
        return create_app(ConfigStore(os.path.join(self.dir, "config.json")), Resolver()).test_client()

    def remarks(self, resp):
        return json.loads(resp.data)[0]["remarks"]

    def test_loads_default_then_files(self):
        self.app()
        names = [p.name for p in load_profiles(ConfigStore(os.path.join(self.dir, "config.json")))]
        self.assertEqual(names, ["default", "three", "two"])

    def test_own_path_wins(self):
        c = self.app()
        self.assertEqual(self.remarks(c.get("/other/cccccccccccccccc")), "from-three")

    def test_host_binding(self):
        c = self.app()
        self.assertEqual(self.remarks(c.get("/sub/bbbbbbbbbbbbbbbb", headers={"Host": "two.example.com"})), "from-two")

    def test_shared_path_is_resolved_by_the_id(self):
        c = self.app()
        self.assertEqual(self.remarks(c.get("/sub/aaaaaaaaaaaaaaaa")), "from-one")
        self.assertEqual(self.remarks(c.get("/sub/bbbbbbbbbbbbbbbb")), "from-two")

    def test_duplicate_id_goes_to_the_first_profile(self):
        c = self.app()
        self.assertEqual(self.remarks(c.get("/sub/dupdupdupdupdupd")), "from-one")

    def test_unknown_id_is_a_404(self):
        c = self.app()
        self.assertEqual(c.get("/sub/nope").status_code, 404)


if __name__ == "__main__":
    unittest.main()


class AdminProfiles(unittest.TestCase):
    def test_new_profile_and_selection(self):
        from werkzeug.security import generate_password_hash
        d = tempfile.mkdtemp()
        path = os.path.join(d, "config.json")
        json.dump({"admin": {"password_hash": generate_password_hash("pw-pw-pw-1")}, "panel": {"url": "http://x/{id}"}}, open(path, "w"))
        c = create_app(ConfigStore(path)).test_client()
        csrf = c.post("/admin/api/login", json={"password": "pw-pw-pw-1"}).get_json()["csrf"]
        h = {"X-CSRF-Token": csrf}
        self.assertEqual(c.post("/admin/api/profile-new", json={"name": "Bad Name"}, headers=h).status_code, 400)
        r = c.post("/admin/api/profile-new", json={"name": "shop2", "copy": "default"}, headers=h)
        self.assertEqual(r.get_json()["profiles"], ["default", "shop2"])
        self.assertEqual(c.post("/admin/api/profile-new", json={"name": "shop2"}, headers=h).status_code, 400)
        st = c.get("/admin/api/state", headers={"X-Profile": "shop2"}).get_json()
        self.assertEqual((st["profile"], st["config"]["panel"]["url"], "admin" in st["config"]), ("shop2", "http://x/{id}", False))
        cfg = st["config"]; cfg["panel"]["url"] = "http://y/{id}"
        self.assertEqual(c.post("/admin/api/save", json={"config": cfg}, headers=dict(h, **{"X-Profile": "shop2"})).status_code, 200)
        self.assertEqual(json.load(open(os.path.join(d, "profiles", "shop2.json")))["panel"]["url"], "http://y/{id}")
        self.assertEqual(json.load(open(path))["panel"]["url"], "http://x/{id}")           # the default is untouched
        self.assertEqual(c.get("/admin/api/state", headers={"X-Profile": "nope"}).get_json()["profile"], "default")


class AdminProfileEdit(unittest.TestCase):
    def test_rename_and_delete(self):
        from werkzeug.security import generate_password_hash
        d = tempfile.mkdtemp()
        path = os.path.join(d, "config.json")
        json.dump({"admin": {"password_hash": generate_password_hash("pw-pw-pw-1")}}, open(path, "w"))
        c = create_app(ConfigStore(path)).test_client()
        h = {"X-CSRF-Token": c.post("/admin/api/login", json={"password": "pw-pw-pw-1"}).get_json()["csrf"]}
        c.post("/admin/api/profile-new", json={"name": "one"}, headers=h)
        c.post("/admin/api/profile-new", json={"name": "two"}, headers=h)
        self.assertEqual(c.post("/admin/api/profile-rename", json={"name": "default", "to": "x"}, headers=h).status_code, 400)
        self.assertEqual(c.post("/admin/api/profile-rename", json={"name": "one", "to": "two"}, headers=h).status_code, 400)
        r = c.post("/admin/api/profile-rename", json={"name": "one", "to": "uno"}, headers=h)
        self.assertEqual(r.get_json()["profiles"], ["default", "two", "uno"])
        self.assertEqual(c.post("/admin/api/profile-delete", json={"name": "default"}, headers=h).status_code, 400)
        r = c.post("/admin/api/profile-delete", json={"name": "two"}, headers=h)
        self.assertEqual(r.get_json()["profiles"], ["default", "uno"])
        self.assertTrue(any(f.startswith("two-") for f in os.listdir(os.path.join(d, "profiles", "trash"))))
