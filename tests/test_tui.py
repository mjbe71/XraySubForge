"""The terminal menu, driven by scripted answers."""
import json
import os
import tempfile
import unittest
from unittest import mock

from xraysubforge import tui
from xraysubforge.__main__ import main as cli


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.path = os.path.join(self.d.name, "config.json")
        with open(self.path, "w") as f:
            json.dump({"panel": {"url": "http://p.invalid/json/"}}, f)

    def run_menu(self, answers, editor=None):
        it = iter(answers)
        out = []
        m = tui.Menu(self.path)
        if editor is not None:
            m.editor = editor
        with mock.patch("builtins.input", lambda *a: next(it)), mock.patch.object(tui, "say", lambda t="": out.append(t)):
            try:
                m.main()
            except (tui.Quit, StopIteration):
                pass
        return "\n".join(out)

    def conf(self):
        with open(self.path) as f:
            return json.load(f)


class Menu(Base):
    def test_header_and_quit(self):
        out = self.run_menu(["0"])
        self.assertIn("http://p.invalid/json/", out)

    def test_change_panel_url_and_port(self):
        self.run_menu(["2", "2", "https://x.example/json/", "0", "0"])
        self.assertEqual(self.conf()["panel"]["url"], "https://x.example/json/")
        self.run_menu(["3", "1", "9001", "0", "0"])
        self.assertEqual(self.conf()["server"]["port"], 9001)

    def test_bad_port_is_refused(self):
        self.run_menu(["3", "1", "abc", "0", "0"])
        self.assertNotIn("server", self.conf())

    def test_add_rule_guided(self):
        # items > rules > Add > id, field remark, operator (find contains), value, done, do=drop
        ops = sorted(tui.OPS)
        self.run_menu(["6", "1", "1", "hide", "remark", str(ops.index("startswith") + 1), "test", "", "2", "0", "0", "0"])
        self.assertEqual(self.conf()["rules"], [{"id": "hide", "when": {"remark": {"startswith": "test"}}, "do": "drop"}])

    def test_rule_toggle_move_delete(self):
        with open(self.path, "w") as f:
            json.dump({"rules": [{"id": "a", "do": "drop"}, {"id": "b", "do": "keep"}]}, f)
        self.run_menu(["6", "1", "3", "1", "0", "0", "0"])           # toggle first
        self.assertFalse(self.conf()["rules"][0]["enabled"])
        self.run_menu(["6", "1", "4", "2", "1", "0", "0", "0"])      # move second to position 1
        self.assertEqual([r["id"] for r in self.conf()["rules"]], ["b", "a"])
        self.run_menu(["6", "1", "5", "1", "y", "0", "0", "0"])      # delete first
        self.assertEqual([r["id"] for r in self.conf()["rules"]], ["a"])

    def test_edit_one_as_json_and_invalid_is_refused(self):
        with open(self.path, "w") as f:
            json.dump({"rules": [{"id": "a", "do": "drop"}]}, f)
        self.run_menu(["6", "1", "2", "1", "0", "0", "0"], editor=lambda text, suffix=".json": '{"id": "a", "do": "keep"}')
        self.assertEqual(self.conf()["rules"][0]["do"], "keep")
        out = self.run_menu(["6", "1", "2", "1", "0", "0", "0"], editor=lambda text, suffix=".json": '{"id": "a", "do": "bogus"}')
        self.assertIn("Not saved", out)
        self.assertEqual(self.conf()["rules"][0]["do"], "keep")

    def test_add_chain_and_patch(self):
        entry = '{"protocol": "masque", "settings": {"address": "g"}}'
        self.run_menu(["6", "3", "1", "", "", "", "0", "0", "0"], editor=lambda text, suffix=".json": entry)
        self.assertEqual(self.conf()["chains"][0]["entry"]["protocol"], "masque")
        self.run_menu(["6", "4", "1", "", "", "", "0", "2", "0", "0", "0"], editor=lambda t, suffix=".json": '{"mux": {"enabled": false}}')
        p = self.conf()["patches"][0]
        self.assertEqual(p["merge"], {"mux": {"enabled": False}})
        self.assertEqual(p["stage"], "source")

    def test_group_leastload_goes_through_editor(self):
        full = '{"id": "g1", "type": "leastLoad", "probe": {"interval": "1m"}}'
        self.run_menu(["6", "2", "1", "g1", "", "", "n", "", "0", "0", "0"], editor=lambda t, suffix=".json": full)
        self.assertEqual(self.conf()["groups"][0]["probe"], {"interval": "1m"})

    def test_admin_password(self):
        out = self.run_menu(["4", "1", "correct-horse", "0"])
        self.assertIn("shown on screen", out)
        self.run_menu(["4", "1", "short", "0"])                  # too short: nothing changes
        h = self.conf()["admin"]["password_hash"]
        from werkzeug.security import check_password_hash
        self.assertTrue(check_password_hash(h, "correct-horse"))
        self.run_menu(["4", "2", "y", "0"])
        self.assertNotIn("password_hash", self.conf()["admin"])

    def test_service_without_installer(self):
        out = self.run_menu(["1", "1", "0", "0"])
        self.assertIn("Not available", out)

    def test_blocks_as_json(self):
        self.run_menu(["5", "y", "0"], editor=lambda t, suffix=".json": '{"rest": "hide", "list": [{"id": "x", "type": "drop", "kinds": [{"protocol": "socks"}]}]}')
        self.assertEqual(self.conf()["blocks"]["list"][0]["id"], "x")
        self.run_menu(["2", "4", "y", "0", "0"])
        self.assertEqual(self.conf()["panel"]["source"], "raw")

    def test_whole_file_edit_validates(self):
        out = self.run_menu(["9", "0"], editor=lambda t, suffix=".json": '{"rules": [{"id": "x", "do": "nope"}]}')
        self.assertIn("Not saved", out)

    def test_accounts_toggle(self):
        self.run_menu(["8", "2", "y", "0"])
        a = self.conf()["accounts"]
        self.assertTrue(a["register"]["enabled"])
        self.assertEqual(a["file"], "accounts.json")

    def test_uninstall_asks_and_delegates(self):
        calls = []
        with mock.patch.object(tui.Menu, "run_ctl", lambda self, *a: calls.append(a)), \
                mock.patch.dict(os.environ, {"XSF_CTL": "/x/xraysubforge"}):
            self.run_menu(["12", "2", "no", "0"])                     # not confirmed
            self.assertEqual(calls, [])
            self.run_menu(["12", "2", "yes"])                         # everything
            self.assertEqual(calls, [("uninstall", "--yes", "--purge")])
            calls.clear()
            self.run_menu(["12", "1", "yes"])
            self.assertEqual(calls, [("uninstall", "--yes")])

    def test_profiles_add_and_switch(self):
        self.run_menu(["11", "2", "shop2", "1", "0"])                     # Profiles > Add > name > empty
        pf = os.path.join(self.d.name, "profiles", "shop2.json")
        self.assertTrue(os.path.exists(pf))
        out = self.run_menu(["11", "2", "0", "0"])                        # switch to shop2: the header names the profile
        self.assertIn("(profile shop2)", out)
        self.run_menu(["11", "2", "2", "2", "https://new.example/json/", "0", "0"])
        self.assertEqual(json.load(open(pf))["panel"]["url"], "https://new.example/json/")
        self.assertEqual(self.conf()["panel"]["url"], "http://p.invalid/json/")   # the default is untouched

    def test_no_tty_refuses(self):
        with mock.patch("sys.stdin.isatty", return_value=False):
            self.assertEqual(cli(["menu", "--config", self.path]), 1)


if __name__ == "__main__":
    unittest.main()
