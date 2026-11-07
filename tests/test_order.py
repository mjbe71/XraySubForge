"""Tests for `order` (stable sort by rank) and output.remark_rewrite."""
import copy
import unittest

from xraysubforge.config import normalize
from xraysubforge.engine import process

FLAG = "\U0001F1E9\U0001F1EA"


def cfg(remark):
    return {"remarks": remark, "outbounds": [{"tag": "p", "protocol": "vless", "settings": {"address": "a.example", "port": 1}}]}


def run(raw, remarks):
    conf, problems = normalize(raw)
    out, _ = process([cfg(r) for r in remarks], conf)
    return [c["remarks"] for c in out], problems


class Order(unittest.TestCase):
    def test_stable_sort_and_unmatched_last(self):
        names, p = run({"order": [{"id": "b", "when": {"remark": {"startswith": "b"}}, "rank": 1},
                                  {"id": "a", "when": {"remark": {"startswith": "a"}}, "rank": 2}]},
                       ["a1", "x", "b1", "a2", "b2"])
        self.assertEqual(names, ["b1", "b2", "a1", "a2", "x"])
        self.assertEqual(p, [])

    def test_catch_all_item(self):
        names, _ = run({"order": [{"id": "z", "when": {"remark": "z"}, "rank": 9}, {"id": "rest", "rank": 1}]}, ["z", "q"])
        self.assertEqual(names, ["q", "z"])

    def test_validation(self):
        _, p = normalize({"order": [{"id": "x"}]})
        self.assertTrue(any("rank" in x for x in p))

    def test_off_by_default(self):
        names, _ = run({}, ["b", "a"])
        self.assertEqual(names, ["b", "a"])


class RemarkRewrite(unittest.TestCase):
    RULES = [{"regex": "^.*?([\\U0001F1E6-\\U0001F1FF]{2})", "replace": "\\1", "if": "[\\U0001F1E6-\\U0001F1FF]{2}"},
             {"regex": "(?<![A-Za-z])CF(?![a-z])[-_ ]?", "replace": "", "if": "[\\U0001F1E6-\\U0001F1FF]{2}"}]

    def test_rewrite(self):
        names, p = run({"output": {"remark_rewrite": self.RULES}}, ["Berlin1" + FLAG + "CF-TypeX", "CF-plain", "Tunnel" + FLAG + "X"])
        self.assertEqual(names, [FLAG + "TypeX", "CF-plain", FLAG + "X"])  # no flag: left alone
        self.assertEqual(p, [])

    def test_validation(self):
        _, p = normalize({"output": {"remark_rewrite": [{"regex": "("}]}})
        self.assertTrue(p)


if __name__ == "__main__":
    unittest.main()
