"""Kinds: configs of a subscription that differ only in their numbers (server 1, server 2, ...) are one kind.

A kind carries a condition (`when`) that matches exactly its configs, so a block built from kinds keeps working for
every user and for servers added later with the next number.
"""
import re

from .matching import fields_of

_FLAG = re.compile("[\U0001F1E6-\U0001F1FF]{2}")
_DIGITS = re.compile(r"\d+")
# the panel's info line (traffic left, days left, ...): its text changes per user, so only its shape is matched
_INFO = re.compile(r"\d(?:[.,]\d+)?\s*(?:[KMGT]i?B)\b|\u221e|\u23f3|\U0001F4CA")
INFO_REGEX = r"\d(?:[.,]\d+)?\s*(?:[KMGT]i?B)\b|\u221e|\u23f3|\U0001F4CA"


def _stem(remark):
    """The remark without its flag, with every run of digits as '#'."""
    return re.sub(r"\s+", " ", _DIGITS.sub("#", _FLAG.sub("", remark or ""))).strip()


def _pattern(remark):
    """A regex for this remark with every run of digits free."""
    parts = _DIGITS.split(remark)
    return "^" + r"\d+".join(re.escape(p) for p in parts) + "$"


def kinds_of(configs):
    """-> [{"id", "label", "when", "count", "flag", "protocol", "network", "security", "remarks", "indexes"}], in the order
    the kinds first appear."""
    kinds, index = [], {}
    for n, c in enumerate(configs):
        if not isinstance(c, dict):
            continue
        f = fields_of(c)
        remark = f.get("remark") or ""
        info = bool(_INFO.search(remark))
        key = (f.get("flag"), f.get("protocol"), f.get("network"), f.get("security"), "\0info" if info else _stem(remark))
        if key not in index:
            when = {"remark": {"regex": INFO_REGEX if info else _pattern(remark)}}
            for field in ("protocol", "network", "security"):
                if f.get(field) is not None:
                    when[field] = f[field]
            stem = "User info (traffic, time)" if info else key[4].replace("#", "*") or "(no name)"
            label = " · ".join([stem] + [str(v) for v in key[1:4] if v])
            index[key] = len(kinds)
            kinds.append({"id": "kind%d" % (len(kinds) + 1), "label": label, "when": when, "count": 0,
                          "flag": key[0], "protocol": key[1], "network": key[2], "security": key[3], "remarks": [],
                          "indexes": []})
        k = kinds[index[key]]
        k["count"] += 1
        k["indexes"].append(n)
        if len(k["remarks"]) < 5:
            k["remarks"].append(remark)
    return kinds
