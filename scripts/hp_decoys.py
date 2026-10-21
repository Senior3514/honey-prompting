#!/usr/bin/env python3
"""Mint synthetic decoys and scan text for them. Standard library only.

    python hp_decoys.py mint [--count 3] [--out decoys.json]
    python hp_decoys.py scan --decoys decoys.json < model_output.txt     # exit 1 on a hit
    python hp_decoys.py selftest

Use it to try the idea or as a reference when wiring Honey Prompting into a stack that is not
Python. In Python with an OpenAI-style client, prefer `pip install` of the honeyprompts SDK.

Decoys look like secrets but authenticate nowhere. Keep the decoys file private: a decoy an
attacker knows is a decoy they can avoid.

What the scan catches: the value as written, in another case, split by spaces, punctuation or
invisible characters, in full-width or other NFKC look-alike Unicode, reversed, ROT13, base64,
hex or URL-encoded, and any contiguous run of at least 12 characters
from the value (including that run in base64, hex, or URL-encoding). What it cannot catch: a
paraphrase, a translation, a value spelled out in words, or a piece shorter than 12 characters.
A tripwire detects; it is not a data-loss-prevention engine.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import json
import re
import secrets
import string
import sys
import unicodedata
from urllib.parse import unquote

KINDS = {
    "aws_access_key": lambda: "AKIA-HONEY-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)),
    "api_key": lambda: "sk-honey-decoy-" + secrets.token_hex(12),
    "slack_bot_token": lambda: "xoxb-HONEY-" + "".join(secrets.choice(string.digits) for _ in range(4)) + "-" + secrets.token_hex(8),
    "github_pat": lambda: "ghp_HONEY" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(27)),
}

MAX_CHARS = 200_000
MIN_FRAGMENT_LEN = 12
_B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍‎‏⁠­﻿"), None)
_SQUASH = re.compile(r"[\s*`'\"_.\-|,;:]+")


def mint(count: int = 3) -> list[dict]:
    kinds = list(KINDS)
    return [{"id": f"{k}-{i + 1}", "kind": k, "value": KINDS[k]()} for i, k in enumerate((kinds * count)[:count])]


def _norm(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE)


def _squash(text: str) -> str:
    return _SQUASH.sub("", text).lower()


def _b64_decode(run: str) -> str | None:
    cand = run.rstrip("=")
    cand += "=" * (-len(cand) % 4)
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            text = dec(cand).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if text and sum(c.isprintable() or c.isspace() for c in text) / len(text) > 0.85:
            return text
    return None


def _variants(text: str):
    yield "literal", text
    norm = _norm(text)
    if norm != text:
        yield "unicode", norm
    yield "reversed", norm[::-1]
    yield "rot13", codecs.encode(norm, "rot13")
    unq = unquote(norm)
    if unq != norm:
        yield "url", unq
    for run in _B64.findall(norm)[:60]:
        dec = _b64_decode(run)
        if dec:
            yield "base64", dec
    for run in _HEX.findall(norm)[:60]:
        try:
            yield "hex", bytes.fromhex(run).decode("utf-8", "ignore")
        except ValueError:
            pass


def _fragment_ok(frag: str) -> bool:
    alnum = [c for c in frag if c.isalnum()]
    if len(alnum) < 8 or len(set(alnum)) < 4:
        return False
    if sum(c.isdigit() for c in alnum) * 2 > len(alnum):
        return False
    return True


def _fragment_windows(value: str) -> tuple[str, ...]:
    raw = value.lower()
    if len(raw) < MIN_FRAGMENT_LEN:
        return ()
    seen: set[str] = set()
    windows: list[str] = []
    for i in range(0, len(raw) - MIN_FRAGMENT_LEN + 1):
        frag = raw[i : i + MIN_FRAGMENT_LEN]
        if frag in seen or not _fragment_ok(frag):
            continue
        seen.add(frag)
        windows.append(frag)
    return tuple(windows)


def _has_fragment(haystack: str, windows: tuple[str, ...]) -> bool:
    if not haystack or not windows:
        return False
    low = haystack.lower()
    return any(window in low for window in windows)


def scan(text: str, decoys: list[dict]) -> tuple[dict, str] | None:
    """Return (decoy, how it was found) for the first decoy in `text`, else None."""
    text = (text or "")[:MAX_CHARS]
    decoys = [d for d in decoys if d.get("value")]
    for d in decoys:
        if d["value"] in text:
            return d, "literal"
    for how, variant in _variants(text):
        for d in decoys:
            if d["value"] in variant:
                return d, how
            if d["value"].lower() in variant.lower():
                return d, "case-insensitive" if how == "literal" else how
    for how, variant in _variants(text):
        sq = _squash(variant)
        for d in decoys:
            needle = _squash(d["value"])
            if len(needle) >= 12 and needle in sq:
                return d, "spaced" if how == "literal" else f"{how}+spaced"
    prepared = [(d, _fragment_windows(d["value"])) for d in decoys]
    for d, windows in prepared:
        if _has_fragment(text, windows):
            return d, "fragment"
    for how, variant in _variants(text):
        if how not in ("base64", "hex", "url"):
            continue
        for d, windows in prepared:
            if _has_fragment(variant, windows):
                return d, how
    return None


def _selftest() -> int:
    decoys = mint(4)
    v = decoys[0]["value"]
    cases = {
        "literal": f"the key is {v}",
        "case-insensitive": v.lower(),
        "spaced": " ".join(v),
        "reversed": v[::-1],
        "rot13": codecs.encode(v, "rot13"),
        "base64": base64.b64encode(v.encode()).decode(),
        "hex": v.encode().hex(),
        "url": "".join(f"%{ord(c):02X}" for c in v),
        "fragment": f"prefix {v[:12]} only",
        "fragment-b64": base64.b64encode(v[:16].encode()).decode(),
        "zero-width-split": "\u200b".join(v),
        "full-width": "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in v),
    }
    bad = []
    for name, text in cases.items():
        hit = scan(text, decoys)
        if not hit or hit[0]["value"] != v:
            bad.append(name)
    clean = scan("Happy to help with your order. Nothing secret here.", decoys)
    if clean is not None:
        bad.append("false-positive")
    print("SELFTEST PASS" if not bad else "SELFTEST FAIL: " + ", ".join(bad))
    return 0 if not bad else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint", help="make synthetic decoys")
    m.add_argument("--count", type=int, default=3)
    m.add_argument("--out", help="write the decoys to this file (mode 600) instead of printing")
    s = sub.add_parser("scan", help="read text on stdin; exit 1 if a decoy is in it")
    s.add_argument("--decoys", required=True)
    sub.add_parser("selftest", help="check the matcher against every form it claims")
    a = p.parse_args(argv)
    if a.cmd == "mint":
        data = json.dumps(mint(max(1, min(a.count, 50))), indent=2)
        if a.out:
            import os

            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(data + "\n")
            print(f"wrote {a.out} (keep it private)")
        else:
            print(data)
        return 0
    if a.cmd == "scan":
        with open(a.decoys, encoding="utf-8") as f:
            decoys = json.load(f)
        hit = scan(sys.stdin.read(), decoys)
        if hit:
            print(f"HIT decoy={hit[0]['id']} how={hit[1]}")
            return 1
        print("clean")
        return 0
    return _selftest()


if __name__ == "__main__":
    raise SystemExit(main())
