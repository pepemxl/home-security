"""MAC OUI -> vendor lookup.

Ships with a small bundled CSV of common vendors. Run
`python -m home_security.vendor refresh` to download the full IEEE
registry into data/oui-full.csv (~ a few MB).
"""

from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
BUNDLED = DATA_DIR / "oui.csv"
FULL = DATA_DIR / "oui-full.csv"

_CACHE: dict[str, str] = {}


def _normalize(mac: str) -> str:
    return mac.replace("-", ":").replace(".", ":").lower()


def _oui(mac: str) -> str:
    """First three octets, no separators, uppercase: 'AABBCC'."""
    parts = _normalize(mac).split(":")
    return "".join(parts[:3]).upper()


def _read(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            oui, vendor = row[0].strip().upper(), (row[1].strip() if len(row) > 1 else "")
            if oui:
                out[oui] = vendor
    return out


def load() -> None:
    if _CACHE:
        return
    # Full DB takes precedence if present.
    if FULL.exists():
        _CACHE.update(_read(FULL))
    _CACHE.update({k: v for k, v in _read(BUNDLED).items() if k not in _CACHE})


def lookup(mac: str | None) -> str | None:
    if not mac:
        return None
    load()
    return _CACHE.get(_oui(mac))


def refresh(url: str = "https://standards-oui.ieee.org/oui/oui.csv") -> Path:
    """Download the canonical IEEE OUI CSV into data/oui-full.csv."""
    import requests  # local import so the lib is optional for plain lookups

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    # Re-encode to a simpler 2-col CSV: oui,vendor
    out_lines = ["# generated from " + url]
    reader = csv.reader(resp.text.splitlines())
    header = next(reader, None)  # IEEE columns: Registry,Assignment,Organization Name,...
    for row in reader:
        if len(row) < 3:
            continue
        oui = row[1].strip().upper().replace("-", "").replace(":", "")
        org = row[2].strip()
        if oui and org:
            out_lines.append(f"{oui},{org}")
    FULL.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    _CACHE.clear()
    return FULL


def _cli(argv: list[str]) -> int:
    if argv and argv[0] == "refresh":
        path = refresh()
        print(f"Wrote {path}")
        return 0
    if argv and argv[0] == "lookup" and len(argv) >= 2:
        print(lookup(argv[1]) or "unknown")
        return 0
    print("usage: python -m home_security.vendor refresh | lookup <mac>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
