"""Persistent device inventory + diff against a fresh scan."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .scanner import Device

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
INVENTORY_PATH = DATA_DIR / "inventory.json"


@dataclass
class KnownDevice:
    mac: str
    label: str = ""
    trusted: bool = False
    last_ip: str | None = None
    last_seen: str | None = None
    vendor: str | None = None
    notes: str = ""


@dataclass
class Inventory:
    known: dict[str, KnownDevice] = field(default_factory=dict)  # keyed by MAC

    @classmethod
    def load(cls, path: Path = INVENTORY_PATH) -> "Inventory":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            known={
                mac: KnownDevice(**data) for mac, data in raw.get("known", {}).items()
            }
        )

    def save(self, path: Path = INVENTORY_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"known": {mac: vars(d) for mac, d in self.known.items()}},
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def upsert_from_scan(self, devices: list[Device]) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for d in devices:
            if not d.mac:
                continue
            entry = self.known.get(d.mac) or KnownDevice(mac=d.mac)
            entry.last_ip = d.ip
            entry.last_seen = now
            entry.vendor = d.vendor or entry.vendor
            self.known[d.mac] = entry

    def trust(self, mac: str, label: str = "", notes: str = "") -> KnownDevice:
        mac = mac.lower()
        entry = self.known.get(mac) or KnownDevice(mac=mac)
        entry.trusted = True
        if label:
            entry.label = label
        if notes:
            entry.notes = notes
        self.known[mac] = entry
        return entry


@dataclass
class Diff:
    new: list[Device]          # never seen before
    untrusted: list[Device]    # seen before but not marked trusted
    returning: list[Device]    # known + trusted, present now
    missing: list[KnownDevice] # trusted devices not seen this scan


def diff(inv: Inventory, scanned: list[Device]) -> Diff:
    by_mac_now = {d.mac: d for d in scanned if d.mac}
    new: list[Device] = []
    untrusted: list[Device] = []
    returning: list[Device] = []
    for mac, d in by_mac_now.items():
        if mac not in inv.known:
            new.append(d)
        elif not inv.known[mac].trusted:
            untrusted.append(d)
        else:
            returning.append(d)
    missing = [
        k for mac, k in inv.known.items()
        if k.trusted and mac not in by_mac_now
    ]
    return Diff(new=new, untrusted=untrusted, returning=returning, missing=missing)
