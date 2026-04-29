from pathlib import Path

from home_security.inventory import Inventory, diff
from home_security.scanner import Device


def make_dev(ip: str, mac: str) -> Device:
    return Device(ip=ip, mac=mac.lower())


def test_diff_classifies_devices(tmp_path: Path):
    inv = Inventory()
    inv.upsert_from_scan([make_dev("192.168.1.10", "AA:BB:CC:00:00:01")])
    inv.trust("aa:bb:cc:00:00:01", label="laptop")

    scanned = [
        make_dev("192.168.1.10", "AA:BB:CC:00:00:01"),  # trusted, present
        make_dev("192.168.1.20", "AA:BB:CC:00:00:02"),  # brand new
    ]
    d = diff(inv, scanned)
    assert [x.mac for x in d.returning] == ["aa:bb:cc:00:00:01"]
    assert [x.mac for x in d.new] == ["aa:bb:cc:00:00:02"]
    assert d.untrusted == []
    assert d.missing == []


def test_diff_flags_missing_trusted(tmp_path: Path):
    inv = Inventory()
    inv.upsert_from_scan([make_dev("192.168.1.10", "AA:BB:CC:00:00:01")])
    inv.trust("aa:bb:cc:00:00:01", label="phone")
    d = diff(inv, scanned=[])
    assert len(d.missing) == 1
    assert d.missing[0].label == "phone"


def test_save_and_load_roundtrip(tmp_path: Path):
    inv = Inventory()
    inv.upsert_from_scan([make_dev("10.0.0.5", "DE:AD:BE:EF:00:01")])
    inv.trust("de:ad:be:ef:00:01", label="nas")
    path = tmp_path / "inv.json"
    inv.save(path)
    loaded = Inventory.load(path)
    assert "de:ad:be:ef:00:01" in loaded.known
    assert loaded.known["de:ad:be:ef:00:01"].label == "nas"
    assert loaded.known["de:ad:be:ef:00:01"].trusted is True
