"""Tests for shared platform helpers and that scanner / device degrade gracefully."""

from home_security import _proc, scanner, device


def test_run_missing_binary_returns_empty():
    assert _proc.run(["definitely-not-a-real-binary-xyz"]) == ""


def test_normalize_mac_dashes():
    assert _proc.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_arp_table_returns_dict():
    # Whatever the OS, arp_table must return a dict (possibly empty), never raise.
    result = scanner.arp_table()
    assert isinstance(result, dict)


def test_ping_sweep_handles_empty_input():
    assert scanner.ping_sweep([]) == set()


def test_outbound_local_ip_is_string_or_none():
    ip = _proc.outbound_local_ip()
    assert ip is None or (isinstance(ip, str) and ip.count(".") == 3)


def test_arp_for_unknown_ip_returns_none():
    # 192.0.2.x is RFC 5737 TEST-NET-1, guaranteed not to be in any ARP cache.
    assert _proc.arp_for_ip("192.0.2.123") is None


def test_device_inspect_does_not_raise_on_unreachable():
    # Use an obviously unreachable IP. Must produce a profile, not crash.
    p = device.inspect("192.0.2.1", do_ports=False, do_banners=False)
    assert p.ip == "192.0.2.1"
    assert isinstance(p.open_ports, list)
