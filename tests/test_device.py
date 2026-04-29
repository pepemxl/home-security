from home_security import device


def test_os_guess_linux():
    assert "Linux" in (device._guess_os_from_ttl(64) or "")
    # decremented one hop
    assert "Linux" in (device._guess_os_from_ttl(63) or "")


def test_os_guess_windows():
    assert "Windows" in (device._guess_os_from_ttl(128) or "")
    assert "Windows" in (device._guess_os_from_ttl(120) or "")


def test_os_guess_router():
    assert "router" in (device._guess_os_from_ttl(255) or "").lower()


def test_os_guess_none():
    assert device._guess_os_from_ttl(None) is None


def test_profile_to_dict_is_json_friendly():
    import json
    p = device.DeviceProfile(ip="10.0.0.1", open_ports=[22, 80], banners={22: "SSH-2.0-OpenSSH"})
    json.dumps(p.to_dict())  # must not raise


def test_render_handles_unreachable():
    p = device.DeviceProfile(ip="192.168.100.5")
    out = device.render(p)
    assert "192.168.100.5" in out
    assert "DOWN" in out


def test_render_treats_open_ports_as_up_when_ping_fails():
    p = device.DeviceProfile(ip="192.168.100.5", reachable=False, open_ports=[443, 554])
    out = device.render(p)
    assert "UP (icmp blocked" in out
    assert "2 tcp port(s)" in out


def test_device_type_hint_ip_camera():
    p = device.DeviceProfile(ip="x", open_ports=[443, 554])
    assert "camera" in (device._device_type_hint(p) or "").lower()


def test_device_type_hint_printer():
    p = device.DeviceProfile(ip="x", open_ports=[80, 9100])
    assert "printer" in (device._device_type_hint(p) or "").lower()


def test_device_type_hint_linux():
    p = device.DeviceProfile(ip="x", open_ports=[22])
    assert "linux" in (device._device_type_hint(p) or "").lower()


def test_normalize_mac_handles_dash():
    assert device._normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_is_up_counts_open_ports():
    p = device.DeviceProfile(ip="x", reachable=False, open_ports=[443])
    assert device.is_up(p) is True
    p2 = device.DeviceProfile(ip="x")
    assert device.is_up(p2) is False
