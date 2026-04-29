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
    assert "reachable : False" in out
