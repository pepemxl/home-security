from home_security import vendor


def test_lookup_known_oui():
    # Raspberry Pi OUI from bundled CSV.
    assert vendor.lookup("B8:27:EB:11:22:33") is not None


def test_lookup_unknown():
    assert vendor.lookup("00:00:00:00:00:00") is None


def test_lookup_handles_dash_separator():
    assert vendor.lookup("B8-27-EB-11-22-33") == vendor.lookup("B8:27:EB:11:22:33")


def test_lookup_none_input():
    assert vendor.lookup(None) is None
