"""Cheap import + CLI parser smoke tests — no network access."""

from home_security import cli, ports, scanner, inventory, vendor, net  # noqa: F401


def test_cli_parser_builds():
    p = cli.build_parser()
    args = p.parse_args(["scan", "--cidr", "192.168.1.0/24", "--no-save"])
    assert args.cmd == "scan"
    assert args.cidr == "192.168.1.0/24"


def test_ports_module_exposes_common_list():
    assert 22 in ports.COMMON_PORTS
    assert ports.describe(22) == "ssh"
