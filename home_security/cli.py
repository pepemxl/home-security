"""home-security command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import device as device_mod
from . import inventory as inv_mod
from . import net, ports, scanner, vendor


def _fmt_device(d: scanner.Device, inv: inv_mod.Inventory | None = None) -> str:
    label = ""
    if inv and d.mac and d.mac in inv.known:
        k = inv.known[d.mac]
        if k.label:
            label = f"  [{k.label}{'*' if k.trusted else ''}]"
    bits = [
        f"{d.ip:<15}",
        f"{(d.mac or '--:--:--:--:--:--'):<17}",
        f"{(d.vendor or '?')[:24]:<24}",
        d.hostname or "",
    ]
    return " ".join(bits) + label


def cmd_scan(args: argparse.Namespace) -> int:
    cidr = args.cidr
    if not cidr:
        iface = net.primary_interface()
        if not iface:
            print("Could not auto-detect a LAN interface; pass --cidr", file=sys.stderr)
            return 2
        cidr = iface.cidr
        print(f"Scanning {cidr} (interface {iface.name}, host {iface.ipv4})")
    devices = scanner.discover(
        cidr,
        do_ping=not args.no_ping,
        resolve_dns=not args.no_dns,
    )

    if args.with_ports:
        for d in devices:
            d.open_ports = ports.scan(d.ip)

    inv = inv_mod.Inventory.load()
    print(f"\nFound {len(devices)} device(s):")
    print("-" * 78)
    for d in devices:
        line = _fmt_device(d, inv)
        print(line)
        if d.open_ports:
            svc = ", ".join(f"{p}/{ports.describe(p)}" for p in d.open_ports)
            print(f"  open: {svc}")

    if not args.no_save:
        inv.upsert_from_scan(devices)
        inv.save()
        print(f"\nInventory updated: {inv_mod.INVENTORY_PATH}")

    if args.json:
        print(json.dumps([d.to_dict() for d in devices], indent=2))
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    cidr = args.cidr
    if not cidr:
        iface = net.primary_interface()
        if not iface:
            print("Could not auto-detect a LAN interface; pass --cidr", file=sys.stderr)
            return 2
        cidr = iface.cidr
    devices = scanner.discover(cidr, do_ping=not args.no_ping)
    inv = inv_mod.Inventory.load()
    d = inv_mod.diff(inv, devices)

    def section(title: str, items: list, render):
        print(f"\n== {title} ({len(items)}) ==")
        for it in items:
            print("  " + render(it))

    section("NEW (never seen)", d.new, lambda x: _fmt_device(x, inv))
    section("UNTRUSTED (seen, not yet trusted)", d.untrusted, lambda x: _fmt_device(x, inv))
    section("MISSING (trusted, absent now)", d.missing,
            lambda k: f"{k.mac}  {k.label or '(no label)'}  last_ip={k.last_ip}")
    section("OK (trusted + present)", d.returning, lambda x: _fmt_device(x, inv))
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    inv = inv_mod.Inventory.load()
    if args.action == "list":
        if not inv.known:
            print("(empty inventory — run a scan first)")
            return 0
        for mac, k in sorted(inv.known.items()):
            star = "*" if k.trusted else " "
            print(f"{star} {mac}  {k.last_ip or '-':<15}  {(k.vendor or '?')[:24]:<24}  {k.label}")
        return 0
    if args.action == "trust":
        k = inv.trust(args.mac, label=args.label or "", notes=args.notes or "")
        inv.save()
        print(f"Trusted {k.mac} ({k.label or 'unlabeled'})")
        return 0
    if args.action == "forget":
        mac = args.mac.lower()
        if mac in inv.known:
            del inv.known[mac]
            inv.save()
            print(f"Removed {mac}")
        else:
            print(f"{mac} not in inventory", file=sys.stderr)
            return 1
        return 0
    return 2


def cmd_ports(args: argparse.Namespace) -> int:
    open_ports = ports.scan(args.ip, timeout=args.timeout)
    if not open_ports:
        print(f"{args.ip}: no common ports open")
        return 0
    print(f"{args.ip}: {len(open_ports)} open port(s)")
    for p in open_ports:
        print(f"  {p:>5}/tcp  {ports.describe(p)}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    profile = device_mod.inspect(
        args.ip,
        do_ping=not args.no_ping,
        do_ports=not args.no_ports,
        do_banners=not args.no_banners,
        port_timeout=args.timeout,
    )
    if args.json:
        print(json.dumps(profile.to_dict(), indent=2))
    else:
        print(device_mod.render(profile))
    return 0 if profile.reachable or profile.mac else 1


def cmd_vendor(args: argparse.Namespace) -> int:
    if args.action == "refresh":
        path = vendor.refresh()
        print(f"Wrote {path}")
        return 0
    if args.action == "lookup":
        print(vendor.lookup(args.mac) or "unknown")
        return 0
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="home-security", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Discover devices on the LAN.")
    s.add_argument("--cidr", help="Subnet to scan, e.g. 192.168.1.0/24")
    s.add_argument("--no-ping", action="store_true", help="Skip ping sweep, use ARP cache only.")
    s.add_argument("--no-dns", action="store_true", help="Skip reverse DNS lookups.")
    s.add_argument("--no-save", action="store_true", help="Don't update inventory.json.")
    s.add_argument("--with-ports", action="store_true", help="Also TCP-scan common ports per host.")
    s.add_argument("--json", action="store_true", help="Print full JSON dump after the table.")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("diff", help="Compare current devices against the saved inventory.")
    s.add_argument("--cidr")
    s.add_argument("--no-ping", action="store_true")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("inventory", help="Manage the device inventory.")
    isub = s.add_subparsers(dest="action", required=True)
    isub.add_parser("list", help="Show all known devices.").set_defaults(func=cmd_inventory)
    t = isub.add_parser("trust", help="Mark a MAC as trusted.")
    t.add_argument("mac")
    t.add_argument("--label", help="Friendly name (e.g. 'kitchen-tablet').")
    t.add_argument("--notes")
    t.set_defaults(func=cmd_inventory)
    f = isub.add_parser("forget", help="Drop a MAC from the inventory.")
    f.add_argument("mac")
    f.set_defaults(func=cmd_inventory)

    s = sub.add_parser("ports", help="TCP-scan common ports on a single host.")
    s.add_argument("ip")
    s.add_argument("--timeout", type=float, default=0.4)
    s.set_defaults(func=cmd_ports)

    s = sub.add_parser(
        "inspect",
        help="Deep inspection of one host: ping, MAC, vendor, names, ports, banners.",
    )
    s.add_argument("ip")
    s.add_argument("--no-ping", action="store_true")
    s.add_argument("--no-ports", action="store_true")
    s.add_argument("--no-banners", action="store_true")
    s.add_argument("--timeout", type=float, default=0.4, help="Per-port TCP timeout (s).")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_inspect)

    s = sub.add_parser("vendor", help="Vendor / OUI utilities.")
    vsub = s.add_subparsers(dest="action", required=True)
    vsub.add_parser("refresh", help="Download IEEE OUI database.").set_defaults(func=cmd_vendor)
    vl = vsub.add_parser("lookup", help="Look up a MAC address.")
    vl.add_argument("mac")
    vl.set_defaults(func=cmd_vendor)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
