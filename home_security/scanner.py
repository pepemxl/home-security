"""Host discovery: ping sweep + ARP table parsing."""

from __future__ import annotations

import concurrent.futures as cf
import re
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Iterable

from . import net, vendor


@dataclass
class Device:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    responded_to_ping: bool = False
    open_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _ping(ip: str, timeout_s: float = 1.0) -> bool:
    r = subprocess.run(
        ["ping", "-c", "1", "-W", str(int(max(1, timeout_s))), ip],
        capture_output=True, text=True, check=False,
    )
    return r.returncode == 0


def ping_sweep(ips: Iterable[str], workers: int = 64, timeout_s: float = 1.0) -> set[str]:
    alive: set[str] = set()
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, ok in zip(
            ips,
            pool.map(lambda x: _ping(x, timeout_s), ips),
        ):
            if ok:
                alive.add(ip)
    return alive


_ARP_RE = re.compile(
    r"^\?*\s*\(?(?P<ip>\d+\.\d+\.\d+\.\d+)\)?\s+.*?(?P<mac>([0-9a-f]{2}:){5}[0-9a-f]{2})",
    re.IGNORECASE,
)


def arp_table() -> dict[str, str]:
    """Return {ip: mac} from the system ARP cache.

    Tries `ip neigh` first (modern Linux), falls back to `arp -an`.
    """
    out = subprocess.run(
        ["ip", "neigh", "show"], capture_output=True, text=True, check=False
    ).stdout
    table: dict[str, str] = {}
    for line in out.splitlines():
        m = re.search(
            r"^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+lladdr\s+"
            r"(([0-9a-f]{2}:){5}[0-9a-f]{2})",
            line,
            re.IGNORECASE,
        )
        if m:
            table[m.group(1)] = m.group(2).lower()
    if table:
        return table
    out = subprocess.run(
        ["arp", "-an"], capture_output=True, text=True, check=False
    ).stdout
    for line in out.splitlines():
        m = _ARP_RE.search(line)
        if m:
            table[m.group("ip")] = m.group("mac").lower()
    return table


def discover(cidr: str, *, do_ping: bool = True, resolve_dns: bool = True) -> list[Device]:
    """Return a list of devices currently visible on the given subnet."""
    targets = net.hosts_in(cidr)
    alive: set[str] = set()
    if do_ping:
        alive = ping_sweep(targets)

    arp = arp_table()
    # Anything in the ARP table is a confirmed neighbour.
    seen_ips = set(arp) | alive

    vendor.load()  # warm the OUI cache once
    devices: list[Device] = []
    for ip in sorted(seen_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = arp.get(ip)
        d = Device(
            ip=ip,
            mac=mac,
            vendor=vendor.lookup(mac) if mac else None,
            responded_to_ping=ip in alive,
        )
        if resolve_dns:
            d.hostname = net.reverse_dns(ip)
        devices.append(d)
    return devices
