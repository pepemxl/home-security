"""Host discovery: ping sweep + ARP table parsing. Cross-platform."""

from __future__ import annotations

import concurrent.futures as cf
from dataclasses import dataclass, field, asdict
from typing import Iterable

from . import _proc, net, vendor


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


def _ping_alive(ip: str, timeout_s: float = 1.0) -> bool:
    alive, _rtt, _ttl = _proc.ping(ip, count=1, timeout_s=int(max(1, timeout_s)))
    return alive


def ping_sweep(ips: Iterable[str], workers: int = 64, timeout_s: float = 1.0) -> set[str]:
    targets = list(ips)
    alive: set[str] = set()
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, ok in zip(targets, pool.map(lambda x: _ping_alive(x, timeout_s), targets)):
            if ok:
                alive.add(ip)
    return alive


def arp_table() -> dict[str, str]:
    return _proc.arp_table()


def discover(cidr: str, *, do_ping: bool = True, resolve_dns: bool = True) -> list[Device]:
    """Return a list of devices currently visible on the given subnet."""
    targets = net.hosts_in(cidr)
    alive: set[str] = set()
    if do_ping:
        alive = ping_sweep(targets)

    arp = arp_table()
    # Anything in the ARP table is a confirmed neighbour, even if it didn't reply to ping.
    seen_ips = (set(arp) & set(targets)) | alive

    vendor.load()
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
