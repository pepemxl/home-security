"""Subnet detection and small networking helpers."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass


@dataclass
class Interface:
    name: str
    ipv4: str
    cidr: str  # e.g. "192.168.1.0/24"


def _run(cmd: list[str]) -> str:
    return subprocess.run(
        cmd, capture_output=True, text=True, check=False
    ).stdout


def primary_interface() -> Interface | None:
    """Best-effort detection of the active LAN interface and its /CIDR."""
    out = _run(["ip", "-o", "-4", "addr", "show"])
    candidates: list[Interface] = []
    for line in out.splitlines():
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        name, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if name == "lo" or ip.startswith("127."):
            continue
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        candidates.append(Interface(name=name, ipv4=ip, cidr=str(net)))
    if not candidates:
        return None
    # Prefer common LAN ranges
    private_first = sorted(
        candidates,
        key=lambda i: (
            0 if ipaddress.ip_address(i.ipv4) in ipaddress.ip_network("192.168.0.0/16")
            else 1 if ipaddress.ip_address(i.ipv4) in ipaddress.ip_network("10.0.0.0/8")
            else 2 if ipaddress.ip_address(i.ipv4) in ipaddress.ip_network("172.16.0.0/12")
            else 3
        ),
    )
    return private_first[0]


def hosts_in(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(h) for h in net.hosts()]


def reverse_dns(ip: str, timeout: float = 0.5) -> str | None:
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)
