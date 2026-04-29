"""Subnet detection and small networking helpers. Cross-platform."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from . import _proc


@dataclass
class Interface:
    name: str
    ipv4: str
    cidr: str  # e.g. "192.168.1.0/24"


def _parse_linux_ip_addr() -> list[Interface]:
    out = _proc.run(["ip", "-o", "-4", "addr", "show"])
    ifaces: list[Interface] = []
    for line in out.splitlines():
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        name, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if name == "lo" or ip.startswith("127."):
            continue
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        ifaces.append(Interface(name=name, ipv4=ip, cidr=str(net)))
    return ifaces


def _parse_windows_ipconfig() -> list[Interface]:
    """Best-effort parse of `ipconfig` output to extract IPv4 + subnet mask."""
    out = _proc.run(["ipconfig"])
    if not out:
        return []
    ifaces: list[Interface] = []
    current_name = "?"
    current_ip: str | None = None
    for raw in out.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        # Section header (no leading whitespace, ends with ':')
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            current_name = line.rstrip(":").strip() or current_name
            current_ip = None
            continue
        # Strings vary by locale ("IPv4 Address", "Dirección IPv4", ...).
        # Match anything followed by an IPv4.
        ipv4_m = re.search(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line) or \
                 re.search(r"IPv4.*?(\d+\.\d+\.\d+\.\d+)", line)
        mask_m = re.search(r"(?:Mask|M[áa]scara)[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if ipv4_m:
            current_ip = ipv4_m.group(1)
        elif mask_m and current_ip:
            mask = mask_m.group(1)
            try:
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                net = ipaddress.ip_network(f"{current_ip}/{prefix}", strict=False)
                if not current_ip.startswith("127.") and not current_ip.startswith("169.254."):
                    ifaces.append(Interface(name=current_name, ipv4=current_ip, cidr=str(net)))
            except (ValueError, ipaddress.NetmaskValueError):
                pass
            current_ip = None
    return ifaces


def _fallback_via_outbound() -> list[Interface]:
    """Last resort: use the outbound source IP and assume a /24 subnet."""
    ip = _proc.outbound_local_ip()
    if not ip or ip.startswith("127."):
        return []
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return [Interface(name="auto", ipv4=ip, cidr=str(net))]


def _rank_private(ifaces: list[Interface]) -> list[Interface]:
    """Prefer 192.168/16, then 10/8, then 172.16/12, then anything else."""
    def key(i: Interface) -> int:
        addr = ipaddress.ip_address(i.ipv4)
        if addr in ipaddress.ip_network("192.168.0.0/16"):
            return 0
        if addr in ipaddress.ip_network("10.0.0.0/8"):
            return 1
        if addr in ipaddress.ip_network("172.16.0.0/12"):
            return 2
        return 3
    return sorted(ifaces, key=key)


def primary_interface() -> Interface | None:
    """Best-effort detection of the active LAN interface and its /CIDR."""
    candidates: list[Interface] = []
    if _proc.IS_WINDOWS:
        candidates = _parse_windows_ipconfig()
    else:
        candidates = _parse_linux_ip_addr()
    if not candidates:
        candidates = _fallback_via_outbound()
    if not candidates:
        return None
    return _rank_private(candidates)[0]


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
