"""Lightweight TCP-connect port scanner (no raw sockets needed)."""

from __future__ import annotations

import concurrent.futures as cf
import socket

# Curated short list of services worth flagging on a home LAN.
# Anything exposed here on a random device deserves a second look.
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    554: "rtsp",          # IP cameras
    3389: "rdp",
    5000: "upnp/dlna",
    5357: "wsd",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9100: "printer",
    62078: "iphone-sync",
}


def _check(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan(
    ip: str,
    ports: list[int] | None = None,
    *,
    timeout: float = 0.4,
    workers: int = 32,
) -> list[int]:
    """Return the subset of *ports* that accepted a TCP connection."""
    ports = ports or list(COMMON_PORTS)
    open_ports: list[int] = []
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        for port, ok in zip(ports, pool.map(lambda p: _check(ip, p, timeout), ports)):
            if ok:
                open_ports.append(port)
    return sorted(open_ports)


def describe(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")
