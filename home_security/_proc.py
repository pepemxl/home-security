"""Shared cross-platform shell helpers.

Centralised so a Linux-only command never escapes into a code path that runs
on Windows (or vice versa). Every public function here is best-effort:
missing tools and non-zero exits return empty / None instead of raising.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import sys

IS_WINDOWS = sys.platform.startswith("win")

# Match either colon- or dash-separated MAC addresses.
MAC_RE = r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}"


def normalize_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


def run(cmd: list[str], timeout: float = 5.0) -> str:
    """Run a command; return stdout. Empty string on any failure."""
    if not shutil.which(cmd[0]):
        return ""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def ping(ip: str, count: int = 1, timeout_s: int = 1) -> tuple[bool, float | None, int | None]:
    """Return (alive, rtt_ms, ttl). Cross-platform."""
    if shutil.which("ping") is None:
        return (False, None, None)
    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout_s), ip]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, check=False,
            timeout=count * (timeout_s + 1) + 1,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return (False, None, None)

    out = proc.stdout
    alive = proc.returncode == 0
    rtt = None
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    if m:
        rtt = float(m.group(1))
    ttl = None
    m = re.search(r"\bttl[=:](\d+)", out, re.IGNORECASE)
    if m:
        ttl = int(m.group(1))
    return (alive, rtt, ttl)


def arp_for_ip(ip: str) -> str | None:
    """Look up a single IP's MAC across whatever ARP tool is available."""
    out = run(["ip", "neigh", "show", ip])
    m = re.search(rf"lladdr\s+({MAC_RE})", out, re.IGNORECASE)
    if m:
        return normalize_mac(m.group(1))
    out = run(["arp", "-an", ip])
    m = re.search(rf"({MAC_RE})", out, re.IGNORECASE)
    if m:
        return normalize_mac(m.group(1))
    out = run(["arp", "-a", ip])
    for line in out.splitlines():
        if ip in line:
            m = re.search(rf"({MAC_RE})", line, re.IGNORECASE)
            if m:
                return normalize_mac(m.group(1))
    return None


def arp_table() -> dict[str, str]:
    """Return {ip: mac} for every entry currently in the OS ARP cache."""
    table: dict[str, str] = {}

    # Linux modern: `ip neigh show`
    out = run(["ip", "neigh", "show"])
    for line in out.splitlines():
        m = re.match(
            rf"^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+lladdr\s+({MAC_RE})",
            line, re.IGNORECASE,
        )
        if m:
            table[m.group(1)] = normalize_mac(m.group(2))
    if table:
        return table

    # Linux/macOS BSD: `arp -an`
    out = run(["arp", "-an"])
    for line in out.splitlines():
        ip_m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
        mac_m = re.search(rf"({MAC_RE})", line, re.IGNORECASE)
        if ip_m and mac_m:
            table[ip_m.group(1)] = normalize_mac(mac_m.group(1))
    if table:
        return table

    # Windows: `arp -a`
    out = run(["arp", "-a"])
    for line in out.splitlines():
        # e.g. "  192.168.100.5         aa-bb-cc-dd-ee-ff     dynamic"
        m = re.match(
            rf"\s*(\d+\.\d+\.\d+\.\d+)\s+({MAC_RE})", line, re.IGNORECASE,
        )
        if m:
            table[m.group(1)] = normalize_mac(m.group(2))
    return table


def outbound_local_ip() -> str | None:
    """Discover the IP the OS would use to reach the internet, without sending traffic.

    Works on every platform — `connect` on a UDP socket only sets the kernel's
    routing decision, no packet is actually transmitted.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
