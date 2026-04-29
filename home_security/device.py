"""Deep inspection of a single host on the LAN.

Given an IP, gather everything we can without sending exotic traffic:

- ICMP echo (reachable / RTT / TTL → coarse OS guess)
- MAC address (forces ARP refresh by pinging first, then reads neighbour table)
- Vendor (OUI lookup)
- Hostnames: reverse DNS, NetBIOS (nmblookup), mDNS (avahi-resolve)
- TCP-connect scan over the common ports list
- Lightweight banners on a few well-known ports (SSH/HTTP/HTTPS)

Each step is best-effort: if a CLI tool isn't installed we skip it.
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass, field, asdict

from . import ports as ports_mod
from . import vendor


@dataclass
class DeviceProfile:
    ip: str
    reachable: bool = False
    rtt_ms: float | None = None
    ttl: int | None = None
    os_guess: str | None = None
    mac: str | None = None
    vendor: str | None = None
    hostname_dns: str | None = None
    hostname_netbios: str | None = None
    hostname_mdns: str | None = None
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        # JSON-friendly: int keys -> str
        d["banners"] = {str(k): v for k, v in self.banners.items()}
        return d


# ---------- low-level helpers ----------

def _run(cmd: list[str], timeout: float = 5.0) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except subprocess.TimeoutExpired:
        return ""


def _ping(ip: str, count: int = 1, timeout_s: int = 1) -> tuple[bool, float | None, int | None]:
    """Return (alive, rtt_ms, ttl). Parses Linux iputils `ping` output."""
    out = _run(["ping", "-c", str(count), "-W", str(timeout_s), ip], timeout=count * (timeout_s + 1))
    if not out:
        return (False, None, None)
    alive = "bytes from" in out
    rtt = None
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    if m:
        rtt = float(m.group(1))
    ttl = None
    m = re.search(r"\bttl[=:](\d+)", out, re.IGNORECASE)
    if m:
        ttl = int(m.group(1))
    return (alive, rtt, ttl)


def _guess_os_from_ttl(ttl: int | None) -> str | None:
    """Coarse OS family guess from observed TTL.

    Senders pick a default TTL; routers decrement by 1 per hop.
    Round up to the nearest common default.
    """
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/Unix/macOS/Android (default TTL 64)"
    if ttl <= 128:
        return "Windows (default TTL 128)"
    if ttl <= 255:
        return "Network device / router (default TTL 255)"
    return None


def _arp_for(ip: str) -> str | None:
    out = _run(["ip", "neigh", "show", ip])
    m = re.search(r"lladdr\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})", out, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    out = _run(["arp", "-an", ip])
    m = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", out, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _reverse_dns(ip: str, timeout: float = 0.8) -> str | None:
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


def _netbios(ip: str) -> str | None:
    """Run nmblookup -A <ip>, return the first <00> UNIQUE name (the host name)."""
    out = _run(["nmblookup", "-A", ip], timeout=4)
    for line in out.splitlines():
        # e.g.  MYPC            <00> -         B <ACTIVE>
        m = re.match(r"\s*(\S+)\s+<00>\s+-\s+B\s+<ACTIVE>", line)
        if m:
            return m.group(1)
    return None


def _mdns(ip: str) -> str | None:
    out = _run(["avahi-resolve", "-a", ip], timeout=3).strip()
    # Format: "192.168.1.5\thostname.local"
    if "\t" in out:
        return out.split("\t", 1)[1].strip() or None
    return None


def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> str | None:
    """Pull a short banner from a well-known service. Best-effort, never raises."""
    try:
        if port == 443 or port == 8443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    cert = s.getpeercert(binary_form=False) or {}
                    subj = cert.get("subject") if cert else None
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    data = s.recv(512).decode(errors="replace")
            head = data.splitlines()[0] if data else ""
            if subj:
                return f"{head} | cert subject={subj}"
            return head or None
        if port in (80, 8080, 8888):
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                data = s.recv(512).decode(errors="replace")
            for line in data.splitlines():
                if line.lower().startswith("server:") or line.startswith("HTTP/"):
                    return line.strip()
            return data.splitlines()[0] if data else None
        if port == 22:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                return s.recv(128).decode(errors="replace").strip() or None
        if port == 21:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                return s.recv(128).decode(errors="replace").strip() or None
    except OSError:
        return None
    return None


# ---------- public API ----------

def inspect(
    ip: str,
    *,
    do_ping: bool = True,
    do_ports: bool = True,
    do_banners: bool = True,
    port_timeout: float = 0.4,
) -> DeviceProfile:
    """Gather everything we can about *ip*. Best-effort, never raises."""
    p = DeviceProfile(ip=ip)

    if do_ping:
        alive, rtt, ttl = _ping(ip)
        p.reachable, p.rtt_ms, p.ttl = alive, rtt, ttl
        p.os_guess = _guess_os_from_ttl(ttl)

    p.mac = _arp_for(ip)
    if p.mac:
        p.vendor = vendor.lookup(p.mac)

    p.hostname_dns = _reverse_dns(ip)
    p.hostname_netbios = _netbios(ip)
    p.hostname_mdns = _mdns(ip)

    if do_ports:
        p.open_ports = ports_mod.scan(ip, timeout=port_timeout)

    if do_banners and p.open_ports:
        banner_targets = [pt for pt in (21, 22, 80, 443, 8080, 8443, 8888) if pt in p.open_ports]
        for pt in banner_targets:
            b = _grab_banner(ip, pt)
            if b:
                p.banners[pt] = b

    return p


def render(profile: DeviceProfile) -> str:
    """Human-readable multi-line report."""
    lines = [
        f"Host: {profile.ip}",
        f"  reachable : {profile.reachable}"
        + (f"  ({profile.rtt_ms:.1f} ms, ttl={profile.ttl})" if profile.reachable else ""),
        f"  os guess  : {profile.os_guess or 'unknown'}",
        f"  mac       : {profile.mac or '(not in ARP cache — host may be silent or off-LAN)'}",
        f"  vendor    : {profile.vendor or 'unknown'}",
        f"  dns name  : {profile.hostname_dns or '-'}",
        f"  netbios   : {profile.hostname_netbios or '-'}",
        f"  mdns      : {profile.hostname_mdns or '-'}",
    ]
    if profile.open_ports:
        lines.append(f"  open tcp  : {len(profile.open_ports)}")
        for pt in profile.open_ports:
            row = f"    {pt:>5}/{ports_mod.describe(pt)}"
            if pt in profile.banners:
                row += f"   {profile.banners[pt]}"
            lines.append(row)
    else:
        lines.append("  open tcp  : (none of the common ports)")
    return "\n".join(lines)
