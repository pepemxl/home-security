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
import sys
from dataclasses import dataclass, field, asdict

_IS_WINDOWS = sys.platform.startswith("win")
# MAC pattern accepts both ":" (Linux/macOS) and "-" (Windows arp -a).
_MAC_RE = r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}"

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
    device_type_hint: str | None = None

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
    """Return (alive, rtt_ms, ttl). Works on Linux/macOS (iputils) and Windows."""
    if shutil.which("ping") is None:
        return (False, None, None)
    if _IS_WINDOWS:
        # Windows: -n count, -w timeout in ms
        cmd = ["ping", "-n", str(count), "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout_s), ip]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, check=False,
            timeout=count * (timeout_s + 1),
        )
    except subprocess.TimeoutExpired:
        return (False, None, None)

    out = proc.stdout
    # Windows returns 0 only when at least one reply was received.
    # Linux/macOS ditto. So returncode is the authoritative signal.
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


def _normalize_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


def _arp_for(ip: str) -> str | None:
    """Try every ARP-querying tool we know of. First hit wins."""
    # Linux modern: ip neigh show <ip>
    out = _run(["ip", "neigh", "show", ip])
    m = re.search(rf"lladdr\s+({_MAC_RE})", out, re.IGNORECASE)
    if m:
        return _normalize_mac(m.group(1))
    # Linux/macOS BSD: arp -an <ip>
    out = _run(["arp", "-an", ip])
    m = re.search(rf"({_MAC_RE})", out, re.IGNORECASE)
    if m:
        return _normalize_mac(m.group(1))
    # Windows: arp -a <ip>  (output uses dash-separated MACs)
    out = _run(["arp", "-a", ip])
    # Filter to lines that mention the IP so we don't grab a neighbour by accident.
    for line in out.splitlines():
        if ip in line:
            m = re.search(rf"({_MAC_RE})", line, re.IGNORECASE)
            if m:
                return _normalize_mac(m.group(1))
    return None


def _reverse_dns(ip: str, timeout: float = 0.8) -> str | None:
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


def _netbios(ip: str) -> str | None:
    """Resolve NetBIOS host name. Tries nmblookup (Linux) then nbtstat (Windows)."""
    # Linux/macOS via Samba
    out = _run(["nmblookup", "-A", ip], timeout=4)
    for line in out.splitlines():
        # e.g.  MYPC            <00> -         B <ACTIVE>
        m = re.match(r"\s*(\S+)\s+<00>\s+-\s+B\s+<ACTIVE>", line)
        if m:
            return m.group(1)
    # Windows native
    out = _run(["nbtstat", "-A", ip], timeout=4)
    for line in out.splitlines():
        # e.g.  "    MYPC           <00>  UNIQUE      Registered"
        m = re.match(r"\s*(\S+)\s+<00>\s+UNIQUE\s+Registered", line)
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


def _device_type_hint(profile: "DeviceProfile") -> str | None:
    """Cheap fingerprint based on the open-port signature."""
    p = set(profile.open_ports)
    if 554 in p and (443 in p or 80 in p) and 22 not in p and 445 not in p:
        return "likely IP camera / NVR (RTSP + HTTP(S) web UI)"
    if 554 in p:
        return "RTSP service present (camera/streamer)"
    if 9100 in p:
        return "likely network printer (raw-print 9100)"
    if 3389 in p:
        return "Windows host with RDP exposed"
    if 5357 in p and 445 in p:
        return "likely Windows host (WSD + SMB)"
    if 445 in p and 139 in p and 22 not in p:
        return "likely Windows / Samba file share"
    if 22 in p and 445 not in p and 3389 not in p:
        return "likely Linux/Unix host (SSH only)"
    if 62078 in p:
        return "likely Apple device (iPhone/iPad sync port)"
    if 5000 in p or 1900 in p:
        return "UPnP / DLNA service present"
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

    p.device_type_hint = _device_type_hint(p)
    return p


def is_up(profile: DeviceProfile) -> bool:
    """A host is 'up' if anything responded — ICMP, an open port, or a fresh ARP entry."""
    return bool(profile.reachable or profile.open_ports or profile.mac)


def render(profile: DeviceProfile) -> str:
    """Human-readable multi-line report."""
    if profile.reachable:
        rtt = f"{profile.rtt_ms:.1f} ms" if profile.rtt_ms is not None else "?"
        status = f"UP (icmp ok, {rtt}, ttl={profile.ttl})"
    elif profile.open_ports:
        status = f"UP (icmp blocked; {len(profile.open_ports)} tcp port(s) responding)"
    elif profile.mac:
        status = "UP (in ARP cache, but no ICMP / no listening common ports)"
    else:
        status = "DOWN or not on this LAN"

    lines = [
        f"Host: {profile.ip}",
        f"  status    : {status}",
        f"  os guess  : {profile.os_guess or 'unknown'}",
        f"  type hint : {profile.device_type_hint or '-'}",
        f"  mac       : {profile.mac or '(unknown — try running on the same LAN segment)'}",
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
