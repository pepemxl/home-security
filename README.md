# home-security

Audit your **own** home network: discover connected devices by IP, identify
them (MAC, vendor, hostname), optionally scan common ports, and compare
against a saved baseline so unknown / new devices stand out.

> Only scan networks you own or have explicit permission to test.

## Features

- Host discovery on the local subnet (ICMP ping sweep + ARP table)
- Reverse DNS / NetBIOS hostname resolution
- MAC vendor (OUI) lookup (offline DB, refreshable from IEEE)
- Optional TCP port scan of common services (22, 23, 80, 443, 445, 8080…)
- JSON device inventory + diff against last scan to flag new/unknown hosts
- CLI: `home-security scan`, `inventory`, `diff`, `ports`

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Auto-detect subnet, scan, save inventory
sudo python -m home_security scan

# Pin a subnet explicitly
sudo python -m home_security scan --cidr 192.168.1.0/24

# Compare current devices against the saved baseline
python -m home_security diff

# Mark a known device as trusted in the inventory
python -m home_security inventory trust AA:BB:CC:DD:EE:FF --label "my-laptop"

# Port scan a single host
python -m home_security ports 192.168.1.10
```

`sudo` is recommended for ARP-level discovery and faster ping sweeps;
without it the tool falls back to the system ARP cache + non-privileged
pings.

## Layout

```
home_security/
  __init__.py
  cli.py          # argparse entry point
  scanner.py      # ping sweep + ARP discovery
  vendor.py       # MAC OUI vendor lookup
  ports.py        # TCP connect scan
  inventory.py    # baseline + diff
  net.py          # subnet auto-detect, helpers
data/
  oui.csv         # small bundled OUI subset (refreshable)
  inventory.json  # generated; trusted device list
```

## Safety notes

- Default port scan is a *connect* scan (no raw sockets needed) limited to a
  short, well-known list. Edit `home_security/ports.py` to extend it.
- The tool never alters traffic; it only observes.
- Keep `data/inventory.json` private — it leaks your device fingerprints.
