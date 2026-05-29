# RCN Port Scanner

A fast, stealthy TCP/UDP port scanner written in Node.js with decoy IP support, jitter, and parallel scanning.

---

## Features

| Feature | Details |
|---|---|
| TCP + TLS detection | Tries TLS first, falls back to plain TCP |
| UDP scanning | Detects open and ICMP-confirmed closed ports |
| Parallel scanning | 50 hosts in parallel, 50 TCP + 20 UDP workers per host |
| Port shuffle | Fisher-Yates randomised scan order per host |
| Jitter | Random 10–250ms delay before each probe |
| Random source port | Breaks sequential local port fingerprint |
| Decoy IPs | Fires spoofed RFC1918 SYN packets before each real probe (requires root) |
| CIDR support | Accepts `/16`–`/32` ranges in target file |
| Resume-safe output | Results written after each host, survives early exit |
| Banner grabbing | Captures first line of HTTP response per open port |

---

## Requirements

- Node.js 18+
- Root / sudo (required for decoy mode)
- `base-devel` + `python` for native addon compilation (Arch: `sudo pacman -S base-devel python`)

---

## Installation

```bash
git clone https://github.com/0Day-legalize/JSPortscanner
cd JSPortscanner
npm install raw-socket
```

---

## Usage

```bash
sudo node src/scanner.js <target> <start-port> <end-port> [output.json]
```

`<target>` can be a **targets file**, a **single IP**, or a **CIDR block**:

```bash
# Scan from a targets file
sudo node src/scanner.js config/targets.txt 1 1024

# Scan a single host
sudo node src/scanner.js 192.168.1.1 1 65535

# Scan a /24 range
sudo node src/scanner.js 10.0.0.0/24 80 443

# Custom output file
sudo node src/scanner.js config/targets.txt 1 1024 scans/results.json
```

---

## Target File Format

```
# Lines starting with # are ignored
192.168.1.1
10.0.0.0/24
172.16.0.0/16
example.com
```

---

## Output

Results are saved as JSON to `scans/` by default (one file per run, timestamped):

```json
[
  {
    "host": "192.168.1.1",
    "ports": [
      { "port": 80,  "proto": "TCP", "state": "open", "banner": "HTTP/1.1 200 OK" },
      { "port": 443, "proto": "TLS", "state": "open", "banner": null }
    ],
    "scannedAt": "2026-05-29T12:00:00.000Z"
  }
]
```

---

## How Decoy Mode Works

Before each real TCP probe, the scanner fires `4` spoofed SYN packets from random private IP addresses (RFC1918). The target logs see:

```
10.45.23.11   → target:port   (decoy)
192.168.4.77  → target:port   (decoy)
172.16.88.3   → target:port   (decoy)
10.201.7.44   → target:port   (decoy)
YOUR_REAL_IP  → target:port   (real)
```

Requires root for raw socket access. The scanner exits with an error if not run as root.

---

## Project Structure

```
JSPortscanner/
├── src/
│   └── scanner.js       Main scanner
├── config/
│   └── targets.txt      Target list
├── scans/               Scan output (gitignored)
├── archive/             Basic TCP/UDP snippets for reference
└── package.json
```

---

## License

MIT — © 0Day-legalize
