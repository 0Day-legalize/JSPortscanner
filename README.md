# RCN Port Scanner

A fast, stealthy TCP/UDP port scanner and credential tester written in Node.js with decoy IP support, jitter, and parallel scanning.

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
| Credential testing | Wordlist-based SSH, FTP, and HTTP/HTTPS login testing against scan results |

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
npm install
```

---

## Usage

### Step 1 — Scan for open ports

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

### Step 2 — Test credentials against scan results

```bash
node src/credtest.js <scan.json> <wordlist.txt>
```

Pass the JSON file produced by the scanner and a wordlist of `username:password` pairs.
Credentials that succeed are written back into the same JSON file under a `credentials` field.

```bash
# Test with the default wordlist
node src/credtest.js scans/scan_1748476800000.json config/wordlist.txt

# Test with a custom wordlist
node src/credtest.js scans/results.json /path/to/passwords.txt
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

## Wordlist Format

Each line must be `username:password`. Lines starting with `#` and blank lines are ignored.

```
# config/wordlist.txt
admin:admin
admin:password
root:toor
user:123456
```

---

## Output

Results are saved as JSON to `scans/` by default (one file per run, timestamped).
After running `credtest.js`, successfully cracked ports are merged into the same file:

```json
[
  {
    "host": "192.168.1.1",
    "ports": {
      "22":  "TCP: SSH-2.0-OpenSSH_8.9",
      "80":  "TCP: HTTP/1.1 200 OK",
      "443": "TLS"
    },
    "scannedAt": "2026-05-29T12:00:00.000Z",
    "credentials": {
      "22": { "user": "admin", "pass": "password", "service": "SSH" },
      "80": { "user": "admin", "pass": "admin",    "service": "HTTP" }
    }
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
PortScanner/
├── src/
│   ├── scanner.js           Port scanner
│   └── credtest.js          Credential tester
├── config/
│   ├── settings.json        Tunable parameters for scanner and credtest
│   ├── targets.txt          Default target list (IPs, hostnames, CIDRs)
│   └── wordlist.txt         Default credential wordlist (username:password)
├── scans/                   Scan output (gitignored)
├── docs/
│   ├── overview.md          Architecture and data flow
│   ├── functions.md         Per-function reference
│   ├── obfuscation.md       Stealth technique details
│   └── constants.md         settings.json field reference
└── package.json
```

---

## License

MIT — © Freazer26 + 0Day-legalize

---

*Reviewed with [Claude](https://claude.ai)*
