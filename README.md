# RCN Port Scanner

A fast, stealthy TCP/UDP port scanner and credential tester written in Node.js with decoy IP support, jitter, and parallel scanning.

---

## Features

| Feature | Details |
|---|---|
| TCP + TLS detection | Tries TLS first, falls back to plain TCP |
| SSL certificate extraction | Captures CN, org, issuer, SANs, and expiry from TLS connections |
| HTTP header parsing | Extracts Server, X-Powered-By, Content-Type, and other fingerprinting headers |
| UDP scanning | Detects open and ICMP-confirmed closed ports |
| Parallel scanning | 50 hosts in parallel, 50 TCP + 20 UDP workers per host |
| Half-open SYN scan | `--syn` flag sends real-source-IP SYNs without completing the TCP handshake — SSH, NGINX, Apache, and Cowrie never log the probe |
| Slow mode | `--slow` flag drops to 5 concurrent hosts, 10 TCP connections, and 5–60s jitter |
| Service-appropriate probes | Passive banner read for SSH/FTP/POP3/IMAP/MySQL/Redis/Telnet; plain EHLO exchange for SMTP (25/587); implicit-TLS EHLO for SMTPS (465) |
| Port shuffle | Fisher-Yates randomised scan order per host |
| Jitter | Random 10–250ms delay before each probe (5–60s in slow mode) |
| Random source port | Breaks sequential local port fingerprint in decoy packets |
| Decoy IPs | Fires spoofed RFC1918 SYN packets before each real probe (requires root) |
| CIDR support | Accepts `/16`–`/32` ranges in target file |
| Resume-safe output | Results written after each host, survives early exit |
| Banner grabbing | Captures first line of HTTP response per open port |
| Rotating HTTP headers | Referer, Accept-Language, Cookie, User-Agent, and path rotated per probe |
| PTR hostname | Reverse DNS lookup stored in `hostname` field when it differs from the IP |
| WHOIS enrichment | Queries whois.ripe.net for each host and adds an `owner` field |
| Honeypot detection | Flags Cowrie SSH/FTP banners, live SSH KEX fingerprinting, T-Pot port combos, Telnet, and bare SSH version strings |
| CVE lookup | Parses software versions from banners and HTTP headers, queries the NVD API for matching CVEs, and writes results back into the scan JSON under a `cves` field per port. Supports 11 services; handles NVD rate limiting (5 req/30 s) |
| Credential testing | Wordlist-based SSH, FTP, and HTTP/HTTPS login testing against scan results |
| Geolocation | Queries ip-api.com batch endpoint for country, city, lat/lon, ISP, org, and AS per host; writes a `geo` field into the scan JSON. Handles rate limiting (100 IPs/batch, 4.5 s between batches). Falls back to home directory on EACCES |
| Interactive map | HTML report renders a Leaflet.js world map with colour-coded circle markers (red = honeypot, orange = credentials found, green = clean) whenever geo data is present |
| SIGINT handler | Ctrl+C flushes partial results before exit |

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
sudo node src/scanner.js <target> <start-port> <end-port> [output.json] [--slow] [--syn] [--udp]
```

`<target>` can be a **targets file**, a **single IP**, or a **CIDR block**.

| Flag | Effect |
|---|---|
| `--slow` | 5 concurrent hosts, 10 TCP connections per host, 5–60s jitter — for low-noise scans |
| `--syn` | Half-open SYN scan — TCP probes never complete the handshake, so application daemons (SSH, NGINX, Apache, Cowrie) write no log entry. Requires root and the `raw-socket` package. Results have `proto: "SYN"` and no banner, cert, or headers |
| `--udp` | Also scan UDP ports (off by default — slow and rarely useful on most targets) |

Flags can be combined: `--syn --slow`

```bash
# Scan from a targets file
sudo node src/scanner.js config/targets.txt 1 1024

# Scan a single host
sudo node src/scanner.js 192.168.1.1 1 65535

# Scan a /24 range
sudo node src/scanner.js 10.0.0.0/24 80 443

# Custom output file
sudo node src/scanner.js config/targets.txt 1 1024 scans/results.json

# Low-noise scan with extended jitter
sudo node src/scanner.js 192.168.1.1 1 1024 --slow

# Half-open SYN scan — no application logs on target
sudo node src/scanner.js 192.168.1.1 1 1024 --syn

# Half-open SYN scan with extended jitter
sudo node src/scanner.js 192.168.1.1 1 1024 --syn --slow
```

### Step 2 — Geolocate hosts (optional)

```bash
node src/geolocate.js <scan.json>
```

Queries the ip-api.com batch endpoint for country, city, lat/lon, ISP, org, and AS for every host
and writes the results back into the scan JSON under a `geo` field. Uses the free tier (no signup
needed); sends up to 100 IPs per request and pauses 4.5 s between batches to stay within the
15-requests-per-minute limit. Does not use HTTPS (free-tier limitation). If the scan file is not
writable, saves to the home directory instead.

```bash
node src/geolocate.js scans/scan_1748476800000.json
```

---

### Step 3 — Enrich results with WHOIS owner data (optional)

```bash
node src/enrich.js <scan.json>
```

Queries `whois.ripe.net` for each host IP and adds an `owner` field (organisation name, netname,
or description) to every entry in the scan JSON. Results are written back into the same file.

```bash
node src/enrich.js scans/scan_1748476800000.json
```

---

### Step 4 — Detect honeypots in scan results

```bash
node src/honeypot.js <scan.json>
```

Reads the scan JSON produced by the scanner and flags suspected honeypots using static checks
(known Cowrie SSH and FTP banners, T-Pot port combinations, open Telnet, bare SSH version strings
with no OS suffix, suspiciously many open ports) and live SSH KEX fingerprinting (connects to each
SSH port, reads `MSG_KEXINIT`, and checks algorithm lists against known Cowrie tells). Results are
written back into the same JSON under a `honeypot` field.

```bash
node src/honeypot.js scans/scan_1748476800000.json
```

---

### Step 5 — Scan for CVEs in detected software versions (optional)

```bash
node src/vulnscan.js <scan.json>
```

Parses software versions from service banners and HTTP response headers, queries the
[NVD REST API](https://nvd.nist.gov/developers/vulnerabilities) for matching CVEs, and writes
results back into the scan JSON under a `cves` field on each port entry. Supports 11 services:
OpenSSH, nginx, Apache, Exim, Postfix, Dovecot, ProFTPD, vsftpd, OpenSSL, PHP, and WordPress.

NVD rate-limits unauthenticated requests to ~5 per 30 seconds. The script pauses automatically
to respect this limit; scans with many open ports will take a few minutes.

If the scan file is not writable (e.g. owned by root), the enriched JSON is saved to the home
directory instead and the path is printed.

```bash
node src/vulnscan.js scans/scan_1748476800000.json
```

---

### Step 6 — Test credentials against scan results (optional)

```bash
node src/credtest.js <scan.json> <wordlist.txt> [--hosts=ip1,ip2,...] [--no-http]
```

Pass the JSON file produced by the scanner and a wordlist of `username:password` pairs.
Credentials that succeed are written back into the same JSON file under a `credentials` field.

| Flag | Effect |
|---|---|
| `--hosts=ip1,ip2,...` | Restrict testing to a comma-separated list of IPs from the scan file. Without it, every host is tested |
| `--no-http` | Skip HTTP/HTTPS credential testing. Useful when the scan contains many web ports and HTTP success detection produces false positives |

```bash
# Test all hosts with the default wordlist
node src/credtest.js scans/scan_1748476800000.json config/wordlist.txt

# Test with a custom wordlist
node src/credtest.js scans/results.json /path/to/passwords.txt

# Test only specific hosts from the scan
node src/credtest.js scans/results.json config/wordlist.txt --hosts=192.168.1.1,192.168.1.5

# Skip HTTP/HTTPS testing
node src/credtest.js scans/results.json config/wordlist.txt --no-http
```

---

### Step 7 — Generate an HTML report

```bash
node src/report.js <scan.json> [output.html] [--min-ports=N]
```

Reads the scan JSON (after any combination of the earlier steps) and writes a self-contained,
dark-themed HTML file. No server or external assets are required — open the file directly in a
browser.

| Flag / argument | Effect |
|---|---|
| `<scan.json>` | Path to the scan JSON produced by previous steps |
| `[output.html]` | Optional output path; defaults to the same path as the input with `.html` extension |
| `--min-ports=N` | Only include hosts with N or more open ports in the report |
| `--help` / `-h` | Print usage and exit |

```bash
# Report saved alongside the scan file
node src/report.js scans/scan_1748476800000.json

# Report saved to a custom path
node src/report.js scans/scan_1748476800000.json reports/results.html

# Only include hosts with 6 or more open ports
node src/report.js scans/scan_1748476800000.json reports/results.html --min-ports=6
```

The generated report includes:
- Summary stats: hosts with open ports, total open ports, suspected honeypots, hosts with credentials, total CVEs found
- Leaflet.js world map with colour-coded circle markers (red = honeypot, orange = credentials found, green = clean); rendered only when `geo` data is present in the scan JSON. Each marker popup shows IP, city/country, ISP, and open ports
- Live search/filter bar (IP, banner, port, owner)
- Checkboxes to show only honeypots or only hosts with credentials
- Each host displayed as a card; honeypot cards are highlighted with a red border and show detection reasons; cards with geo data show a city/country label in the header
- Per-port table with protocol badge, banner, TLS certificate details (CN, Org, Issuer, SANs, expiry), and HTTP response headers
- CVE entries per port: clickable NVD links, severity badges (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green), CVSS scores, and truncated summaries
- Credential results shown in green at the bottom of the relevant host card

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
Each subsequent step (`enrich.js`, `honeypot.js`, `vulnscan.js`, `credtest.js`) enriches the same
file in place. A fully-processed entry looks like this:

```json
[
  {
    "host": "192.168.1.1",
    "hostname": "server1.example.com",
    "ports": {
      "22": {
        "proto": "TCP",
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
      },
      "8022": {
        "proto": "SYN"
      },
      "80": {
        "proto": "TCP",
        "banner": "HTTP/1.1 200 OK",
        "headers": { "server": "nginx/1.24.0" }
      },
      "443": {
        "proto": "TLS",
        "banner": "HTTP/1.1 200 OK",
        "cert": {
          "cn": "example.com",
          "org": "Example Corp",
          "issuer": "Let's Encrypt",
          "sans": ["example.com", "www.example.com"],
          "expires": "Jan  1 00:00:00 2027 GMT"
        },
        "headers": { "server": "nginx/1.24.0", "x-powered-by": "PHP/8.2" },
        "cves": [
          {
            "software": "nginx 1.24.0",
            "cves": [
              {
                "id": "CVE-2024-7347",
                "severity": "MEDIUM",
                "score": 4.7,
                "summary": "NGINX Open Source and NGINX Plus have a vulnerability...",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-7347"
              }
            ]
          }
        ]
      }
    },
    "scannedAt": "2026-05-29T12:00:00.000Z",
    "owner": "Example Corp",
    "geo": {
      "country": "Germany",
      "countryCode": "DE",
      "city": "Falkenstein",
      "lat": 50.4779,
      "lon": 12.3713,
      "isp": "Hetzner Online GmbH",
      "org": "Hetzner Online GmbH",
      "as": "AS24940 Hetzner Online GmbH"
    },
    "credentials": {
      "22": { "user": "admin", "pass": "password", "service": "SSH" },
      "80": { "user": "admin", "pass": "admin",    "service": "HTTP" }
    }
  }
]
```

---

## How Decoy Mode Works

Before each real TCP probe, the scanner fires `4` spoofed SYN packets. Source IPs are drawn from
the scan target pool (same address range as the real targets), falling back to random hosts in the
destination's /24 when the pool is too small. Each packet is 60 bytes (20-byte IP header + 40-byte
TCP header with options: MSS, SACK permitted, Timestamps, NOP, Window Scale) — indistinguishable
from a real Linux SYN. The target logs see:

```
37.27.7.131   → target:port   (decoy)
37.27.7.140   → target:port   (decoy)
37.27.7.129   → target:port   (decoy)
37.27.7.138   → target:port   (decoy)
YOUR_REAL_IP  → target:port   (real)
```

Requires root for raw socket access. The scanner exits with an error if not run as root.

---

## Project Structure

```
PortScanner/
├── src/
│   ├── scanner.js           Port scanner
│   ├── geolocate.js         Geolocation (ip-api.com batch, writes geo field per host)
│   ├── enrich.js            WHOIS enrichment (adds owner field)
│   ├── honeypot.js          Honeypot detector
│   ├── vulnscan.js          CVE lookup (NVD API, writes cves field per port)
│   ├── credtest.js          Credential tester
│   ├── report.js            HTML report generator (Leaflet map when geo data present)
│   └── utils.js             Shared helpers (jitter, runPool)
├── config/
│   ├── settings.json        Tunable parameters for scanner, credtest, and honeypot
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
