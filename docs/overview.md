# Port Scanner — Architecture Overview

A stealth-capable TCP/UDP port scanner written in Node.js ESM with an optional credential-testing
phase. It resolves targets, shuffles and probes ports with injected jitter and decoy SYN packets,
writes all open-port results to a JSON file, and can then run a wordlist-based login test against
every detected service.

---

## Data flow

```
┌──────────────────────────────────────────────────────────┐
│  PHASE 1 — PORT SCANNING  (src/scanner.js)               │
└──────────────────────────────────────────────────────────┘

CLI arguments
  targetFile  firstPort  lastPort  [outputFile]  [--slow]  [--syn]
       │
       ▼
┌─────────────────────────┐
│   Target resolution     │  process.argv parsing
│                         │
│  file path?             │
│    └─ parseTargetFile() │  reads lines from disk
│  CIDR string?           │
│    └─ expandCIDR()      │  enumerates host IPs
│  bare host?             │
│    └─ used as-is        │
└──────────┬──────────────┘
           │  string[]  — flat list of IPs / hostnames
           ▼
┌─────────────────────────┐
│   Host pool             │  runPool(hostTasks, MAX_HOST_WORKERS)
│                         │
│  For each host:         │
│    scanHost()           │
│      │                  │
│      ├─ shufflePorts()  │  randomise probe order
│      ├─ dns.lookup()    │  resolve hostname → IP (for decoys)
│      ├─ dns.reverse()   │  PTR lookup → hostname for TLS SNI + HTTP Host header
│      │                  │
│      │  TCP pool        │  runPool(tcpTasks, MAX_TCP_CONNECTIONS)
│      │    jitter()      │  random inter-probe delay
│      │    sendDecoys()  │  DECOY_COUNT spoofed SYN packets
│      │    [normal mode] │
│      │    scanTCPPort() │
│      │      tryTLSConnect()  ──► banner grab + cert extraction + header parsing
│      │      tryTCPConnect()  ──► banner grab (fallback)
│      │    [--syn mode]  │
│      │    probeSYNHalfOpen() ──► SYN sent, SYN-ACK awaited, handshake never completed
│      │                  │    (no application log on target; result proto="SYN")
│      │                  │
│      └─ UDP pool        │  runPool(udpTasks, MAX_UDP_CONNECTIONS)
│           jitter()      │
│           scanUDPPort() │
│             tryUDPConnect()  ──► response / OPEN|FILTERED / closed
│                         │
│      onPortResult()     │  filters, prints, accumulates
│      sort by port       │
└──────────┬──────────────┘
           │  { host, hostname?, ports{}, scannedAt }[]
           ▼
┌─────────────────────────┐
│   Output                │
│                         │
│  JSON written after     │
│  every host completes   │  incremental flush — survives SIGINT
│  (fs.writeFileSync)     │
│                         │
│  scans/scan_<ts>.json   │  timestamped default path
└──────────┬──────────────┘
           │
           │  (optional — run manually as subsequent steps)
           ▼

┌──────────────────────────────────────────────────────────┐
│  PHASE 2 — WHOIS ENRICHMENT  (src/enrich.js)             │
└──────────────────────────────────────────────────────────┘

CLI arguments
  scan.json
       │
       ▼
┌─────────────────────────┐
│   For each host entry:  │
│                         │
│   whoisLookup()         │  TCP to whois.ripe.net:43
│   parseOwner()          │  extracts org-name / netname / descr
│                         │
│   entry.owner = result  │  written back into each host entry
└──────────┬──────────────┘
           │  scan JSON updated in place
           ▼

┌──────────────────────────────────────────────────────────┐
│  PHASE 3 — CREDENTIAL TESTING  (src/credtest.js)         │
└──────────────────────────────────────────────────────────┘

CLI arguments
  scan.json  wordlist.txt  [--hosts=ip1,ip2,...]
       │
       ▼
┌─────────────────────────┐
│   Input parsing         │
│                         │
│  JSON.parse(scan.json)  │  load scan results from Phase 1
│  parseWordlist()        │  load username:password pairs
└──────────┬──────────────┘
           │  scanResults[]  +  credentials[]
           ▼
┌─────────────────────────┐
│   Host loop             │  sequential, one host at a time
│                         │
│  For each host entry:   │
│    testHost()           │
│      │                  │
│      ├─ detectService() │  classify each open port by number/banner
│      │                  │
│      │  Per service:    │  runPool(tasks, CRED_CONCURRENCY)
│      │    jitter()      │  random inter-attempt delay (500–2000ms)
│      │    trySSH()      │  ssh2 auth attempt
│      │    tryFTP()      │  basic-ftp plain + implicit TLS
│      │    tryHTTP()     │  axios POST across endpoints × field sets
│      │                  │
│      └─ stop on first   │  cracked flag halts remaining tasks
│         valid cred      │
└──────────┬──────────────┘
           │  hits: { port → { user, pass, service } }
           ▼
┌─────────────────────────┐
│   Output (merge)        │
│                         │
│  Successful creds are   │
│  written back into the  │  hostEntry.credentials = hits
│  original scan JSON     │
│  after each host        │  incremental flush — survives early exit
└─────────────────────────┘
```

---

## Key design decisions

| Decision | Reason |
|---|---|
| Ports scanned in shuffled order | Sequential scans are trivially detected by IDS/IPS |
| Random inter-probe jitter | Uniform probe timing is a classic scanner fingerprint |
| Random local source port per socket | Sequential local ports are another IDS signal; used in decoy SYN packets via `buildSynPacket` |
| Decoy SYN packets from private IPs | Floods IDS alert queues with spoofed origins before each real probe |
| TLS attempted before plain TCP | A plaintext connect to a TLS port returns garbage; TLS-first gets useful data |
| TLS connect split into `tryTLSConnect` | Allows cert extraction at `secureConnect` time, before the banner is written |
| `extractCert` on every TLS connection | SANs and CN identify the host owner without a separate lookup |
| `parseHeaders` on every HTTP response | Server, X-Powered-By, and CMS headers fingerprint the stack without additional probes |
| `hostname` field on host results | PTR record stored so downstream tools know the resolved name without re-querying DNS |
| WHOIS enrichment is a separate process | Owner lookup is slow and sequential; keeping it out of the scanner avoids blocking port probes |
| PLAINTEXT_PORTS skip-list | Avoids wasted TLS handshake attempts on protocols that never negotiate TLS |
| Incremental JSON flush (scanner) | Partial results are preserved if the process is interrupted |
| Incremental JSON flush (credtest) | Cracked credentials are saved host-by-host; a crash loses at most one host |
| Credential testing is a separate process | Decouples scan speed from login attempt rate; each phase can be tuned independently |
| credtest jitter range is wider (500–2000ms) | Login attempts must stay below account lockout thresholds; wider spacing is safer |
| `cracked` flag stops the wordlist on first hit | Avoids unnecessary login noise after success; most services lock accounts after N failures |
| `raw-socket` loaded optionally | Scanner still functions (without decoys) when not running as root |
| Optional npm dependencies in credtest | Missing ssh2/basic-ftp/axios disables that protocol without crashing the tool |
| `jitter` and `runPool` extracted to `utils.js` | Eliminates the previously duplicated implementations between scanner and credtest |
| SIGINT handler in scanner | Ctrl+C flushes the in-progress results array to disk before the process exits, preserving partial scans |
| Port validation at startup | NaN, out-of-range, or inverted port arguments exit early with a clear error rather than producing an empty or corrupt scan |
| Rotating Referer, Accept-Language, Cookie per probe | Each HTTP banner probe uses a different randomly chosen value from the configured lists, making all probes from the same scan look like different browser sessions |
| `--slow` mode | A single CLI flag drops to 5 concurrent hosts, 10 TCP connections, and 5–60s jitter; all limits are read from `settings.json` so no code changes are needed |
| `--syn` mode | Half-open SYN scan via `probeSYNHalfOpen`; the TCP handshake is never completed so application-layer daemons (SSH, NGINX, Apache, Cowrie) write no log entry for the probe; can be combined with `--slow` |
| Service-appropriate probe dispatch in `scanTCPPort` | Ports in `PASSIVE_PORTS` use `probeBannerOnly` (passive read, no HTTP); ports in `SMTP_PORTS` use `probeSMTP` (EHLO exchange); all others use the TLS-first HTTP strategy — prevents protocol-mismatch errors appearing in service logs |
| TCP options in decoy SYN packets | MSS(1460), SACK, Timestamps, NOP, Window Scale(7) make the 60-byte packet match a real Linux kernel SYN, defeating OS-fingerprint-based decoy detection |

---

## Module layout

```
PortScanner/
├── src/
│   ├── scanner.js          Port scanner — all scan logic lives here
│   ├── enrich.js           WHOIS enrichment — adds owner field to each host entry
│   ├── credtest.js         Credential tester — runs after scanner produces output
│   ├── honeypot.js         Honeypot detector — flags suspected honeypots in scan results
│   └── utils.js            Shared helpers — jitter() and runPool() used by scanner and credtest
├── config/
│   ├── settings.json       Tunable parameters for scanner, credtest, and honeypot
│   ├── targets.txt         Default target list (IPs, hostnames, CIDRs)
│   └── wordlist.txt        Default credential wordlist (username:password)
├── scans/                  JSON output directory (auto-created at runtime)
└── docs/
    ├── overview.md         This file
    ├── functions.md        Per-function reference
    ├── obfuscation.md      Stealth technique details
    └── constants.md        settings.json field reference
```

---

## Runtime requirements

- Node.js 18+ (ESM `import`, top-level `await`)
- `raw-socket` npm package (optional — required for decoy SYN injection)
- `ssh2` npm package (optional — required for SSH credential testing)
- `basic-ftp` npm package (optional — required for FTP credential testing)
- `axios` npm package (optional — required for HTTP/HTTPS credential testing)
- Root / `sudo` (enforced at scanner startup — required by raw socket API)

---

*Documentation written with assistance from [Claude](https://claude.ai) — used for documentation, package understanding, and packet crafting reference.*
