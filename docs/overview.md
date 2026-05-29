# Port Scanner — Architecture Overview

A stealth-capable TCP/UDP port scanner written in Node.js ESM.
It resolves targets, shuffles and probes ports with injected jitter and decoy SYN packets, then
writes all open-port results to a JSON file.

---

## Data flow

```
CLI arguments
  targetFile  firstPort  lastPort  [outputFile]
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
│      │                  │
│      │  TCP pool        │  runPool(tcpTasks, MAX_TCP_CONNECTIONS)
│      │    jitter()      │  random inter-probe delay
│      │    sendDecoys()  │  DECOY_COUNT spoofed SYN packets
│      │    scanTCPPort() │
│      │      tryTCPConnect(TLS)  ──► banner grab
│      │      tryTCPConnect(TCP)  ──► banner grab (fallback)
│      │                  │
│      └─ UDP pool        │  runPool(udpTasks, MAX_UDP_CONNECTIONS)
│           jitter()      │
│           scanUDPPort() │
│             tryUDPConnect()  ──► response / OPEN|FILTERED / closed
│                         │
│      onPortResult()     │  filters, prints, accumulates
│      sort by port       │
└──────────┬──────────────┘
           │  { host, ports[], scannedAt }[]
           ▼
┌─────────────────────────┐
│   Output                │
│                         │
│  JSON written after     │
│  every host completes   │  incremental flush — survives SIGINT
│  (fs.writeFileSync)     │
│                         │
│  scans/scan_<ts>.json   │  timestamped default path
└─────────────────────────┘
```

---

## Key design decisions

| Decision | Reason |
|---|---|
| Ports scanned in shuffled order | Sequential scans are trivially detected by IDS/IPS |
| Random inter-probe jitter | Uniform probe timing is a classic scanner fingerprint |
| Random local source port per socket | Sequential local ports are another IDS signal |
| Decoy SYN packets from private IPs | Floods IDS alert queues with spoofed origins before each real probe |
| TLS attempted before plain TCP | A plaintext connect to a TLS port returns garbage; TLS-first gets useful data |
| PLAINTEXT_PORTS skip-list | Avoids wasted TLS handshake attempts on protocols that never negotiate TLS |
| Incremental JSON flush | Partial results are preserved if the process is interrupted |
| `raw-socket` loaded optionally | Scanner still functions (without decoys) when not running as root |

---

## Module layout

```
PortScanner/
├── src/
│   └── scanner.js          Single-file scanner — all logic lives here
├── config/
│   └── targets.txt         Default target list (IPs, hostnames, CIDRs)
├── scans/                  JSON output directory (auto-created at runtime)
└── docs/
    ├── overview.md         This file
    ├── functions.md        Per-function reference
    ├── obfuscation.md      Stealth technique details
    └── constants.md        Constant reference
```

---

## Runtime requirements

- Node.js 18+ (ESM `import`, top-level `await`)
- `raw-socket` npm package (optional — required for decoy SYN injection)
- Root / `sudo` (enforced at startup — required by raw socket API)
