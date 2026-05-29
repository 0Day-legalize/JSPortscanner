# Constants Reference

All constants are defined at the top of `src/scanner.js` in the `CONSTANTS` section.
Every constant is a `const` at module scope. None are configurable at runtime without editing the
source — there are no environment variable or CLI overrides.

---

## MAX_TCP_CONNECTIONS

| Property | Value |
|---|---|
| Default | `50` |
| Type | `number` (integer) |
| Scope | Per host — `runPool` is called once per host |

**What it controls:**
The maximum number of TCP port probes that are in flight simultaneously for a single host.
This is the `workerLimit` argument passed to `runPool` for the TCP task array in `scanHost`.

**Effect of increasing:**
More concurrent connections → faster scan per host. Each additional slot consumes one OS file
descriptor and one OS socket buffer. Above roughly 200–500 simultaneous connections on a standard
Linux system you will start hitting `EMFILE` (too many open files) or `ECONNREFUSED` errors from
the local OS before the target rejects you. The scan speed gain plateaus once you are network-bound
rather than concurrency-bound.

**Effect of decreasing:**
Fewer concurrent connections → slower scan per host. Reducing to 1 makes the TCP scan sequential
and very slow but produces the lowest possible probe rate, which is the hardest to detect by
volume-based IDS rules.

**Interaction with jitter:**
Effective probe rate ≈ `MAX_TCP_CONNECTIONS / avg_jitter_ms`. With default values:
`50 / 130ms ≈ 0.38 probes/ms ≈ 385 probes/sec` for TCP across all concurrent workers.

---

## MAX_UDP_CONNECTIONS

| Property | Value |
|---|---|
| Default | `20` |
| Type | `number` (integer) |
| Scope | Per host |

**What it controls:**
The maximum number of UDP probes in flight simultaneously for a single host.

**Why lower than TCP:**
UDP sockets are stateless and each one binds a file descriptor until the timeout fires or a reply
arrives. With `SOCKET_TIMEOUT_MS = 2000` ms and 20 workers, you can probe approximately
`20 / 2s = 10 UDP ports/sec`. Raising this aggressively risks exhausting file descriptors because
UDP sockets stay open longer than TCP sockets (no FIN/RST exchange).

**Effect of increasing:**
Faster UDP scan, higher FD consumption. Routers and firewalls will also rate-limit ICMP
port-unreachable responses (RFC 1812 §4.3.2.8), so many simultaneous UDP probes may receive
delayed or suppressed ICMP responses, turning closed ports into false `OPEN|FILTERED` results.

**Effect of decreasing:**
More conservative FD usage, lower risk of false-positives from ICMP rate-limiting. Very low values
(1–2) make UDP scanning extremely slow given the `SOCKET_TIMEOUT_MS` timeout.

---

## MAX_HOST_WORKERS

| Property | Value |
|---|---|
| Default | `50` |
| Type | `number` (integer) |
| Scope | Global — controls `runPool` at the host level |

**What it controls:**
How many hosts are scanned concurrently. Each host runs its own TCP and UDP pools internally, so
the total number of active sockets is up to `MAX_HOST_WORKERS × (MAX_TCP_CONNECTIONS + MAX_UDP_CONNECTIONS)` = `50 × 70` = 3,500 simultaneous sockets at peak.

**Effect of increasing:**
Dramatically faster for large CIDR ranges or target lists with many hosts. However, the total
socket count rises proportionally and can quickly exceed OS limits. The effective network bandwidth
consumed also rises — against a remote target this may saturate your uplink or trigger upstream
rate-limiting.

**Effect of decreasing:**
Fewer total sockets, gentler on system resources, lower aggregate probe rate. Setting this to 1
serialises host scanning entirely, which is appropriate when scanning a single sensitive target or
when operating under strict rate-limit constraints.

**Practical ceiling:**
On a default Linux system with `ulimit -n 65536`, the practical ceiling before FD exhaustion is
roughly `65536 / 70 ≈ 936` host workers. The default of 50 provides a large safety margin.

---

## SOCKET_TIMEOUT_MS

| Property | Value |
|---|---|
| Default | `2000` (ms) |
| Type | `number` |
| Scope | Per socket — used in both `tryTCPConnect` and `tryUDPConnect` |

**What it controls:**
How long the scanner waits for a response after establishing or sending to a socket before
declaring the attempt dead. Applied via `socket.setTimeout()` (TCP/TLS) and `setTimeout` (UDP).

**Effect of increasing:**
Catches more open ports on high-latency targets (long round-trips, overloaded services, congested
networks). Dramatically slows scan completion time because slow-to-respond or silently filtered
ports each hold a worker slot for the full timeout duration.

**Effect of decreasing:**
Faster scans. Risk of false-negatives on legitimate open ports that are slow to respond. For local
network targets with sub-10ms RTT, values as low as 200–500ms are reliable. For internet targets
with 100–300ms RTT, values below 1000ms risk missing open ports.

**UDP-specific note:**
For UDP, `SOCKET_TIMEOUT_MS` is the primary mechanism for deciding `OPEN|FILTERED`. A shorter
timeout means fewer `OPEN|FILTERED` results (more presumed-closed), which may improve signal
quality but also increases false-negatives for services with slow or delayed responses.

---

## JITTER_MIN_MS

| Property | Value |
|---|---|
| Default | `10` (ms) |
| Type | `number` |
| Scope | Lower bound of `jitter()` delay range |

**What it controls:**
The minimum pause between probe attempts. Even in the fastest case, probes are at least 10ms apart.

**Effect of increasing:**
Wider minimum gap between probes. At high values (e.g. 500ms) the scan becomes noticeably stealthy
but very slow. The minimum delay directly increases total scan time by `numPorts × JITTER_MIN_MS`
in the single-worker worst case.

**Effect of decreasing (toward 0):**
Probes can be back-to-back with no pause. Zero jitter with high concurrency approaches a flood
scanner in behaviour and rate. Setting to 0 is not recommended — the IDS evasion value of jitter
comes from its lower bound providing a guaranteed minimum spread, not just a maximum.

---

## JITTER_MAX_MS

| Property | Value |
|---|---|
| Default | `250` (ms) |
| Type | `number` |
| Scope | Upper bound of `jitter()` delay range |

**What it controls:**
The maximum possible pause between probe attempts. Combined with `JITTER_MIN_MS`, this defines the
full inter-probe delay distribution `U[10ms, 250ms]` with mean 130ms.

**Effect of increasing:**
Wider spread makes the timing signature harder to fingerprint statistically. However, very high
values (seconds) have diminishing returns and massively extend scan duration.

**Effect of decreasing (toward JITTER_MIN_MS):**
Narrows the distribution toward a fixed delay. A fixed delay is better than no delay but worse than
a wide random range for IDS evasion, since the probe rate becomes predictable again.

**Relationship to `JITTER_MIN_MS`:**
Must always be `>= JITTER_MIN_MS`. If set equal to `JITTER_MIN_MS`, the delay is fixed (the range
collapses to a single value). If accidentally set below `JITTER_MIN_MS`, `Math.random() * negative`
produces negative numbers and `Math.floor` rounds toward 0, causing `delay = JITTER_MIN_MS + negative`
which still lands in a valid range — but this is a bug, not a feature. Keep `JITTER_MAX_MS > JITTER_MIN_MS`.

---

## PLAINTEXT_PORTS

| Property | Value |
|---|---|
| Default | `Set([21, 22, 23, 25, 53, 3306, 5432, 6379, 27017])` |
| Type | `Set<number>` |
| Scope | Checked in `scanTCPPort` before any connection is made |

**What it controls:**
The set of TCP ports for which TLS is never attempted. Ports in this set go directly to a plain TCP
probe, skipping the TLS-first strategy entirely.

| Port | Protocol | Reason for inclusion |
|---|---|---|
| 21 | FTP | Never speaks TLS natively (FTPS uses explicit TLS via `AUTH TLS` command, not on connect) |
| 22 | SSH | Custom binary protocol; a TLS ClientHello causes an immediate protocol error in sshd logs |
| 23 | Telnet | Plaintext by design |
| 25 | SMTP | Uses STARTTLS (opportunistic upgrade), not TLS-on-connect |
| 53 | DNS | UDP/TCP plaintext; DNS-over-TLS uses port 853, not 53 |
| 3306 | MySQL | Plaintext by default; TLS is opt-in via capability flags |
| 5432 | PostgreSQL | Same as MySQL — STARTTLS-style upgrade, not on-connect TLS |
| 6379 | Redis | Plaintext by default; TLS is a compile-time option rarely enabled |
| 27017 | MongoDB | Plaintext by default |

**Effect of adding a port:**
That port will skip the TLS probe. Use this for any protocol that never negotiates TLS at the very
start of the connection. The scan for that port will be slightly faster (one connection attempt
instead of two) and will not leave TLS error traces in the target service's logs.

**Effect of removing a port:**
That port will receive a TLS probe first. If the service is truly plaintext, the TLS handshake
will fail (returning `null`), and the plain TCP fallback will run anyway — so the result is still
correct, just slower and noisier (a failed TLS record appears in the service log).

---

## DECOY_COUNT

| Property | Value |
|---|---|
| Default | `4` |
| Type | `number` (integer) |
| Scope | Controls the loop in `sendDecoys` |

**What it controls:**
How many spoofed SYN packets are sent to the target port before the real TCP probe. A defender
inspecting traffic sees `DECOY_COUNT + 1` SYN packets at each probed port, from `DECOY_COUNT`
different private IPs plus the real scanner IP.

**Effect of increasing:**
More decoys flood the defender's alert queue with more false source IPs. Each decoy is a raw
packet send — very cheap to generate. However, a large burst of SYNs to a single port from many
sources in the same millisecond is itself suspicious to a sophisticated IDS (a real distributed
scan would not be this synchronous).

**Effect of decreasing (toward 0):**
Fewer false sources. Setting to 0 disables decoys entirely (the loop in `sendDecoys` does not
execute). The real probe is then the only SYN at each port, unambiguously identifiable.

**Setting to 1:**
Only one decoy before the real probe — the defender sees two SYNs at each port from different
sources. Provides some confusion but the low count makes correlation easier.

**Practical range:**
3–8 is the practical sweet spot. Below 3 the signal-to-noise ratio is too favourable for the
defender. Above 8, the rapid burst of synchronous SYNs from different IPs starts to look like a
SYN flood rather than legitimate traffic, potentially triggering different (and more aggressive)
countermeasures.
