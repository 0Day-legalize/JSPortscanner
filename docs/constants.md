# Configuration Reference — `config/settings.json`

All tunable parameters live in `config/settings.json`. Both `src/scanner.js` and `src/credtest.js`
read this file at startup under their respective top-level keys (`scanner` and `credtest`). No
environment variables or CLI flags are needed — edit the JSON file and restart the process.

```json
{
  "scanner":  { ... },
  "credtest": { ... }
}
```

---

## scanner section

Controls port-scanning behaviour in `src/scanner.js`.

---

### maxTCPConnections

| Property | Value |
|---|---|
| Default | `50` |
| Type | `number` (integer) |
| Scope | Per host — `workerLimit` argument to the TCP `runPool` call inside `scanHost` |

**What it controls:**
Maximum number of TCP port probes in flight simultaneously for a single host.

**Effect of increasing:**
Faster scan per host. Each additional slot consumes one OS file descriptor. Above roughly 200–500
simultaneous connections you will hit `EMFILE` or the target will start rate-limiting connections
before you see further speed gains.

**Effect of decreasing:**
Slower scan per host. Setting to `1` makes TCP scanning sequential, producing the lowest possible
per-host probe rate and the weakest volume-based IDS signal.

**Interaction with jitter:**
Effective TCP probe rate ≈ `maxTCPConnections / avgJitter`. With defaults (`50` workers,
130 ms mean jitter): `50 / 0.13s ≈ 385 probes/sec` across all workers.

---

### maxUDPConnections

| Property | Value |
|---|---|
| Default | `20` |
| Type | `number` (integer) |
| Scope | Per host |

**What it controls:**
Maximum number of UDP probes in flight simultaneously for a single host.

**Why lower than maxTCPConnections:**
UDP sockets hold a file descriptor open until the full `socketTimeoutMs` elapses (no FIN/RST to
close them early). With 2 000 ms timeouts and 20 workers: `20 / 2s = 10 UDP ports/sec`. Raising
this aggressively risks FD exhaustion.

**Effect of increasing:**
Faster UDP scan. At high values, routers rate-limit ICMP port-unreachable replies (RFC 1812
§4.3.2.8), converting closed ports into false `OPEN|FILTERED` results.

**Effect of decreasing:**
More conservative FD usage, lower false-positive risk from ICMP rate-limiting. Very low values
(1–2) make UDP scanning extremely slow given the socket timeout.

---

### maxHostWorkers

| Property | Value |
|---|---|
| Default | `50` |
| Type | `number` (integer) |
| Scope | Global — `workerLimit` at the host-level `runPool` call |

**What it controls:**
How many hosts are scanned concurrently. Peak active sockets =
`maxHostWorkers × (maxTCPConnections + maxUDPConnections)` = `50 × 70` = 3 500.

**Effect of increasing:**
Dramatically faster for large CIDR ranges or long target lists. Total socket count rises
proportionally — can exhaust OS FD limits and saturate uplink bandwidth.

**Effect of decreasing:**
Fewer total sockets, lower aggregate probe rate. Setting to `1` serialises host scanning
completely, which is appropriate for a single sensitive target or strict rate-limit constraints.

**Practical ceiling:**
With the Linux default `ulimit -n 65536`: `65536 / 70 ≈ 936` host workers before FD exhaustion.
The default of `50` provides a large safety margin.

---

### socketTimeoutMs

| Property | Value |
|---|---|
| Default | `2000` (ms) |
| Type | `number` |
| Scope | Per socket — applied in both `tryTCPConnect` and `tryUDPConnect` |

**What it controls:**
How long the scanner waits for a response before declaring a port dead. Applied via
`socket.setTimeout()` for TCP/TLS and `setTimeout` for UDP.

**Effect of increasing:**
Catches open ports on high-latency or overloaded targets. Slows completion proportionally because
filtered ports each hold a worker slot for the full duration.

**Effect of decreasing:**
Faster scan. Risk of false-negatives on legitimate open ports that are slow to reply. For local
networks with sub-10 ms RTT, values as low as 200–500 ms are reliable. For internet targets with
100–300 ms RTT, values below 1 000 ms risk missing open ports.

**UDP-specific note:**
`socketTimeoutMs` is the sole basis for the `OPEN|FILTERED` verdict. Shorter values reduce
`OPEN|FILTERED` noise but increase the chance of misclassifying a slow responder as closed.

---

### jitterMinMs

| Property | Value |
|---|---|
| Default | `10` (ms) |
| Type | `number` |
| Scope | Lower bound of the per-probe delay drawn in `jitter()` |

**What it controls:**
The minimum pause inserted before each probe. Guarantees that even back-to-back workers have at
least this gap between transmissions.

**Effect of increasing:**
Wider guaranteed floor between probes. At high values (e.g. 500 ms) the scan is measurably stealthy
but very slow. Total scan time increases by roughly `numPorts × jitterMinMs` in the single-worker
worst case.

**Effect of decreasing toward 0:**
Probes can become back-to-back. Zero jitter with high concurrency approaches flood-scanner
behaviour and eliminates the IDS-evasion benefit of the lower bound.

---

### jitterMaxMs

| Property | Value |
|---|---|
| Default | `250` (ms) |
| Type | `number` |
| Scope | Upper bound of the per-probe delay drawn in `jitter()` |

**What it controls:**
The maximum possible pause between probes. Together with `jitterMinMs`, defines the full delay
distribution `U[jitterMinMs, jitterMaxMs]` with mean `(10 + 250) / 2 = 130 ms`.

**Effect of increasing:**
Wider spread makes the timing signature harder to fingerprint statistically. Diminishing IDS-evasion
returns above a few seconds; scan time grows proportionally.

**Effect of decreasing toward jitterMinMs:**
Narrows the distribution toward a fixed delay. A fixed delay is better than no delay but worse than
a wide random range, since the probe rate becomes predictable.

**Constraint:**
Must be `>= jitterMinMs`. Equal values collapse the range to a single fixed delay. Setting
`jitterMaxMs < jitterMinMs` is a misconfiguration that produces incorrect (but non-crashing)
delay values.

---

### decoyCount

| Property | Value |
|---|---|
| Default | `4` |
| Type | `number` (integer) |
| Scope | Controls the loop count in `sendDecoys()` |

**What it controls:**
How many spoofed SYN packets are sent to the target port before the real probe. A defender sees
`decoyCount + 1` SYNs at each probed port from `decoyCount` different private source IPs plus the
real scanner IP.

**Effect of increasing:**
More decoys flood the defender's alert queue with false source IPs. However, a synchronous burst of
many SYNs from different IPs in the same millisecond is itself suspicious to a sophisticated IDS —
a genuine distributed scan would not be this synchronous.

**Effect of decreasing toward 0:**
Fewer false sources. Setting to `0` disables decoys entirely (the loop body never executes), leaving
the real probe as the only SYN at each port.

**Practical range:**
3–8 is the effective sweet spot. Below 3 the noise-to-signal ratio is too low to meaningfully
confuse a defender. Above 8, the rapid synchronous burst starts to resemble a SYN flood, potentially
triggering different countermeasures.

---

### plaintextPorts

| Property | Value |
|---|---|
| Default | `[21, 22, 23, 25, 53, 3306, 5432, 6379, 27017]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | Checked at the top of `scanTCPPort()` |

**What it controls:**
TCP ports for which TLS is never attempted. Ports in this list go straight to a plain TCP probe,
skipping the TLS-first strategy.

| Port | Protocol | Reason for inclusion |
|---|---|---|
| 21 | FTP | FTPS uses explicit in-band upgrade (`AUTH TLS`), not TLS-on-connect |
| 22 | SSH | Custom binary framing; a TLS ClientHello produces a visible protocol error in sshd logs |
| 23 | Telnet | Plaintext by design |
| 25 | SMTP | Uses STARTTLS for opportunistic upgrade, not TLS-on-connect |
| 53 | DNS | Plaintext; DNS-over-TLS runs on port 853, not 53 |
| 3306 | MySQL | Plaintext by default; TLS is opt-in via capability flags |
| 5432 | PostgreSQL | Same STARTTLS-style upgrade as MySQL |
| 6379 | Redis | Plaintext by default; TLS is a compile-time option rarely enabled |
| 27017 | MongoDB | Plaintext by default |

**Effect of adding a port:**
That port skips the TLS handshake attempt — one connection instead of two, no TLS error in the
service log.

**Effect of removing a port:**
That port receives a TLS probe first. If the service is plaintext, TLS fails, the plain TCP
fallback runs, and the result is still correct — just slower and noisier.

---

## credtest section

Controls credential-testing behaviour in `src/credtest.js`.

---

### concurrency

| Property | Value |
|---|---|
| Default | `3` |
| Type | `number` (integer) |
| Scope | Per-port wordlist run — `workerLimit` passed to `runPool` inside `testHost` |

**What it controls:**
Maximum number of credential attempts in flight simultaneously against a single port. All ports on
a host are still tested sequentially; concurrency is only within one port's wordlist run.

**Effect of increasing:**
Faster credential testing per port. Higher values risk triggering account lockout policies, which
typically activate after 3–10 rapid failures. At `concurrency = 3` and a mean jitter of 1 250 ms,
the effective rate is `3 / 1.25s ≈ 2.4 attempts/sec` — well under most lockout thresholds.

**Effect of decreasing to 1:**
Fully sequential attempts. Safest against lockouts; slowest throughput. Appropriate when targeting
services with aggressive lockout policies (e.g. Active Directory with a 3-attempt threshold).

---

### jitterMinMs (credtest)

| Property | Value |
|---|---|
| Default | `500` (ms) |
| Type | `number` |
| Scope | Lower bound of the per-attempt delay in `jitter()` within credtest |

**What it controls:**
Minimum pause before each individual credential attempt.

**Why much higher than the scanner's jitterMinMs (10 ms):**
Login services interpret rapid repeated auth failures as a brute-force attack and may lock the
account, block the source IP, or add artificial delays. A 500 ms floor keeps the attempt rate
below the threshold most services use to trigger automated defences.

**Effect of increasing:**
More conservative attempt rate. Safer against lockouts; slower wordlist exhaustion.

**Effect of decreasing toward 0:**
Attempts can become back-to-back. At low values with `concurrency > 1` the rate will exceed
common lockout thresholds.

---

### jitterMaxMs (credtest)

| Property | Value |
|---|---|
| Default | `2000` (ms) |
| Type | `number` |
| Scope | Upper bound of the per-attempt delay in `jitter()` within credtest |

**What it controls:**
Maximum pause before each individual credential attempt. Combined with `jitterMinMs`, defines the
delay distribution `U[500ms, 2000ms]` with mean 1 250 ms.

**Effect of increasing:**
Wider spread makes attempt timing harder to fingerprint; slower overall. Diminishing evasion
returns above 5–10 seconds.

**Effect of decreasing toward jitterMinMs:**
Narrows to a near-fixed delay, making attempt timing more predictable while still respecting the
minimum floor.

---

### timeoutMs

| Property | Value |
|---|---|
| Default | `5000` (ms) |
| Type | `number` |
| Scope | Per-attempt connection timeout — applied in `trySSH`, `tryFTP`, and `tryHTTP` |

**What it controls:**
How long a single login attempt waits for a response from the service before giving up.

**Effect of increasing:**
Catches responses from slow services (overloaded SSH daemons, slow web apps). Extends total
credential-test duration proportionally on unresponsive hosts.

**Effect of decreasing:**
Faster abandonment of non-responsive ports. Risk of false-negatives on legitimate services that
are slow to respond to auth requests (e.g. a service adding artificial delay after failed attempts).

---

### sshPorts

| Property | Value |
|---|---|
| Default | `[22, 2222]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | `detectService()` — port-number classification check |

**What it controls:**
Port numbers that `detectService` unconditionally classifies as `"ssh"`, routing them to `trySSH`.

**Effect of adding a port:**
Any open port with that number will be tested with SSH credentials, regardless of its banner.
Useful for SSH servers running on non-standard ports (e.g. `2022`, `22222`).

**Effect of removing a port:**
That port number will not be SSH-tested unless its banner triggers the `portValue.startsWith("TLS")`
or HTTP fallback checks. Removing port 22 would cause standard SSH to be skipped.

---

### ftpPorts

| Property | Value |
|---|---|
| Default | `[21]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | `detectService()` |

**What it controls:**
Port numbers classified as `"ftp"`, routing them to `tryFTP`.

**Effect of adding a port:**
FTP credential testing is attempted on that port. Both plain and implicit TLS modes are tried
by `tryFTP` regardless of which port it receives.

**Effect of removing port 21:**
Standard FTP servers on port 21 will not be credential-tested unless a non-port-number fallback
would match (FTP has no TLS or HTTP banner pattern, so they would fall through to `null`).

---

### httpPorts

| Property | Value |
|---|---|
| Default | `[80, 8080, 8000, 8888]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | `detectService()` |

**What it controls:**
Port numbers classified as `"http"` (plain HTTP), routing them to `tryHTTP` with `useHTTPS = false`.

**Effect of adding a port:**
HTTP form-login testing runs against that port using plain HTTP scheme.

**Effect of removing a port:**
That port will not be HTTP-tested unless its scanner banner starts with `"TCP: HTTP"`, which
triggers the banner-based fallback in `detectService`.

---

### httpsPorts

| Property | Value |
|---|---|
| Default | `[443, 8443]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | `detectService()` |

**What it controls:**
Port numbers classified as `"https"`, routing them to `tryHTTP` with `useHTTPS = true`.

**Effect of adding a port:**
HTTPS form-login testing (with certificate validation disabled) runs against that port.

**Effect of removing a port:**
That port falls through to the banner-based fallback — if the scanner recorded `"TLS"` as its
`portValue`, `detectService` will still classify it as `"https"`. Port-number matching is just the
first check; the banner check acts as a safety net for non-standard HTTPS ports.

---

### httpEndpoints

| Property | Value |
|---|---|
| Default | `["/login", "/admin", "/wp-login.php", "/admin/login", "/signin", "/user/login"]` |
| Type | `string[]` |
| Scope | Outer loop in `tryHTTP` |

**What it controls:**
The URL paths `tryHTTP` posts credentials to. Each entry is appended to
`scheme://host:port` to form the full POST URL. All entries are tried for every credential pair
until a success response is detected.

**Effect of adding an entry:**
More paths are tested per credential pair. Useful for covering CMS-specific or
application-specific login routes (e.g. `/wp-admin`, `/auth/login`, `/api/v1/session`).

**Effect of removing an entry:**
That login path is skipped. Removing `/wp-login.php` means WordPress installations on default
paths will not receive a POST attempt.

---

### httpFields

| Property | Value |
|---|---|
| Default | `[{"user":"username","pass":"password"}, {"user":"email","pass":"password"}, {"user":"user","pass":"pass"}, {"user":"login","pass":"password"}]` |
| Type | `{ user: string, pass: string }[]` |
| Scope | Inner loop in `tryHTTP` |

**What it controls:**
The HTML form field names used when building the POST body. Each object represents one set of
field names. `tryHTTP` tries every `httpFields` entry for every `httpEndpoints` entry, so the
total attempts per credential pair = `httpEndpoints.length × httpFields.length`.

**Effect of adding an entry:**
An additional field-name set is tested at every endpoint. Useful when targeting frameworks that
use non-standard field names (e.g. `{ "user": "j_username", "pass": "j_password" }` for Java EE).

**Effect of removing an entry:**
That combination of field names is skipped. If the target application uses those field names
exclusively, its login form will not be tested successfully.
