# Configuration Reference — `config/settings.json`

All tunable parameters live in `config/settings.json`. `src/scanner.js`, `src/credtest.js`, and
`src/honeypot.js` each read this file at startup under their respective top-level keys (`scanner`,
`credtest`, and `honeypot`). No environment variables or CLI flags are needed — edit the JSON file
and restart the process.

```json
{
  "scanner":  { ... },
  "credtest": { ... },
  "honeypot": { ... }
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

### userAgents

| Property | Value |
|---|---|
| Default | Five real browser UA strings (Chrome Windows, Chrome macOS, Firefox Linux, Firefox Windows, Safari macOS) |
| Type | `string[]` |
| Scope | `randomUA()` — picked once per connection inside `tryTCPConnect` and `tryTLSConnect` |

**What it controls:**
The pool of HTTP `User-Agent` header values rotated across probes. One string is picked at random
for each banner-grab request.

**Effect of adding an entry:**
A wider pool makes the set of UA strings from a single scan run harder to correlate. New entries
should be real, current browser UA strings — invented strings may match known-scanner signatures.

**Effect of removing an entry:**
Smaller pool increases the probability that consecutive probes share the same UA, weakening the
rotation effect.

---

### httpPaths

| Property | Value |
|---|---|
| Default | `["/", "/index.html", "/robots.txt", "/favicon.ico", "/sitemap.xml"]` |
| Type | `string[]` |
| Scope | `randomPath()` — picked once per connection inside `tryTCPConnect` and `tryTLSConnect` |

**What it controls:**
The pool of URL paths used in the HTTP HEAD request sent during banner grabbing. One path is picked
at random for each probe.

**Effect of adding an entry:**
More path variety across probes. Paths should be common, innocuous URLs that a real browser would
request — unusual paths could themselves be a scanner signal.

**Effect of removing an entry:**
Smaller pool; more repeated paths across a scan run.

---

### referers

| Property | Value |
|---|---|
| Default | Google, Bing, DuckDuckGo, Reddit, t.co |
| Type | `string[]` |
| Scope | `randomReferer()` — picked once per connection inside `tryTCPConnect` and `tryTLSConnect` |

**What it controls:**
The pool of `Referer` header values rotated per probe. Simulates a user navigating to the target
from a real search engine or social link rather than typing the URL directly (which produces no
Referer) or arriving from a script (which sends no Referer or a synthetic one).

**Effect of adding an entry:**
Wider pool; more realistic variation in apparent traffic origin.

**Effect of removing an entry:**
Smaller pool; less variation.

---

### acceptLanguages

| Property | Value |
|---|---|
| Default | en-US, de-DE, fr-FR, nl-NL, es-ES, pl-PL (each with quality weighting) |
| Type | `string[]` |
| Scope | `randomLanguage()` — picked once per connection inside `tryTCPConnect` and `tryTLSConnect` |

**What it controls:**
The pool of `Accept-Language` header values rotated per probe. Simulates requests originating from
users in different locales — a realistic mix that a WAF or server log would associate with multiple
distinct browser clients.

**Effect of adding an entry:**
More locale variation. Adding non-Latin-script locales (e.g. `zh-CN`) broadens the apparent
geographic spread of requests.

**Effect of removing an entry:**
Smaller pool; less locale diversity.

---

### fakeCookies

| Property | Value |
|---|---|
| Default | Four strings containing plausible session, GA, GID, and consent cookie patterns |
| Type | `string[]` |
| Scope | `randomCookie()` — picked once per connection inside `tryTCPConnect` and `tryTLSConnect` |

**What it controls:**
The pool of `Cookie` header values rotated per probe. Sending a plausible cookie string makes the
request look like it comes from a browser that has previously visited the site, as opposed to a
fresh scanner connection which carries no cookies at all.

**Effect of adding an entry:**
More variety in the cookie fingerprint across probes. Custom entries can mimic the cookie patterns
of specific platforms (e.g. Cloudflare `__cf_bm`, WordPress `wordpress_logged_in`).

**Effect of removing an entry:**
Smaller pool; more repeated cookie values across a scan run.

---

### connectionReuseRequests

| Property | Value |
|---|---|
| Default | `1` |
| Type | `number` (integer) |
| Scope | `tryTCPConnect` / `tryTLSConnect` — number of HTTP HEAD requests sent on a single keep-alive connection before closing |

**What it controls:**
How many HTTP HEAD requests are pipelined on the same TCP/TLS connection per banner-grab probe.
At `1` each probe opens one connection, sends one request, and reads the response — no keep-alive
pipelining occurs. Values above `1` send that many requests on the same socket, with
`Connection: keep-alive` on all but the last.

**Effect of increasing:**
More requests per connection. Useful for extracting rotating headers from servers that vary their
response across requests, but increases per-host connection duration and banner-grab latency.

**Effect of decreasing to 1:**
One request per connection — minimum traffic, minimum latency, no risk of server-side
connection-reuse limits cutting the probe short.

---

### passiveBannerPorts

| Property | Value |
|---|---|
| Default | `[22, 2222, 21, 53, 110, 995, 143, 993, 3306, 5432, 6379, 27017, 23]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | `PASSIVE_PORTS` — first dispatch check at the top of `scanTCPPort()` |

**What it controls:**
TCP ports that are handed to `probeBannerOnly` instead of the TLS-first HTTP probe strategy.
These are services that send a banner immediately on connect; they must not receive an HTTP request
or a TLS `ClientHello` because that would produce a visible protocol-mismatch error in the service
log — a reliable scanner fingerprint.

| Port(s) | Protocol |
|---|---|
| 22, 2222 | SSH |
| 21 | FTP |
| 53 | DNS |
| 110, 995 | POP3, POP3S |
| 143, 993 | IMAP, IMAPS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 27017 | MongoDB |
| 23 | Telnet |

**Effect of adding a port:**
That port receives a passive banner read — no HTTP request, no TLS handshake. Use this for any
plaintext protocol that sends a greeting on connect.

**Effect of removing a port:**
That port falls through to the TLS-first HTTP strategy. This will produce protocol-mismatch errors
in the service log and waste a connection slot on a failed TLS handshake.

---

### smtpPorts

| Property | Value |
|---|---|
| Default | `[25, 587]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | `SMTP_PORTS` — second dispatch check in `scanTCPPort()`, after `passiveBannerPorts` |

**What it controls:**
TCP ports that are handed to `probeSMTP(host, port, false)`, which performs a proper EHLO exchange
over a plain TCP connection (waits for the `220` greeting, sends `EHLO mail.example.com`, collects
the capability reply). A bare TCP read or HTTP probe against SMTP would log a protocol error and
yield less information.

**Effect of adding a port:**
Non-standard SMTP deployments (e.g. port 2525) receive the plain-TCP EHLO probe instead of an
HTTP request.

**Effect of removing a port:**
That port falls through to the TLS-first HTTP strategy, which will produce errors in the SMTP log.

---

### smtpsTLSPorts

| Property | Value |
|---|---|
| Default | `[465]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | `SMTPS_PORTS` — third dispatch check in `scanTCPPort()`, after `smtpPorts` |

**What it controls:**
TCP ports that are handed to `probeSMTP(host, port, true)`, which performs the same EHLO exchange
as `smtpPorts` but wraps the connection in implicit TLS first (SMTPS). Port 465 is the standard
SMTPS port; the TLS handshake must complete before any SMTP data flows, unlike STARTTLS on ports
25/587 which upgrades an existing plain connection.

**Effect of adding a port:**
Non-standard SMTPS deployments receive the implicit-TLS EHLO probe.

**Effect of removing a port:**
That port falls through to the TLS-first HTTP strategy, which will produce SMTP protocol errors
in the service log.

---

### slowJitterMinMs

| Property | Value |
|---|---|
| Default | `5000` (ms) |
| Type | `number` |
| Scope | Lower bound of the per-probe delay when `--slow` is active |

**What it controls:**
The minimum inter-probe jitter when the scanner is invoked with `--slow`. Replaces `jitterMinMs`
for all TCP and UDP tasks in that mode.

**Effect of increasing:**
Longer guaranteed floor between probes — slower scan, lower IDS-detectable probe rate.

**Effect of decreasing toward `jitterMinMs`:**
Narrows the gap between normal and slow mode. Values below ~1 000 ms provide little meaningful
difference from the default mode.

---

### slowJitterMaxMs

| Property | Value |
|---|---|
| Default | `60000` (ms) |
| Type | `number` |
| Scope | Upper bound of the per-probe delay when `--slow` is active |

**What it controls:**
The maximum inter-probe jitter in slow mode. Combined with `slowJitterMinMs`, defines the delay
distribution `U[5s, 60s]` with a mean of 32.5 seconds per probe.

**Effect of increasing:**
Wider spread makes the timing signature harder to fingerprint statistically; significantly longer
total scan time.

**Effect of decreasing toward `slowJitterMinMs`:**
Narrows the distribution to near-fixed delays. Must be `>= slowJitterMinMs`.

---

### slowMaxHostWorkers

| Property | Value |
|---|---|
| Default | `5` |
| Type | `number` (integer) |
| Scope | Host-level `runPool` concurrency when `--slow` is active |

**What it controls:**
How many hosts are scanned concurrently in slow mode. Replaces `maxHostWorkers` when `--slow` is
active. Peak sockets in slow mode = `slowMaxHostWorkers × (slowMaxTCPConnections + maxUDPConnections)`
= `5 × (10 + 20)` = 150.

**Effect of increasing:**
More concurrent hosts — faster scan but higher aggregate probe rate, reducing the stealth benefit
of slow mode.

**Effect of decreasing to 1:**
Fully sequential host scanning — maximum stealth, minimum network footprint.

---

### slowMaxTCPConnections

| Property | Value |
|---|---|
| Default | `10` |
| Type | `number` (integer) |
| Scope | Per-host TCP `runPool` concurrency when `--slow` is active |

**What it controls:**
Maximum TCP probes in flight per host in slow mode. Replaces `maxTCPConnections` when `--slow` is
active.

**Interaction with slow jitter:**
Effective TCP probe rate in slow mode ≈ `slowMaxTCPConnections / avgSlowJitter` =
`10 / 32.5s ≈ 0.3 probes/sec` — well below any volume-based IDS threshold.

**Effect of increasing:**
Faster per-host TCP scan in slow mode at the cost of a higher instantaneous connection count.

**Effect of decreasing to 1:**
Fully sequential TCP probing per host — one port at a time with full jitter between each.

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
That port number will not be SSH-tested unless its port object's `proto` or banner triggers the TLS
or HTTP fallback checks in `detectService`. Removing port 22 would cause standard SSH to be skipped.

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
That port will not be HTTP-tested unless its port object has `proto: "TCP"` and a banner starting
with `"HTTP"`, which triggers the banner-based fallback in `detectService`.

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
That port falls through to the banner-based fallback — if the scanner recorded `proto: "TLS"` in
the port object, `detectService` will still classify it as `"https"`. Port-number matching is just
the first check; the proto field acts as a safety net for non-standard HTTPS ports.

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

---

---

## honeypot section

Controls honeypot-detection behaviour in `src/honeypot.js`.

---

### suspiciousPortThreshold

| Property | Value |
|---|---|
| Default | `6` |
| Type | `number` (integer) |
| Scope | `checkHost()` — compared against `openPorts.length` |

**What it controls:**
Minimum number of open ports required to trigger the "too many open ports" heuristic. Real servers
rarely expose six or more distinct services simultaneously; honeypots are configured to answer on
many ports to maximise attacker engagement.

**Effect of increasing:**
Fewer hosts flagged under this heuristic. Reduce false positives on servers that legitimately run
many services (e.g. a combined web + database + mail server).

**Effect of decreasing:**
More hosts flagged. Setting to 3 or 4 will produce many false positives on ordinary multi-service
hosts.

---

### telnetPort

| Property | Value |
|---|---|
| Default | `23` |
| Type | `number` |
| Scope | `checkHost()` — checked with `openPorts.includes()` |

**What it controls:**
The port number that triggers the "Telnet open" heuristic. Telnet is effectively absent from
legitimate modern infrastructure and is a near-certain honeypot indicator when present.

**Effect of changing:**
Only relevant if a deployment uses a non-standard Telnet port. No reason to change this in normal
use.

---

### tpotPortCombo

| Property | Value |
|---|---|
| Default | `[21, 22, 23, 25, 80, 443, 445]` |
| Type | `number[]` (loaded as a `Set`) |
| Scope | `checkHost()` — intersection with open ports |

**What it controls:**
The set of ports whose co-occurrence indicates a T-Pot honeypot installation. T-Pot runs multiple
honeypot daemons (Cowrie, Dionaea, Conpot, etc.) simultaneously, which results in an unusually wide
set of open ports from a single host.

**Effect of adding a port:**
A larger reference set means the intersection with `openPorts` can grow, but it can also reduce
false positives if you remove a port that legitimate hosts commonly open (e.g. 80 or 443 alone is
not suspicious).

**Effect of removing a port:**
Smaller reference set. Fewer potential matches; the threshold must be met with fewer ports.

---

### tpotMatchMin

| Property | Value |
|---|---|
| Default | `4` |
| Type | `number` (integer) |
| Scope | `checkHost()` — minimum intersection size to trigger the T-Pot heuristic |

**What it controls:**
How many ports from `tpotPortCombo` must be open simultaneously before the T-Pot flag is raised.

**Effect of increasing:**
Stricter match — fewer false positives on hosts running a subset of these ports for legitimate
reasons (web + SSH + SMTP is normal; web + SSH + SMTP + FTP + Telnet + SMB is not).

**Effect of decreasing toward 1:**
Any single port from the combo set would trigger a flag — produces many false positives.

---

### cowrieSSHBanners

| Property | Value |
|---|---|
| Default | Six known Cowrie version strings (OpenSSH 5.3, 5.9p1, 6.0p1, 6.6.1p1, 6.7p1, 7.2p2 with Debian/Ubuntu suffixes) |
| Type | `string[]` |
| Scope | `checkHost()` — substring match against each SSH port's banner value |

**What it controls:**
The list of SSH banner strings that are known Cowrie default configurations. A match is a high-confidence
honeypot indicator because these specific version + OS combinations are hard-coded defaults in
Cowrie's configuration file and have not appeared in real-world OpenSSH packages for many years.

**Effect of adding an entry:**
New Cowrie default banners (from updated Cowrie versions or community-reported configurations) are
detected. Check the Cowrie changelog and honeypot research feeds for new defaults.

**Effect of removing an entry:**
That specific banner string will fall through to the bare-suffix heuristic instead (which may still
flag it, just with a lower-confidence message).

---

### sshDistroKeywords

| Property | Value |
|---|---|
| Default | `["Ubuntu", "Debian", "RHEL", "CentOS", "Alpine", "FreeBSD"]` |
| Type | `string[]` |
| Scope | `SSH_DISTRO_SUFFIX` regex compiled at module load — tested against SSH banners not matched by `cowrieSSHBanners` |

**What it controls:**
The OS name strings that legitimate distro-packaged OpenSSH always appends to its version banner
(e.g. `SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6`). A banner that matches `SSH-2.0-OpenSSH_x.y`
but contains none of these keywords is flagged as a possible honeypot — Cowrie and similar tools
often emit bare version strings with no OS suffix.

**Effect of adding an entry:**
A new OS keyword is accepted as a legitimate suffix. Add entries for distributions in your target
environment if they use suffixes not in the default list (e.g. `Raspbian`, `NixOS`).

**Effect of removing an entry:**
SSH banners from that OS distribution will be flagged as suspicious. Only remove entries for OS
strings known to appear in honeypot configurations.

---

### ftpHoneypotBanners

| Property | Value |
|---|---|
| Default | Five strings: DiskStation variants, `"220 FTP Server Ready"`, `"220 Cowrie FTP"`, `"220 (vsFTPd 2.0.8)"` |
| Type | `string[]` |
| Scope | `checkHost()` — substring match against each port value that starts with `"TCP: 220"` |

**What it controls:**
FTP banner strings that are known honeypot defaults. A substring match (not exact match) is used
so partial captures from the scanner still trigger the check. In `checkHost`, the banner is
extracted from either the object format (`value.banner`) or the legacy string format before the
match is applied — the check is not tied to the raw `"TCP: 220"` prefix.

**Effect of adding an entry:**
New honeypot FTP banners are detected. Sources: Cowrie FTP component changelogs, T-Pot release
notes, and community honeypot research.

**Effect of removing an entry:**
That banner string will no longer be flagged. An FTP port with that banner may still be caught by
the T-Pot port combination or suspicious port count heuristics.

---

### cowrieKexTells

| Property | Value |
|---|---|
| Default | `["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"]` |
| Type | `string[]` |
| Scope | `checkSSHFingerprint()` — checked against the `kexAlgos` list from a live `MSG_KEXINIT` probe |

**What it controls:**
KEX algorithm names that Cowrie (via twisted.conch) advertises but modern OpenSSH no longer
includes. A match produces a `"Cowrie KEX algorithm"` reason string.

**Effect of adding an entry:**
Additional legacy KEX algorithms are treated as Cowrie tells. Verify against the current
twisted.conch source before adding — some algorithms may also appear in embedded or
resource-constrained SSH implementations that are not honeypots.

**Effect of removing an entry:**
That KEX algorithm is no longer considered suspicious during live probing.

---

### cowrieMacTells

| Property | Value |
|---|---|
| Default | `["hmac-md5", "hmac-md5-96"]` |
| Type | `string[]` |
| Scope | `checkSSHFingerprint()` — checked against the `macAlgos` (client→server) list |

**What it controls:**
MAC algorithm names advertised by Cowrie that OpenSSH dropped due to MD5 being cryptographically
broken. Both `hmac-md5` and `hmac-md5-96` were removed from OpenSSH's default list in 6.7.

**Effect of adding an entry:**
More MAC algorithms are treated as Cowrie tells.

**Effect of removing an entry:**
That MAC algorithm is no longer flagged during live KEX probing.

---

### cowrieEncTells

| Property | Value |
|---|---|
| Default | `["3des-cbc", "blowfish-cbc", "arcfour256", "arcfour128"]` |
| Type | `string[]` |
| Scope | `checkSSHFingerprint()` — checked against the `encAlgos` (client→server) list |

**What it controls:**
Cipher names advertised by Cowrie that modern OpenSSH removed. `3des-cbc` was dropped in
OpenSSH 7.4; `blowfish-cbc` and the `arcfour` variants even earlier. Their presence in a server's
advertisement is a strong Cowrie indicator.

**Effect of adding an entry:**
More ciphers are treated as Cowrie tells.

**Effect of removing an entry:**
That cipher is no longer flagged during live KEX probing.

---

### cowrieHostKeyTells

| Property | Value |
|---|---|
| Default | `["ssh-dss"]` |
| Type | `string[]` |
| Scope | `checkSSHFingerprint()` — checked against the `hostKeyAlgos` list |

**What it controls:**
Host key algorithm names advertised by Cowrie that modern OpenSSH disabled by default. `ssh-dss`
(DSA) was disabled in OpenSSH 7.0 due to weak key sizes. A server advertising it is almost
certainly running Cowrie or very old OpenSSH.

**Effect of adding an entry:**
Additional legacy host key types are treated as Cowrie tells.

**Effect of removing an entry:**
That host key type is no longer flagged during live KEX probing.

---

*Documentation written with assistance from [Claude](https://claude.ai) — used for documentation, package understanding, and packet crafting reference.*
