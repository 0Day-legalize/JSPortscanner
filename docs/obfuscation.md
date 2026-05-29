# Stealth and Obfuscation Techniques

This document describes every technique the scanner uses to avoid detection by IDS/IPS systems,
firewalls, and network monitoring tools. For each technique: what it does, why it matters, and
what a defender sees with and without it.

---

## 1. Port shuffle

**Implementation:** `shufflePorts()` — Fisher-Yates shuffle applied once per host before any probes
are sent.

**What it does:**
Instead of probing port 1, 2, 3, 4... in order, the scanner builds the full list of ports in the
range and randomises their sequence. Every host gets a different random ordering.

**Why it helps:**
The single most reliable IDS rule for detecting port scanners is a sequence of SYN packets to
incrementing destination ports from the same source IP within a short time window. Nmap's default
scan order and virtually all naive scanner implementations trigger this rule. A shuffled order
produces no sequential pattern and forces an IDS to rely on volume (N probes in T seconds from the
same source) rather than ordering, which is a much noisier signal.

| Scenario | What the IDS sees |
|---|---|
| Without shuffle | SYNs to port 1, 2, 3, 4, 5... — trivially matches "port sweep" signature |
| With shuffle | SYNs to port 412, 7801, 23, 999, 1337... — no ordering pattern to match |

**Gotchas:**
- Both TCP and UDP scan the same shuffled list in the same order. This creates a mild correlation
  (TCP and UDP probes always arrive at the same port at roughly the same time). An IDS correlating
  across protocols could notice this, though it is rarely implemented.

---

## 2. Jitter (inter-probe delay)

**Implementation:** `jitter()` — `setTimeout` to a uniformly random value in `[JITTER_MIN_MS, JITTER_MAX_MS]`, awaited before every individual port probe.

**What it does:**
Inserts a random pause between 10 ms and 250 ms before each probe attempt. The delay is sampled
independently for each probe; there is no correlation between successive delays.

**Why it helps:**
Even with shuffled ports, a scanner sending thousands of SYNs at a fixed rate produces a flat
probe-rate distribution that is detectable. IDS systems (and human analysts) look for a sustained,
constant probing rate from one source. By adding random inter-arrival time, the scanner mimics the
bursty, irregular pattern of legitimate traffic — human browsing, application polling, and
background service discovery all have irregular timing profiles.

| Scenario | What the IDS sees |
|---|---|
| Without jitter | 50 SYNs per ~2100 ms = ~24 probes/sec, flat rate — matches "scanner" profile |
| With jitter | Highly variable inter-arrival times — indistinguishable from bursty application traffic |

**Gotchas:**
- Jitter is applied per-task, not globally. With `MAX_TCP_CONNECTIONS = 50` concurrent workers,
  up to 50 probes are in flight at once. The effective probe rate is approximately
  `MAX_TCP_CONNECTIONS / avg_delay`, not `1 / avg_delay`. Reducing concurrency has more impact on
  rate than widening the jitter range.
- The `JITTER_MIN_MS = 10` floor ensures probes are never back-to-back even under extreme
  scheduling conditions.

---

## 3. Random source port

**Implementation:** `randomSourcePort()` — called inside `tryTCPConnect` to set `localPort`, and
inside `buildSynPacket` for the TCP header source port field in decoy packets.

**What it does:**
Every outgoing TCP connection binds to a different randomly chosen local port number in the range
1024–65535 (`Math.floor(Math.random() * (65535 - 1024 + 1)) + 1024`).

**Why it helps:**
The OS assigns ephemeral ports sequentially by default (Linux starts around 32768 and increments).
A scanner that opens many connections in quick succession would produce a run of sequential source
ports: 32768, 32769, 32770... — another reliable scanner signature. Binding each socket to a
random port breaks this sequence. To an IDS the source ports appear to be from an ordinary mix of
active application sockets rather than a systematic scanner.

| Scenario | What the IDS sees |
|---|---|
| Without random source port | Source ports 32768, 32769, 32770... — matches OS auto-assign scanner pattern |
| With random source port | Source ports 54102, 18442, 61007... — looks like normal application traffic |

**Gotchas:**
- In rare cases the chosen port may already be in use. The OS will return `EADDRINUSE` and the
  connection attempt will fail. With 64,512 available ports and typical short-lived socket hold
  times, collision probability is negligible but non-zero. Affected probes will register as closed,
  producing a potential false-negative.
- Decoy packets and the real probe for the same destination port may share the same randomly-chosen
  source port by coincidence. This is harmless — the decoy source IPs are already different.

---

## 4. Decoy IPs

**Implementation:** `randomPrivateIP()`, `buildSynPacket()`, `getDecoySocket()`, `sendDecoys()` —
together these fire `DECOY_COUNT` spoofed TCP SYN packets per real probe.

**What it does:**
Before each real TCP probe, the scanner sends `DECOY_COUNT` (4) raw IP/TCP packets at the target
port. Each packet has:
- A source IP randomly drawn from RFC 1918 private address space (`10.x.x.x`, `172.16-31.x.x`,
  `192.168.x.x`)
- A randomised IP ID, TTL (64–127), and TCP sequence number
- A randomised TCP window size
- A valid, correctly computed IP and TCP checksum (required for the packet to be accepted by the
  kernel and network stack)
- The SYN flag set (identical to a connection initiation)

The raw socket is created with `IP_HDRINCL`, which means the kernel passes the packet through
exactly as built — no source IP rewriting, no kernel-generated headers. The target's network stack
receives what looks like a SYN from a private internal IP address.

**Why it helps:**
From the target's perspective (and any IDS watching inbound traffic), five SYN packets arrive at
the same port in close succession from five different source IPs. The defender cannot easily
identify which one is the real probe. Alert queues fill with entries for internal hosts that do not
exist or did not actually send the packet. Correlation rules that trigger on "N SYNs from one
source" must set N high enough to avoid all these false sources, making them much less sensitive.

Private IPs are chosen specifically because:
1. They make the decoys look like internal traffic, which is often less scrutinised than external.
2. A private IP can never actually receive a SYN-ACK reply, so it cannot accidentally complete a
   TCP handshake with the target.
3. Defenders chasing the alert would be looking for an internal host that does not exist.

**How the raw packet is built:**

```
Byte offset   Field                  Value
─────────────────────────────────────────────────────
0             IP version + IHL       0x45  (IPv4, header = 5×4 = 20 bytes)
1             DSCP/ECN               0x00
2–3           Total length           40    (IP header + TCP header, no payload)
4–5           IP identification      random uint16
6–7           Flags + fragment       0x4000 (DF bit, no fragmentation)
8             TTL                    random in [64, 127]
9             Protocol               6     (TCP)
10–11         IP header checksum     computed over bytes 0–19
12–15         Source IP              random private IP (spoofed)
16–19         Destination IP         real target IP

20–21         TCP source port        random in [1024, 65535]
22–23         TCP dest port          target port being scanned
24–27         Sequence number        random uint32
28–31         Acknowledgement        0
32            Data offset            0x50  (5 × 4 = 20 bytes, no options)
33            Flags                  0x02  (SYN)
34–35         Window size            random | 0x1000 (minimum 4096)
36–37         TCP checksum           computed over pseudo-header + TCP segment
38–39         Urgent pointer         0
```

**What the target sees:**

```
Time    Src IP           Dst IP         Src Port  Dst Port  Flags
────────────────────────────────────────────────────────────────────
T+0ms   192.168.14.201   10.10.10.5     54102     80        SYN   ← decoy
T+0ms   10.7.231.99      10.10.10.5     18442     80        SYN   ← decoy
T+0ms   172.22.44.7      10.10.10.5     61007     80        SYN   ← decoy
T+0ms   192.168.200.3    10.10.10.5     37815     80        SYN   ← decoy
T+0ms   <real scanner>   10.10.10.5     29043     80        SYN   ← real probe
```

The real scanner's IP is buried in the noise of four apparent internal connections.

**Gotchas:**
- Requires the `raw-socket` npm package and root privileges. If either is absent, `sendDecoys`
  silently skips without affecting the TCP scan.
- RFC 1918 private IPs are non-routable over the internet. In a LAN environment the target could
  theoretically receive a SYN-ACK from one of these if the matching private IP actually exists on
  the network. This is unlikely given the random generation, but a defender doing deep packet
  inspection and ARP correlation could distinguish real from spoofed.
- `IP_HDRINCL` behaviour varies slightly between Linux kernel versions. On some setups the kernel
  may still override the source IP or checksum — test in your environment.

---

## 5. TLS plaintext skip-list (`PLAINTEXT_PORTS`)

**Implementation:** `PLAINTEXT_PORTS` constant (a `Set`) checked at the top of `scanTCPPort`.

**What it does:**
Ports `21, 22, 23, 25, 53, 3306, 5432, 6379, 27017` are probed with plain TCP immediately, without
attempting a TLS handshake first.

**Why it helps:**
This is primarily a stealth/precision concern rather than an IDS-evasion technique. Attempting a
TLS `ClientHello` against SSH (port 22) or MySQL (port 3306) produces a visible failed handshake
in server logs and IDS alerts. The server logs "unknown SSL error" or "protocol mismatch", which is
a distinct fingerprint of a TLS-naive scanner. By skipping TLS on known plaintext ports:

1. No spurious TLS error events appear in service logs.
2. No failed TLS handshake packets hit the wire before the real probe.
3. Scan time is cut roughly in half for these ports (one connection instead of two).

| Scenario | What service logs show |
|---|---|
| Without skip-list | TLS handshake failure on port 22 → "Bad protocol version" in sshd log |
| With skip-list | Clean TCP connect followed by valid SSH banner exchange |

**Gotchas:**
- The list is static. Services running on non-standard ports (e.g. MySQL on port 13306) will still
  receive a TLS probe first. This is unavoidable without per-service probing logic.
- The list does not include every plaintext protocol — just the most common ones. Adding a port to
  this set is the correct way to suppress unwanted TLS attempts.

---

## 6. User-Agent string

**Implementation:** Hardcoded in `tryTCPConnect` as the `User-Agent` header value in the HTTP HEAD
probe: `"Team Dangerous"`.

**What it does:**
Sends a custom, non-standard User-Agent string in the HTTP HEAD request that is issued after a
successful connection.

**Why it helps:**
Default scanner User-Agent strings (`Nmap`, `masscan`, `python-requests/2.x.x`, `Go-http-client`)
are included in most web application firewall (WAF) and IDS rule sets. Any scanner that announces
itself with a well-known tool string will trigger an automatic block or alert. A custom string that
does not match any known scanner signature passes through these rules silently.

| Scenario | What a WAF / IDS sees |
|---|---|
| Without custom UA | `User-Agent: python-urllib3/1.26` → matches "known scanner" rule → blocked |
| With custom UA | `User-Agent: Team Dangerous` → no rule match → request passes |

**Gotchas:**
- HTTP 1.0 (`HTTP/1.0`) is used deliberately. HTTP/1.1 requires a `Host` header and the server
  may expect persistent connections, complicating the probe. HTTP/1.0 with `Connection: close`
  produces the cleanest single-response interaction.
- The User-Agent only matters when the target speaks HTTP/HTTPS. For all other services (SSH, FTP,
  SMTP, databases) the HTTP request is sent but ignored or met with an error — the banner data
  returned is whatever the service sent spontaneously on connection.
- A sufficiently sophisticated IDS that fingerprints scanner behaviour (rather than string matching)
  will still detect the probe pattern regardless of User-Agent.
