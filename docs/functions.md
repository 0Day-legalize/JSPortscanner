# Function Reference

Functions are grouped by source file. Scanner functions are listed first, followed by credtest functions.
Within each group they appear in file order.

---

## jitter()

**Purpose:**
Pauses execution for a random number of milliseconds in the range `[JITTER_MIN_MS, JITTER_MAX_MS]`.
It exists because a scanner that probes at perfectly uniform intervals has a detectable timing
signature. Inserting a random pause between each probe makes automated detection significantly harder.

**Parameters:** none

**Returns:** `{Promise<void>}`

**Notes:**
- The delay is drawn from a uniform distribution, not Gaussian. This is intentional — a Gaussian
  distribution clusters around the mean and can still be statistically fingerprinted with enough
  samples.
- The range is controlled by `JITTER_MIN_MS` (10 ms) and `JITTER_MAX_MS` (250 ms). Widening the
  range increases stealth at the cost of scan speed.

**Example:**
```js
await jitter(); // waits somewhere between 10 ms and 250 ms
await scanTCPPort(host, port);
```

---

## randomDecoyIP(dstIP)

**Purpose:**
Returns a source IP to use as the spoofed address in a decoy SYN packet. Prefers IPs drawn from
the live scan target pool (the same address range as the real targets) so decoy traffic blends with
the expected source distribution. Falls back to a random host in the destination's /24 when the
pool is empty or contains only the destination itself.

**Parameters:**
- `dstIP` `{string}` — destination IP being probed; excluded from the pool to prevent a decoy
  from using the same address as the real target

**Returns:** `{string}` — dotted-decimal IP string, e.g. `"37.27.7.131"`

**Notes:**
- When `decoyPool` has more than one entry, a random element is selected with a do-while retry
  loop that discards any element equal to `dstIP`. This is O(1) space and terminates in at most
  two iterations in practice.
- The fallback /24 selection similarly avoids the exact host octet of `dstIP` via a do-while loop.
- `decoyPool` is populated from the full target list at startup, so decoy IPs are always
  plausible neighbors of the real scan targets.

**Example:**
```js
const fakeSource = randomDecoyIP("37.27.7.154");
// => "37.27.7.131"  (from target pool)
// => "37.27.7.88"   (fallback /24, if pool has only one entry)
```

---

## oneComplementChecksum(buf)

**Purpose:**
Computes the 16-bit one's complement checksum mandated by RFC 791 (IP) and RFC 793 (TCP).
Required when building raw packets manually — the kernel normally calculates this automatically, but
since `IP_HDRINCL` is set the scanner owns the full header and must supply correct checksums itself.

**Parameters:**
- `buf` `{Buffer}` — raw byte sequence to checksum (either the 20-byte IP header or the
  12-byte TCP pseudo-header concatenated with the 20-byte TCP header)

**Returns:** `{number}` — 16-bit checksum value (fits in a `uint16`)

**Notes:**
- If the buffer has an odd length, the final byte is left-shifted into the high byte of a 16-bit
  word and the low byte is treated as zero — this is mandated by the RFC.
- The carry-fold `while (sum >> 16)` loop is theoretically O(1) because at most two iterations are
  needed after a single pass over the data, but the loop form is used for correctness regardless of
  intermediate accumulator size.
- Returns the bitwise NOT of the folded sum, masked to 16 bits.

**Example:**
```js
const header = Buffer.alloc(20);
// ... fill IP header fields ...
const checksum = oneComplementChecksum(header);
header.writeUInt16BE(checksum, 10); // write back into header checksum field
```

---

## buildSynPacket(srcIP, dstIP, srcPort, dstPort)

**Purpose:**
Constructs a complete 60-byte raw IP/TCP packet with the SYN flag set and a spoofed source address.
This packet is handed directly to the raw socket and sent without kernel TCP stack involvement,
which is what allows the source IP to be anything we choose.

**Parameters:**
- `srcIP`   `{string}` — spoofed source IP in dotted-decimal, e.g. `"37.27.7.131"` (typically from `randomDecoyIP()`)
- `dstIP`   `{string}` — real destination IP in dotted-decimal
- `srcPort` `{number}` — source port number written into the TCP header (1024–65535)
- `dstPort` `{number}` — destination port number for the SYN

**Returns:** `{Buffer}` — 60-byte packet ready to pass to `socket.send()`

**Notes:**
- **Packet layout:** 20-byte IP header + 20-byte TCP header + 20-byte TCP options = 60 bytes. The
  data offset field is set to `0xA0` (10 × 4 = 40 bytes) to account for the options block.
- **TCP options (bytes 40–59):** MSS(1460), SACK permitted, Timestamps (random TSval, TSecr=0),
  NOP (alignment pad), Window Scale(7). This matches the default Linux kernel SYN fingerprint,
  making the decoy indistinguishable from a genuine connection at the TCP options level.
- **IP ID** is randomised on every call. A fixed or incrementing ID is an easy scanner fingerprint.
- **TTL** is randomised in the range 64–127, covering both Linux (64) and Windows (128) defaults, so
  packets do not share a single identifiable hop count.
- **TCP sequence number** is randomised. A predictable ISN is a fingerprint even in decoy traffic.
- **Window size** is randomised with a minimum of `0x1000` (4096) bytes to avoid zero-window packets
  being filtered by network gear.
- The IP checksum is computed over bytes 0–19 only. The TCP checksum requires a 12-byte
  pseudo-header (source IP, dest IP, zero byte, protocol 6, TCP length = 40) prepended to the
  TCP segment before checksumming — this is the RFC 793 pseudo-header construction.

**Example:**
```js
const pkt = buildSynPacket("10.0.0.1", "203.0.113.50", 54321, 80);
socket.send(pkt, 0, pkt.length, "203.0.113.50", () => {});
```

---

## getDecoySocket()

**Purpose:**
Returns a single shared raw socket, creating it on the first call. Reusing one socket for all
decoy sends avoids the per-packet syscall overhead of `createSocket` / `close` and prevents kernel
file-descriptor exhaustion under high-volume scans.

**Parameters:** none

**Returns:** `{object|null}` — `raw-socket` socket instance, or `null` if the `raw-socket` package
is unavailable or the process does not have the required privileges.

**Notes:**
- `IP_HDRINCL` must be set on the socket so the kernel passes our hand-crafted IP header through
  unmodified instead of prepending its own.
- The socket is stored in the module-level `rawSocket` variable. It is never closed — the process
  lifetime is the socket lifetime.
- Failure is intentionally silent. The scanner degrades gracefully to operation without decoys.

---

## sendDecoys(dstIP, dstPort)

**Purpose:**
Sends `DECOY_COUNT` spoofed TCP SYN packets to the target immediately before the real probe.
Each decoy uses a source IP from `randomDecoyIP`, drawn from the scan target pool or the
destination's /24, making it look like multiple neighbor hosts are connecting at the same time.

**Parameters:**
- `dstIP`   `{string}` — resolved destination IP in dotted-decimal
- `dstPort` `{number}` — port number being probed

**Returns:** `{void}`

**Notes:**
- Decoys are fired-and-forgotten; the `send` callback is a no-op. We do not wait for
  acknowledgement because the spoofed source addresses cannot receive a reply.
- If `getDecoySocket()` returns null the function returns immediately without error, so TCP scanning
  continues unaffected even without root privileges.
- Only called for TCP probes. UDP decoys are not implemented because UDP does not do handshakes,
  making SYN-based spoofing irrelevant.

**Example:**
```js
// called inside the TCP task, just before scanTCPPort
if (resolvedIP) sendDecoys(resolvedIP, port);
```

---

## randomSourcePort()

**Purpose:**
Returns a random local port number in the ephemeral range (1024–65535) to bind the outgoing socket
to. When every connection leaves from a different local port, the sequential local-port pattern that
many IDS systems use as a scanner fingerprint is eliminated.

**Parameters:** none

**Returns:** `{number}` — integer in range `[1024, 65535]`

**Notes:**
- Port 0 through 1023 are reserved (well-known ports). Binding to them requires root and would be
  confusing to a service on the target, so the range starts at 1024.
- The OS may still refuse a specific port if it is already in use. `net.createConnection` and
  `tls.connect` will throw in that case, but the probability of collision is negligible given the
  64,512-port range and typical ephemeral hold durations.

**Example:**
```js
const socket = net.createConnection({ host, port, localPort: randomSourcePort() });
```

---

## shufflePorts(firstPort, lastPort)

**Purpose:**
Builds a contiguous range of port numbers and randomises their order using a Fisher-Yates shuffle.
A scanner that probes ports 1, 2, 3, 4... is trivially detected by any IDS that watches for
sequential SYN packets. Shuffling removes that signal entirely.

**Parameters:**
- `firstPort` `{number}` — lowest port number to include, e.g. `1`
- `lastPort`  `{number}` — highest port number to include, e.g. `1024`

**Returns:** `{number[]}` — randomly ordered array containing every integer from `firstPort` to
`lastPort` inclusive

**Notes:**
- Fisher-Yates guarantees a uniformly random permutation in O(n) time with O(n) space.
- The output array is `lastPort - firstPort + 1` elements long. For the full 65535-port range that
  is a ~256 KB array, which is acceptable.
- Both TCP and UDP task arrays are built from the same shuffled `portList` inside `scanHost`, so TCP
  and UDP scan the same ports but in the same shuffled order (not independently shuffled). This is a
  minor correlation that has no practical stealth impact.

**Example:**
```js
shufflePorts(1, 5);
// => [3, 1, 5, 2, 4]  (example — actual order is random each call)
```

---

## probeBannerOnly(host, port)

**Purpose:**
Opens a plain TCP connection and waits for the service to send an unsolicited banner, then closes
the socket. Used for protocols that send a greeting immediately on connect (SSH, FTP, POP3, IMAP,
MySQL, Redis, Telnet) where sending an HTTP request would produce a visible protocol-mismatch error
in the service log and be a scanner fingerprint.

**Parameters:**
- `host` `{string}` — IP address or hostname to connect to
- `port` `{number}` — destination port number

**Returns:** `{Promise<string|null>}`
- Trimmed banner string if the service sent data
- `null` on connection failure, timeout, or an empty response

**Notes:**
- The socket is destroyed immediately on the first `data` event. Waiting for the full `close` event
  to resolve the promise means the returned string is always the complete first chunk received.
- Ports dispatched here are defined in `PASSIVE_PORTS` (`passiveBannerPorts` in `settings.json`).
  This set currently includes: 22, 2222, 21, 53, 110, 995, 143, 993, 3306, 5432, 6379, 27017, 23.

**Example:**
```js
const banner = await probeBannerOnly("10.0.0.1", 22);
// => "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6"
```

---

## probeSMTP(host, port)

**Purpose:**
Opens a plain TCP connection to an SMTP port, waits for the `220` greeting, sends `EHLO`, and
collects the capability response. A raw TCP or HTTP probe against SMTP would log a protocol error;
the EHLO exchange is the minimum correct interaction that elicits service information.

**Parameters:**
- `host` `{string}` — IP address or hostname to connect to
- `port` `{number}` — SMTP port number (typically 25 or 587)

**Returns:** `{Promise<string|null>}`
- Full accumulated response (greeting + EHLO reply) if the exchange completed
- `null` on connection failure, timeout, or missing greeting

**Notes:**
- Ports dispatched here are defined in `SMTP_PORTS` (`smtpPorts` in `settings.json`): 25 and 587.
- The `greeted` flag prevents sending `EHLO` more than once if the server sends the `220` greeting
  in multiple TCP segments.
- The socket is destroyed as soon as a `250 ` or `250-` line is received — the first of those
  reliably indicates the EHLO reply is complete.

**Example:**
```js
const data = await probeSMTP("10.0.0.1", 25);
// => "220 mail.example.com ESMTP\r\n250-mail.example.com\r\n250 STARTTLS\r\n"
```

---

## tryTCPConnect(host, port, hostname)

**Purpose:**
Opens a plain TCP connection to the target and attempts to elicit a banner by sending an HTTP/1.1
HEAD request. Used as the fallback probe when `tryTLSConnect` returns null. Returns whatever the
service sends back, or null if the connection could not be established.

**Parameters:**
- `host`     `{string}` — IP address or hostname to connect to
- `port`     `{number}` — destination port (1–65535)
- `hostname` `{string}` — value used in the HTTP `Host` header; typically the PTR-resolved hostname
  so traffic resembles a real browser session

**Returns:** `{Promise<string|null>}`
- Response text (possibly empty string `""`) if the connection was established
- `null` if the connection was refused, reset, or timed out without connecting

**Notes:**
- The HTTP HEAD probe is opportunistic. Services that do not speak HTTP will respond with their own
  banner (e.g. SSH, FTP, SMTP) or nothing at all. In both cases the accumulated buffer holds
  whatever bytes arrived.
- `socket.destroy()` on timeout triggers the `close` event, which resolves the promise. Without
  this chain the promise would hang indefinitely after a timeout.
- The `error` event only resolves the promise with `null` when `connected` is false. If an error
  fires after connect (e.g. mid-transfer RST) the `close` event resolves it instead with whatever
  data arrived — partial responses are still useful.

**Example:**
```js
const data = await tryTCPConnect("10.0.0.1", 22, "10.0.0.1");
if (data !== null) console.log("22 is open, got:", data.slice(0, 80));
```

---

## extractCert(socket)

**Purpose:**
Reads the peer TLS certificate from a connected `TLSSocket` and returns the fields most useful for
host identification. SANs in particular reveal every domain name the certificate covers, which
often identifies the network owner without a separate WHOIS lookup.

**Parameters:**
- `socket` `{tls.TLSSocket}` — an already-connected TLS socket at or after the `secureConnect` event

**Returns:** `{object|null}`
- `{ cn, org, issuer, sans, expires }` on success
- `null` if the socket has no peer certificate or the certificate has no subject

**Notes:**
- `cn`      — `subject.CN`; the common name of the certificate
- `org`     — `subject.O`; the organisation field from the subject
- `issuer`  — `issuer.O`; the CA organisation name
- `sans`    — array of DNS and IP SAN strings with `DNS:` / `IP Address:` prefixes stripped; `null` if none
- `expires` — `valid_to` as a date string; `null` if absent
- Any field that is absent on the certificate is set to `null` rather than omitted, so callers can
  check `cert.cn` without guarding for `undefined`.
- Wrapped in try/catch because `getPeerCertificate()` can throw on malformed certificates.

**Example:**
```js
socket.on("secureConnect", () => {
    const cert = extractCert(socket);
    if (cert) console.log(cert.sans); // => ["example.com", "www.example.com"]
});
```

---

## parseHeaders(raw)

**Purpose:**
Parses a raw HTTP response string and extracts a fixed set of fingerprinting headers into a plain
object. Only headers that reveal server software or CMS identity are captured; the rest are ignored.

**Parameters:**
- `raw` `{string}` — full HTTP response text, including the status line

**Returns:** `{object|null}`
- Key/value map of lower-cased header names to trimmed values for headers that were present
- `null` if none of the watched headers appeared in the response

**Notes:**
- Captured headers: `server`, `x-powered-by`, `content-type`, `location`, `x-generator`,
  `x-drupal-cache`, `x-wordpress-cache`.
- The status line (first line) is skipped by slicing off index 0 after splitting on `\r?\n`.
- Parsing stops at the first blank line (`sep === -1`) so the response body is never scanned.
- Returns `null` rather than an empty object so callers can use a simple truthiness check.

**Example:**
```js
const headers = parseHeaders("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Powered-By: PHP/8.2\r\n\r\n");
// => { server: "nginx/1.24.0", "x-powered-by": "PHP/8.2" }
```

---

## tryTLSConnect(host, port, hostname)

**Purpose:**
Opens a TLS connection to the target, extracts the peer certificate via `extractCert`, and
attempts to elicit a banner via HTTP/1.1 HEAD. Returns both the raw response text and the parsed
certificate object, or null if the TLS handshake failed.

**Parameters:**
- `host`     `{string}` — IP address or hostname to connect to
- `port`     `{number}` — destination port (1–65535)
- `hostname` `{string}` — used as TLS `servername` (SNI) when it is a DNS name, and as the HTTP `Host` header

**Returns:** `{Promise<{data: string, cert: object|null}|null>}`
- `{ data, cert }` if the TLS handshake succeeded and the service sent data
- `null` if the handshake failed, timed out, or the connection was refused

**Notes:**
- `rejectUnauthorized: false` is intentional — scanning targets commonly use self-signed certificates
  and the scanner cares about open/closed state, not certificate validity.
- `servername` is omitted when `hostname` is a bare IP address. Passing an IP as SNI causes
  handshake failures on some TLS implementations.
- `cert` is extracted at `secureConnect` time, before the banner write, so it is always populated
  even if the service closes the connection immediately after the handshake.
- Returns `null` (not `{ data: "", cert }`) when the service sends no data, to signal a clean "port
  speaks TLS but gave no response" case to `scanTCPPort`.

**Example:**
```js
const result = await tryTLSConnect("10.0.0.1", 443, "example.com");
if (result) {
    console.log(result.data.slice(0, 80)); // HTTP response
    console.log(result.cert?.cn);          // certificate CN
}
```

---

## scanTCPPort(host, port, hostname)

**Purpose:**
Dispatches each port to the probe strategy appropriate for its service, then returns a uniform
result object for accumulation by `scanHost`. The dispatch order is: passive banner read for ports
in `PASSIVE_PORTS`, EHLO exchange for ports in `SMTP_PORTS`, then TLS-first HTTP banner grab for
everything else.

**Parameters:**
- `host`     `{string}` — IP address or hostname
- `port`     `{number}` — TCP port number to scan
- `hostname` `{string}` — (optional, defaults to `host`) PTR-resolved hostname passed through to
  `tryTCPConnect` for use in TLS SNI and the HTTP `Host` header

**Returns:** `{Promise<{proto: string, port: number, data: string|null, cert: object|null, headers: object|null}>}`
- `proto`   — `"TCP"` for passive/SMTP probes, `"TLS"` if TLS succeeded, `"SMTP"` for SMTP ports
- `port`    — echoed back for result aggregation
- `data`    — response text, or `null` if the port is closed
- `cert`    — parsed certificate fields from `extractCert`, or `null` for non-TLS ports
- `headers` — fingerprinting headers from `parseHeaders`, or `null` when no watched headers were present

**Notes:**
- **`PASSIVE_PORTS` dispatch:** ports like SSH (22/2222), FTP (21), DNS (53), POP3 (110/995),
  IMAP (143/993), MySQL (3306), Redis (6379), Telnet (23) go to `probeBannerOnly`. An HTTP probe
  against these services creates a protocol-mismatch error entry in the service log — a clear
  scanner fingerprint.
- **`SMTP_PORTS` dispatch:** ports 25 and 587 go to `probeSMTP`, which performs the minimum
  valid EHLO exchange to get capability data without triggering SMTP error logging.
- **TLS-first fallback:** all other ports attempt TLS first. If the handshake fails, plain TCP
  with an HTTP HEAD probe is tried. Both probes are never run simultaneously.
- `proto` reflects which strategy was used, not merely what was tried last. A successful TLS probe
  sets `proto: "TLS"`; a successful SMTP probe sets `proto: "SMTP"`.
- `headers` is only populated for HTTP/HTTPS responses. `cert` is only populated for successful
  TLS connections.

**Example:**
```js
const result = await scanTCPPort("192.168.1.1", 443);
// => { proto: "TLS", port: 443, data: "HTTP/1.1 200 OK\r\n...", cert: { cn: "example.com", ... }, headers: { server: "nginx" } }

const result = await scanTCPPort("192.168.1.1", 22);
// => { proto: "TCP", port: 22, data: "SSH-2.0-OpenSSH_9.3p1 Ubuntu-3", cert: null, headers: null }
```

---

## tryUDPConnect(host, port)

**Purpose:**
Sends an empty UDP datagram to the target port and waits for a response. UDP has no connection
handshake, so the semantics of "open" and "closed" differ fundamentally from TCP: a service that
is open may simply not respond to an empty payload, making it indistinguishable from a firewall
silently dropping the packet.

**Parameters:**
- `host` `{string}` — IP address to probe (hostname resolution is not performed here)
- `port` `{number}` — UDP port number

**Returns:** `{Promise<string|null>}`
- Response string if the service sent a UDP reply
- `"OPEN|FILTERED"` if no reply arrived within `SOCKET_TIMEOUT_MS`
- `null` if the OS received an ICMP port-unreachable (definitive closed)
- `"ERROR: <message>"` for other unexpected socket errors

**Notes:**
- The `finish()` guard (`isFinished` flag) is essential because the `message` event and the timer
  callback can both fire in the same event loop tick under some OS conditions, and `socket.close()`
  must only be called once.
- An empty payload (`Buffer.alloc(0)`) is used because we have no knowledge of what protocol the
  port might speak. Protocol-specific probes (DNS, NTP, SNMP) would yield better results but are
  out of scope.
- `ECONNREFUSED` on a UDP socket is the Node.js representation of an ICMP type 3 code 3
  (port-unreachable) packet. This is the only reliable signal that a UDP port is definitively
  closed.
- The timer is cleared in all non-timeout code paths to prevent a dangling timeout from resolving
  an already-resolved promise.

**Example:**
```js
const result = await tryUDPConnect("10.0.0.1", 53);
// port 53 (DNS) is open and replied => "\x00\x00\x81\x80..." (raw DNS response)
// port 9999 unreachable            => null
// port 5555 no reply               => "OPEN|FILTERED"
```

---

## scanUDPPort(host, port)

**Purpose:**
Thin wrapper that calls `tryUDPConnect` and returns the result in the same
`{ proto, port, data }` shape that `scanTCPPort` uses. This uniform shape lets `onPortResult`
and `runPool` handle TCP and UDP results identically without conditional logic.

**Parameters:**
- `host` `{string}` — IP address to scan
- `port` `{number}` — UDP port number

**Returns:** `{Promise<{proto: string, port: number, data: string|null}>}`
- `proto` is always `"UDP"`

**Notes:**
- `"OPEN|FILTERED"` from `tryUDPConnect` becomes the `data` field here and is explicitly filtered
  out in `onPortResult`. The value is preserved through this layer rather than converted to `null`
  so that callers can distinguish "no reply (uncertain)" from "definite closed (null)" if needed in
  the future.

---

## runPool(taskList, workerLimit, onTaskDone)

**Purpose:**
Executes an array of async tasks with a bounded concurrency limit. Without this, mapping 65535 ports
to parallel promises would immediately open 65535 sockets, exhausting OS file descriptors and
flooding the network. `runPool` keeps at most `workerLimit` tasks alive at any moment.

**Parameters:**
- `taskList`    `{Array<() => Promise<any>>}` — array of zero-argument factory functions, each
  returning a promise; tasks are not started until a worker picks them up
- `workerLimit` `{number}` — maximum number of tasks to run concurrently
- `onTaskDone`  `{(result: any) => void}` — called synchronously with each task's resolved value
  as soon as it completes

**Returns:** `{Promise<void>}` — resolves only after every task has completed

**Notes:**
- Workers share a single `taskIndex` counter. Each worker atomically reads and increments it in the
  same synchronous step (`taskList[taskIndex++]()`), so tasks are never duplicated or skipped.
  This works because JavaScript is single-threaded — there is no race condition on `taskIndex`.
- `Math.min(workerLimit, taskList.length)` ensures we do not spawn more workers than tasks, which
  would create idle workers that loop forever checking a depleted queue.
- The `onTaskDone` callback fires in completion order, not submission order. Callers that need
  ordered results must sort afterwards (as `scanHost` does).
- Rejected task promises will propagate through `worker()` and cause `Promise.all` to reject,
  aborting remaining workers. All task functions in this scanner handle errors internally and never
  reject.

**Example:**
```js
const tasks = ports.map((p) => () => scanTCPPort(host, p));
await runPool(tasks, 50, ({ port, data }) => {
    if (data !== null) console.log(`${port} open`);
});
```

---

## getOutboundIP()

**Purpose:**
Detects the machine's real outbound IP address so that SYN probes in `--syn` mode use the correct
source IP and the resulting SYN-ACK packets are routed back to this host. A UDP socket is
connected to `8.8.8.8:53` without sending any data — the OS selects the right source address as
part of routing, which is then read from `socket.address()`.

**Parameters:** none

**Returns:** `{Promise<string|null>}`
- Dotted-decimal outbound IP address on success
- `null` if the socket could not be created or an error occurred

**Notes:**
- No actual UDP packet is transmitted. `dgram.connect()` only triggers the kernel routing table
  lookup; it does not send anything to Google's DNS server.
- Only called when `--syn` is active. The result is passed to every `probeSYNHalfOpen` call so the
  SYN-ACK from the target has a valid destination.

**Example:**
```js
const srcIP = await getOutboundIP();
// => "10.0.0.5"
```

---

## initSYNReceiver()

**Purpose:**
Creates a raw TCP socket that captures all inbound TCP packets and resolves pending
`probeSYNHalfOpen` promises when a matching SYN-ACK arrives. The socket is stored in
`synRecvSocket` and kept alive for the duration of the process.

**Parameters:** none

**Returns:** `{boolean}` — `true` if the raw socket was set up successfully, `false` if
`raw-socket` is unavailable or the process lacks root privileges

**Notes:**
- Each received packet includes the IP header — `(buffer[0] & 0x0f) * 4` computes the variable
  header length before reading the TCP fields.
- A pending probe is looked up by `responseDstPort` (the destination port in the inbound packet,
  which equals the source port the scanner used when sending the SYN). The `dstIP` and `dstPort`
  fields in the pending entry are cross-checked against the packet source to prevent resolving a
  probe with an unrelated packet.
- `isSYNACK` is passed as the resolve value so `probeSYNHalfOpen` can distinguish an open port
  (SYN-ACK received) from a timeout (false) without a separate error path.
- Only called when `--syn` is active. Failure causes the process to exit with an error rather than
  degrade silently, because a silent failure would report all ports as closed.

---

## probeSYNHalfOpen(dstIP, dstPort, srcIP)

**Purpose:**
Probes one TCP port using a half-open SYN scan. The scanner sends a SYN and waits for a SYN-ACK
but never sends the final ACK, so the three-way handshake is never completed. Application-layer
daemons (SSH, NGINX, Apache, Cowrie) only log connections after the handshake finishes — they never
see this probe.

**Parameters:**
- `dstIP`   `{string}` — destination IP in dotted-decimal
- `dstPort` `{number}` — TCP port to probe
- `srcIP`   `{string}` — real outbound IP from `getOutboundIP`; must be the machine's actual
  address so the SYN-ACK is routed back to us

**Returns:** `{Promise<boolean>}` — `true` if a SYN-ACK was received within `TIMEOUT` ms (port
open), `false` on timeout or if raw sockets are unavailable

**Notes:**
- The probe is registered in `pendingSYNs` before the packet is sent so there is no window where
  a fast SYN-ACK could arrive before the entry exists.
- A random source port is chosen per probe via `randomSourcePort()`. The source port is both the
  `pendingSYNs` map key and the field `initSYNReceiver` uses to match inbound SYN-ACKs back to
  this call.
- On timeout, the entry is removed from `pendingSYNs` to prevent the map from growing without
  bound across a long scan run.
- Uses the same `getDecoySocket()` raw socket as the decoy system — no additional file descriptor
  is consumed per probe.

**Example:**
```js
const open = await probeSYNHalfOpen("192.168.1.1", 22, "10.0.0.5");
// => true  (SYN-ACK received — port is open)
// => false (timeout — port is closed or filtered)
```

---

## scanHost(host, firstPort, lastPort, onProgress, srcIP)

**Purpose:**
Scans the full port range on one host, running TCP and UDP pools concurrently, and returns a
structured result object. This is the main per-host orchestration function. It exists as a named
function (rather than inline code) so that `runPool` at the host level can parallelise across
multiple targets.

**Parameters:**
- `host`       `{string}`      — IP address or hostname to scan
- `firstPort`  `{number}`      — start of port range, inclusive
- `lastPort`   `{number}`      — end of port range, inclusive
- `onProgress` `{Function}`    — called once per completed probe; used to advance the progress bar
- `srcIP`      `{string|null}` — real outbound IP passed through to `probeSYNHalfOpen` in `--syn`
  mode; `null` in normal mode

**Returns:** `{Promise<{host: string, hostname?: string, ports: object, scannedAt: string}>}`
- `host`      — echoed input value (IP or hostname passed on the CLI)
- `hostname`  — PTR-resolved hostname, present only when it differs from `host`
- `ports`     — plain object keyed by port number string; each value is `{ proto, banner, cert?, headers? }`;
  in `--syn` mode values are `{ proto: "SYN" }` with no banner, cert, or headers;
  ports are sorted ascending before the object is built
- `scannedAt` — ISO 8601 timestamp of when the scan completed

**Notes:**
- DNS resolution happens twice per host: once with `dns.lookup()` to get the IP for decoy sending,
  and once with `dns.reverse()` to get the PTR hostname for use in TLS SNI and the HTTP `Host`
  header. Both lookups are silently skipped on failure.
- If DNS lookup fails the host is scanned normally but decoys are disabled (silently). The catch
  block intentionally has no body.
- In `--syn` mode, TCP tasks call `probeSYNHalfOpen` instead of `scanTCPPort`. Results carry
  `proto: "SYN"` and no banner, cert, or headers because the handshake never completes.
- `hostname` is only included in the result object when the PTR hostname differs from the raw
  `host` argument, keeping the JSON compact for hosts with no PTR record.
- `onPortResult` is an inner function rather than a top-level one because it closes over
  `openPorts` and `host`, keeping the per-host result accumulation self-contained.
- TCP and UDP pools run with `Promise.all`, meaning both start simultaneously and `scanHost`
  resolves only after both finish. This halves elapsed time compared to running TCP then UDP
  sequentially.
- Results are sorted after both pools complete so the final JSON is deterministically ordered
  regardless of which port resolved first.

**Example:**
```js
// Normal mode
const result = await scanHost("192.168.1.1", 1, 1024, onProgress, null);
// => { host: "192.168.1.1", hostname: "server1.example.com", ports: { "22": { proto: "TCP", banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" } }, scannedAt: "..." }

// --syn mode
const result = await scanHost("192.168.1.1", 1, 1024, onProgress, "10.0.0.5");
// => { host: "192.168.1.1", ports: { "22": { proto: "SYN" }, "80": { proto: "SYN" } }, scannedAt: "..." }
```

---

## expandCIDR(cidr)

**Purpose:**
Converts a CIDR notation block into a flat list of scannable host IP strings, skipping the network
and broadcast addresses. This allows the scanner to accept a single CIDR string on the CLI or in
the target file instead of requiring every individual host to be listed.

**Parameters:**
- `cidr` `{string}` — CIDR block, e.g. `"10.0.0.0/24"` or `"192.168.1.0/28"`

**Returns:** `{string[]}` — array of dotted-decimal host IP strings (network and broadcast excluded)

**Notes:**
- Prefix lengths below `/16` are rejected with a thrown `Error`. Expanding a `/8` would produce
  16 million hosts, which would be both slow and irresponsible without an explicit confirmation
  mechanism. The `/16` floor produces at most 65,534 hosts.
- `/32` (single host) is supported: `hostCount` is 1, the loop runs `offset` from 1 to -1
  (exclusive upper bound `hostCount - 1 = 0`), producing an empty array. Callers should be aware
  that a `/32` CIDR expands to zero hosts — use a bare IP string for single-host scans.
- Bit manipulation uses unsigned right-shift (`>>> 0`) to coerce the result to an unsigned 32-bit
  integer, preventing negative numbers on addresses with a high bit set (e.g. `192.x.x.x`).

**Example:**
```js
expandCIDR("10.0.0.0/30");
// => ["10.0.0.1", "10.0.0.2"]
```

---

## parseTargetFile(filePath)

**Purpose:**
Reads a newline-delimited target file and expands its contents into a flat list of host strings.
Supports mixing individual IPs, hostnames, and CIDR blocks in the same file. Exists so users can
manage large target lists in a file instead of passing a huge CIDR on the CLI.

**Parameters:**
- `filePath` `{string}` — path to the targets file (read synchronously)

**Returns:** `{string[]}` — flat array of IP/hostname strings, with all CIDRs expanded inline

**Notes:**
- The file is read synchronously (`readFileSync`) because target parsing happens once at startup
  before any async scanning begins. There is no benefit to async I/O here.
- Lines are trimmed before processing so Windows-style `\r\n` line endings do not produce hosts
  with a trailing `\r`.
- `#` comment lines and blank lines are silently skipped.
- A line containing `/` is treated as a CIDR block. There is no validation that the `/` is part of
  a valid CIDR — a malformed value like `host/name` will be passed to `expandCIDR` and throw.
- The file is not required to exist before calling this function; the check `fs.existsSync` is
  performed by the caller (entry point) before dispatching to `parseTargetFile` vs. direct CLI
  argument handling.

**Example:**
```
# config/targets.txt
10.0.1.5
scanme.example.com
192.168.0.0/28
```
```js
parseTargetFile("config/targets.txt");
// => ["10.0.1.5", "scanme.example.com", "192.168.0.1", "192.168.0.2", ..., "192.168.0.14"]
```

---

---

---

# utils.js — Function Reference

Both functions are exported and imported by `scanner.js` and `credtest.js`.

---

## jitter(min, max)

**Purpose:**
Pauses execution for a uniformly random number of milliseconds in the range `[min, max]`.
Injecting a random pause between probes or attempts prevents a scanner from producing a flat,
detectable probe-rate distribution.

**Parameters:**
- `min` `{number}` — minimum delay in milliseconds (inclusive)
- `max` `{number}` — maximum delay in milliseconds (inclusive)

**Returns:** `{Promise<void>}`

**Notes:**
- The distribution is uniform, not Gaussian — a Gaussian clusters around its mean and can still
  be statistically fingerprinted with enough samples.
- `scanner.js` calls it with `J_MIN = 10` / `J_MAX = 250` in normal mode, or `SLOW_J_MIN = 5000` /
  `SLOW_J_MAX = 60000` when `--slow` is active. `credtest.js` calls it with `JITTER_MIN_MS = 500` /
  `JITTER_MAX_MS = 2000`. The wider credtest range keeps login attempt rates below account lockout
  thresholds.

**Example:**
```js
await jitter(10, 250);      // scanner — normal mode
await jitter(5000, 60000);  // scanner — slow mode
await jitter(500, 2000);    // credtest
```

---

## runPool(tasks, limit, onDone)

**Purpose:**
Executes an array of async tasks with a bounded concurrency limit. Without this, mapping tens of
thousands of ports to parallel promises would immediately exhaust OS file descriptors and flood the
network.

**Parameters:**
- `tasks`  `{Array<() => Promise<any>>}` — zero-argument factory functions; not started until a worker picks them up
- `limit`  `{number}` — maximum number of tasks to run concurrently
- `onDone` `{(result: any) => void}` — called synchronously with each task's resolved value as soon as it completes

**Returns:** `{Promise<void>}` — resolves only after every task has completed

**Notes:**
- Workers share a single `i` counter. Each worker reads and increments it atomically in the same
  synchronous step (`tasks[i++]()`), so tasks are never duplicated or skipped. This is safe because
  JavaScript is single-threaded — there is no race on `i`.
- `Math.min(limit, tasks.length)` avoids spawning more workers than tasks, which would leave idle
  workers looping forever on a depleted queue.
- `onDone` fires in completion order, not submission order. Callers that need ordered output must
  sort afterwards (as `scanHost` does).
- Rejected task promises propagate through `worker()` and cause `Promise.all` to reject. All task
  functions in the scanner and credtest handle errors internally and never reject.

**Example:**
```js
const tasks = ports.map((p) => () => scanTCPPort(host, p));
await runPool(tasks, 50, ({ port, data }) => {
    if (data !== null) console.log(`${port} open`);
});
```

---

---

# honeypot.js — Function Reference

---

## probeSSHFingerprint(host, port)

**Purpose:**
Connects to an SSH port, reads the server's `MSG_KEXINIT` packet, and returns the advertised
algorithm lists. Cowrie (via twisted.conch) advertises legacy algorithms that modern OpenSSH
dropped — this detects it without needing credentials.

**Parameters:**
- `host` `{string}` — IP address or hostname to connect to
- `port` `{number}` — SSH port number

**Returns:** `{Promise<{kexAlgos: string[], hostKeyAlgos: string[], encAlgos: string[], macAlgos: string[]}|null>}`
- Parsed algorithm lists if the server sent a valid `MSG_KEXINIT`
- `null` on connection failure, timeout, or unexpected message type

**Notes:**
- The client version string sent on connect is `SSH-2.0-OpenSSH_9.9` to impersonate a real client
  and avoid leaving an identifiable version string in server logs.
- The socket times out after 5 000 ms regardless of `socketTimeoutMs` in `settings.json` — the KEX
  probe is a fixed-duration operation separate from the main scan.
- Only the client→server encryption and MAC name-lists are extracted; the server→client lists are
  skipped over to keep offset arithmetic simple. The client→server lists are sufficient for
  Cowrie fingerprinting because twisted.conch advertises the same algorithms in both directions.
- `MSG_KEXINIT` payload layout: 1 byte message type (20) + 16 bytes cookie + 10 name-lists. The
  first four name-lists are kex algorithms, host key types, and encryption algorithms
  (client→server, then server→client). Only the first three and the client→server MAC list are read.

**Example:**
```js
const fp = await probeSSHFingerprint("10.0.0.1", 22);
if (fp) console.log(fp.kexAlgos);
// => ["curve25519-sha256", "diffie-hellman-group14-sha1", ...]
```

---

## checkSSHFingerprint(fp, port)

**Purpose:**
Checks a parsed SSH KEX fingerprint against the four Cowrie algorithm tell-lists from
`settings.json` and returns a reason string for each match found.

**Parameters:**
- `fp`   `{{kexAlgos: string[], hostKeyAlgos: string[], encAlgos: string[], macAlgos: string[]}}` — object returned by `probeSSHFingerprint`
- `port` `{number}` — SSH port number, included in each reason string for context

**Returns:** `{string[]}` — one reason string per matched algorithm; empty array if nothing suspicious

**Notes:**
- Each of the four tell-lists (`cowrieKexTells`, `cowrieMacTells`, `cowrieEncTells`,
  `cowrieHostKeyTells`) is checked independently — a single fingerprint can produce multiple reasons
  if Cowrie advertises more than one legacy algorithm.
- The reason strings include both the port number and the specific algorithm name so that
  multi-port SSH deployments produce unambiguous output.

**Example:**
```js
checkSSHFingerprint({ kexAlgos: ["diffie-hellman-group1-sha1"], hostKeyAlgos: [], encAlgos: [], macAlgos: ["hmac-md5"] }, 22);
// => [
//      "Cowrie KEX algorithm on port 22: diffie-hellman-group1-sha1",
//      "Cowrie MAC algorithm on port 22: hmac-md5"
//    ]
```

---

## checkHost(ports)

**Purpose:**
Inspects the open ports and banners of a single host against static honeypot indicators and returns
a list of reason strings. Returns an empty array if nothing suspicious is found.

**Parameters:**
- `ports` `{object}` — port map from scan JSON; accepts both the current object format
  `{ "22": { proto: "TCP", banner: "SSH-2.0-..." } }` and the legacy string format
  `{ "22": "TCP: SSH-2.0-..." }`

**Returns:** `{string[]}` — human-readable reason strings, one per triggered heuristic; empty array if clean

**Notes:**
- Five static heuristics are applied: known Cowrie SSH banners, SSH banners missing an OS distro
  suffix, known FTP honeypot banners, open Telnet (port 23), T-Pot port combination, and
  suspiciously many open ports. Live KEX probing is handled separately in the entry point after
  this function returns.
- The Cowrie exact-match check (`COWRIE_SSH_BANNERS`) runs before the bare-suffix check and uses
  `continue` to skip the suffix check on the same port — avoiding a duplicate reason for the same
  port when both would match.
- `SSH_DISTRO_SUFFIX` is a compiled `RegExp` built at module load from `cfg.sshDistroKeywords`. Real
  distro-packaged OpenSSH always appends an OS string (e.g. `Ubuntu-4ubuntu2.2`) — its absence is
  a reliable Cowrie tell for versions not in the exact-match list.
- FTP banner matching checks ports whose banner starts with `"220"` against `FTP_HONEYPOT_BANNERS`
  using a substring search — covers banners where the scanner captured more text than the list entry.
- `TPOT_MATCH_MIN` (default 4) means at least 4 ports from the T-Pot set must be open before the
  combination is flagged, reducing false positives on hosts that legitimately run web + SSH + FTP.
- `SUSPICIOUS_THRESHOLD` (default 6) is intentionally low — real servers rarely expose that many
  services simultaneously.

**Example:**
```js
checkHost({ "22": { proto: "TCP", banner: "SSH-2.0-OpenSSH_5.3" }, "23": { proto: "TCP", banner: null } });
// => [
//      'Cowrie SSH banner on port 22: "SSH-2.0-OpenSSH_5.3"',
//      "Telnet (port 23) open — almost always a honeypot"
//    ]
```

---

## honeypot.js — Entry Point

**CLI syntax:**
```
node src/honeypot.js <scan.json>
```

**Behaviour:**
1. Reads the scan JSON file produced by `scanner.js`.
2. Calls `checkHost()` for every entry to collect static indicator reasons.
3. For each SSH port found in the entry, calls `probeSSHFingerprint()` to fetch the live KEX
   advertisement, then `checkSSHFingerprint()` to append any algorithm-based reasons.
4. Writes `{ suspected: true, reasons: [...] }` or `{ suspected: false }` back into each entry
   under a `honeypot` key.
5. Saves the updated JSON back to the same file.
6. Prints a summary count of flagged hosts.

**Notes:**
- All detection thresholds, banner lists, and algorithm tell-lists are loaded from
  `config/settings.json` under the `honeypot` key — nothing is hard-coded in the source.
- The file is overwritten in place. Run on a copy if you want to preserve the original scan output.
- Live KEX probing runs sequentially per host, after the static checks, to avoid opening many
  simultaneous raw TCP connections during the probe phase.

---

# credtest.js — Function Reference

All functions below are defined in `src/credtest.js`. They are listed in the order they appear in the file.

---

---

## trySSH(host, port, username, password)

**Purpose:**
Attempts a single SSH authentication using the `ssh2` library. Returns `true` if the server accepts
the credentials, `false` for any other outcome including connection failure, timeout, or wrong
password.

**Parameters:**
- `host`     `{string}` — target IP address or hostname
- `port`     `{number}` — SSH port number
- `username` `{string}` — login username
- `password` `{string}` — login password

**Returns:** `{Promise<boolean>}` — `true` if authentication succeeded, `false` otherwise

**Notes:**
- Returns `false` immediately if `ssh2` was not installed, preserving the optional-dependency
  contract — the tool does not crash on missing packages.
- Both the `ready` event and the manual `TIMEOUT_MS` timer clear each other to prevent double-resolve.
  The `conn.destroy()` call on timeout causes the `error` event to fire, which also resolves to
  `false` — but the `cracked` flag in `testHost` makes a duplicate resolve harmless.
- `readyTimeout` in the `conn.connect` options doubles as an internal ssh2 connection timeout,
  providing a defence-in-depth against the external timer being delayed by a busy event loop.

**Example:**
```js
const ok = await trySSH("10.0.0.5", 22, "root", "toor");
if (ok) console.log("SSH login succeeded");
```

---

## tryFTP(host, port, user, password)

**Purpose:**
Attempts FTP login with both plain and implicit TLS connections, returning `true` on the first
mode that authenticates successfully. Trying both modes avoids a false-negative when a port
accepts FTPS but not plain FTP, or vice versa.

**Parameters:**
- `host`     `{string}` — target IP address or hostname
- `port`     `{number}` — FTP port number
- `user`     `{string}` — FTP username
- `password` `{string}` — FTP password

**Returns:** `{Promise<boolean>}` — `true` if either plain or implicit TLS login succeeded

**Notes:**
- Returns `false` immediately if `basic-ftp` was not installed.
- A single `ftpLib.Client` instance is reused across both attempts. `client.close()` is called in
  both the success and failure paths to ensure the underlying socket is always released.
- `client.ftp.verbose = false` suppresses the library's internal debug logging to stdout, which
  would otherwise mix with the tool's own progress output.
- `secureOptions: { rejectUnauthorized: false }` is set for the TLS attempt because FTP servers
  on private networks commonly use self-signed certificates.
- Explicit FTPS (STARTTLS via `AUTH TLS` command) is not attempted here. Port 21 with explicit TLS
  would require sending the `AUTH TLS` command mid-session, which `basic-ftp`'s `access()` does
  not support in this code path.

**Example:**
```js
const ok = await tryFTP("10.0.0.5", 21, "anonymous", "anon@");
if (ok) console.log("FTP login succeeded");
```

---

## tryHTTP(host, port, username, password, useHTTPS)

**Purpose:**
Submits a credential pair as a form POST across every combination of common login endpoints and
field name sets. Treats a 301–303 redirect response, or a 200 response with no error keywords in
the body, as a successful login. Covers the most common web login patterns without requiring prior
knowledge of the application.

**Parameters:**
- `host`      `{string}`  — target IP address or hostname
- `port`      `{number}`  — HTTP or HTTPS port number
- `username`  `{string}`  — value to place in the username field
- `password`  `{string}`  — value to place in the password field
- `useHTTPS`  `{boolean}` — when `true`, uses `https://` scheme and disables certificate validation

**Returns:** `{Promise<boolean>}` — `true` if any endpoint/field combination returned a success response

**Notes:**
- Returns `false` immediately if `axios` was not installed.
- Endpoints and field name pairs are driven by `HTTP_ENDPOINTS` and `HTTP_FIELDS` from `settings.json`,
  so new login paths or field names can be added without touching this function.
- `maxRedirects: 0` prevents axios from following the redirect. The 3xx status itself is the success
  signal; following it would lose the status code needed for detection.
- `validateStatus: (s) => s < 500` tells axios to resolve (not reject) for all non-5xx responses,
  including 3xx and 4xx, so catch blocks are only reached on network errors.
- A 200 with no error keywords (`invalid`, `incorrect`, `failed`, `wrong`, `error`, `denied`) in the
  lowercased response body is also treated as a success — covers login forms that return 200 + an
  error message on failure rather than a redirect.
- `httpsAgent` is a module-level singleton constructed once at startup. Reusing it across requests
  avoids repeated TLS context creation overhead and socket pool fragmentation.

**Example:**
```js
const ok = await tryHTTP("10.0.0.5", 80, "admin", "admin123", false);
if (ok) console.log("HTTP login succeeded");
```

---

## detectService(portNum, portValue)

**Purpose:**
Classifies an open port as `ssh`, `ftp`, `http`, `https`, or `null` so `testHost` knows which
protocol tester to invoke. Checks port number first against known port sets, then falls back to
inspecting the proto and banner from the scan result for TLS or HTTP indicators.

**Parameters:**
- `portNum`   `{number}`          — the port number key from the scan JSON
- `portValue` `{object|string}`   — the port entry from the scan JSON; accepts both the current
  object format `{ proto, banner, ... }` and the legacy string format `"TCP: banner"`

**Returns:** `{"ssh"|"ftp"|"http"|"https"|null}` — service type, or `null` if the port is not a recognised testable service

**Notes:**
- Port-number matching takes priority over banner matching. If port 22 runs an HTTP server (unusual
  but possible), it will be treated as SSH. This is intentional — port numbers are the most reliable
  classification signal for the common case.
- Banner fallback (`proto === "TLS"` → `"https"`) catches HTTPS running on non-standard ports
  (e.g. 8443 is covered by `HTTPS_PORTS`, but 9443 would fall through to the banner check).
- `null` is returned for UDP-only ports, database ports, or any service the tool does not support.
  `testHost` skips `null` entries entirely.

**Example:**
```js
detectService(22,   { proto: "TCP", banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" })  // => "ssh"
detectService(443,  { proto: "TLS", banner: "HTTP/1.1 200 OK" })                 // => "https"
detectService(8080, { proto: "TCP", banner: "HTTP/1.1 200 OK" })                 // => "http"
detectService(9999, { proto: "TLS", banner: null })                              // => "https" (banner fallback)
detectService(3306, { proto: "TCP", banner: null })                              // => null    (MySQL — not tested)
```

---

## parseWordlist(filePath)

**Purpose:**
Reads a credential wordlist file and parses it into an array of `{ user, pass }` objects.
Each non-comment, non-blank line must be in `username:password` format.

**Parameters:**
- `filePath` `{string}` — path to the wordlist file (read synchronously)

**Returns:** `{{ user: string, pass: string }[]}` — array of credential pairs

**Notes:**
- Uses `l.indexOf(":")` to find the first colon, then `slice` on both sides. This correctly handles
  passwords that contain colons (e.g. `admin:pass:word` → `user="admin"`, `pass="pass:word"`).
- The file is read synchronously because wordlist parsing happens once at startup, before any async
  work begins.
- Lines starting with `#` and blank lines are filtered out so the wordlist can include comments and
  section separators without producing malformed credential pairs.

**Example:**
```
# config/wordlist.txt
admin:admin
root:toor
user:p@ss:w0rd
```
```js
parseWordlist("config/wordlist.txt");
// => [
//      { user: "admin", pass: "admin" },
//      { user: "root",  pass: "toor" },
//      { user: "user",  pass: "p@ss:w0rd" }
//    ]
```

---

## testHost(host, ports, credentials)

**Purpose:**
Iterates over every open port on a host, identifies testable services, and runs the full wordlist
against each one using a bounded concurrency pool. Stops testing a port as soon as valid credentials
are found to minimise login noise and lockout risk.

**Parameters:**
- `host`        `{string}` — IP address or hostname of the target
- `ports`       `{object}` — port map from scan JSON; accepts both the current object format
  `{ "22": { proto: "TCP", banner: "SSH-2.0-..." } }` and the legacy string format
  `{ "22": "TCP: SSH-2.0-..." }`
- `credentials` `{{ user: string, pass: string }[]}` — parsed wordlist from `parseWordlist()`

**Returns:** `{Promise<{ found: object, honeypot: boolean }>}`
- `found` — map of port string → `{ user, pass, service }` for every successful login; empty object if none succeed
- `honeypot` — `true` if the very first credential attempt on any port was accepted (classic honeypot tell)

**Notes:**
- The `abort` controller is signalled the moment a valid credential is found. Tasks that have not
  started yet return immediately; tasks already in flight run to completion but discard their result.
- Port iteration is sequential (a standard `for...of` loop). All concurrency is within a single
  port's wordlist run. This is intentional: parallelising across ports would multiply the per-port
  attempt rate by the number of ports, making lockouts more likely.
- The `firstAttempt` flag is reset to `true` at the start of each port's wordlist run. A hit on the
  very first credential of any port sets `honeypot = true` and marks the result with
  `{ honeypot: true }` so the caller can surface it separately.
- Successful results are keyed by port string (e.g. `"22"`) to match the key format in the scan
  JSON, making the merge at the entry point a direct property assignment.

**Example:**
```js
const { found, honeypot } = await testHost("10.0.0.5", { "22": { proto: "TCP", banner: "SSH-2.0-OpenSSH_8.9" }, "80": { proto: "TCP", banner: "HTTP/1.1 200 OK" } }, creds);
// => { found: { "22": { user: "root", pass: "toor", service: "SSH" } }, honeypot: false }
```

---

## credtest.js — Entry Point

**CLI syntax:**
```
node src/credtest.js <scan.json> <wordlist.txt> [--hosts=ip1,ip2,...]
```

**Argument parsing:**
- `args[0]` (`scanFile`) — path to the JSON file produced by the scanner
- `args[1]` (`wordlistFile`) — path to a `username:password` wordlist
- `args.find(a => a.startsWith("--hosts="))` — optional filter; comma-separated list of IP
  addresses to restrict testing to a subset of the scan results

**Behaviour:**
1. Parses `--hosts=` from the raw `process.argv` array; all other args are positional.
2. If `--hosts` is supplied, filters `scanResults` to only entries whose `host` field appears in
   the provided set. Exits with an error if no matching hosts are found.
3. Iterates hosts sequentially. For each host, calls `testHost()` and merges the returned
   `found` map into `hostEntry.credentials`. Sets `hostEntry.honeypot` if the `honeypot` flag
   is true.
4. Writes the updated scan JSON back to `scanFile` after every host so a crash loses at most
   one host's results.

**Notes:**
- `jitter` and `runPool` are imported from `src/utils.js` — they are not duplicated in this file.
- The process does not require root — credential testing uses standard TCP connections only.
- Missing optional packages (`ssh2`, `basic-ftp`, `axios`) print a warning but do not abort
  startup; affected protocol testers return `false` silently at runtime.

---

---

---

# enrich.js — Function Reference

---

## whoisLookup(ip)

**Purpose:**
Queries `whois.ripe.net` over a plain TCP connection on port 43 and returns the raw response text.
RIPE NCC is the RIR for European IP space; most Hetzner addresses fall under RIPE.

**Parameters:**
- `ip` `{string}` — dotted-decimal IP address to look up

**Returns:** `{Promise<string|null>}`
- Raw WHOIS response text on success
- `null` on connection failure or 5-second timeout

**Notes:**
- The query is the IP string followed by `\r\n`, per the WHOIS protocol (RFC 3912).
- A 5-second hard timeout is applied regardless of how much data has arrived — RIPE responses
  are small and complete well within this window.
- Only queries RIPE. IPs assigned by ARIN, APNIC, LACNIC, or AFRINIC will return an empty or
  referral response. `parseOwner` returns `"unknown"` in that case.

**Example:**
```js
const raw = await whoisLookup("188.40.1.1");
// => "% This is the RIPE Database...\ninetnum: ..."
```

---

## parseOwner(raw)

**Purpose:**
Extracts the most human-readable owner name from a raw WHOIS response by checking a priority-ordered
list of field names.

**Parameters:**
- `raw` `{string}` — raw WHOIS response text from `whoisLookup`; `null` is also accepted

**Returns:** `{string}` — organisation or network name, or `"unknown"` if no recognised field was found

**Notes:**
- Fields are checked in order: `org-name` (most specific), `netname`, `descr` (most generic).
  The first match wins.
- The regex uses the `im` flags: `i` for case-insensitive field names, `m` for per-line `^` anchors.
- Passing `null` returns `"unknown"` immediately without attempting a regex match.

**Example:**
```js
parseOwner("org-name: Hetzner Online GmbH\nnetname: HETZNER-RZ\n");
// => "Hetzner Online GmbH"
```

---

## enrich.js — Entry Point

**CLI syntax:**
```
node src/enrich.js <scan.json>
```

**Behaviour:**
1. Reads the scan JSON file produced by `scanner.js`.
2. For each host entry, calls `whoisLookup()` with the `host` IP and then `parseOwner()` on the
   raw response.
3. Writes the resolved name into `entry.owner`.
4. Saves the updated JSON back to the same file after all hosts are processed.
5. Prints a running `[done/total]` progress line to stdout.

**Notes:**
- Lookups run sequentially (one at a time) to avoid overwhelming `whois.ripe.net` with concurrent
  TCP connections, which could result in rate-limiting or temporary blocks.
- The file is overwritten in place. Run on a copy if you want to preserve the unenriched version.
- Hosts for which `whoisLookup` returns `null` (timeout, unreachable) get `owner: "unknown"`.

---

---

---

---

# report.js — Function Reference

All functions below are defined in `src/report.js`. They are listed in the order they appear in the file.

---

## esc(s)

**Purpose:**
HTML-escapes a value before it is spliced into an HTML document. Every piece of data from the scan
JSON passes through this before being written into the report, preventing stored XSS if the scan
contains attacker-controlled banners or hostnames.

**Parameters:**
- `s` `{*}` — value to escape; `null` and `undefined` are coerced to an empty string before escaping

**Returns:** `{string}` — the input with `&`, `<`, `>`, and `"` replaced by their HTML entity equivalents

---

## badge(text, color)

**Purpose:**
Renders a small pill-shaped label used to display protocol names (TLS, SYN, SMTP, TCP) alongside
each port in the port table.

**Parameters:**
- `text`  `{string}` — label text; passed through `esc()` before insertion
- `color` `{string}` — any CSS colour value (hex, named, rgb) applied as the background

**Returns:** `{string}` — HTML `<span class="badge">` element

---

## portRow(port, info)

**Purpose:**
Renders one `<tr>` for the port table inside a host card. Handles the optional TLS certificate
block, HTTP headers block, and CVE block; absent fields are omitted rather than rendered as empty
cells.

**Parameters:**
- `port` `{string}` — port number string (e.g. `"443"`)
- `info` `{object}` — port entry from the scan JSON with the following optional fields:
  - `proto`   `{string}` — protocol label (`"TLS"`, `"TCP"`, `"SYN"`, `"SMTP"`, `"UDP"`)
  - `banner`  `{string}` — first line of the service response
  - `cert`    `{object}` — TLS certificate object with `cn`, `org`, `issuer`, `sans`, `expires`
  - `headers` `{object}` — HTTP fingerprinting headers key/value map
  - `cves`    `{Array}`  — CVE results from `vulnscan.js`; array of `{ software, cves[] }` objects

**Returns:** `{string}` — HTML `<tr>` element

**Notes:**
- Protocol colours are hard-coded per protocol name: green for TLS, orange for SYN, purple for
  SMTP, blue for everything else. This makes the most security-relevant protocols visually distinct
  at a glance.
- The SANs list is truncated to 5 entries with a `+N more` suffix to prevent cards from growing
  unwieldy on wildcard or multi-SAN certificates.
- CVE severity badge colours: CRITICAL=red (`#f44336`), HIGH=orange (`#ff9800`),
  MEDIUM=yellow (`#ffeb3b`), LOW=green (`#4caf50`). Each CVE ID is a clickable link to
  `nvd.nist.gov`. The CVSS score and a truncated summary (up to 120 characters) are shown inline.

---

## hostCard(entry)

**Purpose:**
Renders the full card for one host, combining the header (IP, hostname, owner, port count, scan
time), optional honeypot reasons banner, port table, CVE entries per port, and credential results
block.

**Parameters:**
- `entry` `{object}` — single host entry from the scan JSON array with the following fields:
  - `host`        `{string}`          — IP address
  - `hostname`    `{string}`          — (optional) PTR-resolved hostname
  - `owner`       `{string}`          — (optional) WHOIS organisation name
  - `ports`       `{object}`          — port map passed to `portRow()`; port entries may contain a `cves` field
  - `scannedAt`   `{string}`          — ISO 8601 timestamp
  - `honeypot`    `{object}`          — (optional) `{ suspected: boolean, reasons: string[] }`
  - `credentials` `{object|"none found"}` — (optional) credential map from credtest

**Returns:** `{string}` — HTML `<div class="card">` element; gets class `honeypot` when suspected

**Notes:**
- Honeypot reason strings are joined with `<br>` and displayed in a full-width warning strip
  immediately below the card header, using a red border and dark red background to draw attention.
- CVE data is rendered inside each port row via `portRow()`, not at the card level.
- The credential block is rendered only when `entry.credentials` exists and is not the literal
  string `"none found"`. Each cracked port is shown as a monospace inline chip.
- `entry.scannedAt` is truncated to 19 characters (`2026-05-28T12:00:00`) by slicing before the
  milliseconds; the `T` is replaced with a space for human readability.

---

## buildHTML(scanFile, data)

**Purpose:**
Assembles the complete self-contained HTML document. Computes five summary statistics at the top,
renders every host as a card, and embeds the `filterCards()` search function and all CSS inline.
The resulting string can be written directly to a `.html` file with no further processing.

**Parameters:**
- `scanFile` `{string}`   — path to the source JSON file; used in the page title and header subtitle
- `data`     `{object[]}` — parsed scan JSON array

**Returns:** `{string}` — complete `<!DOCTYPE html>` document

**Notes:**
- All CSS and JavaScript are embedded inline so the output is fully self-contained: opening it
  without a server or network connection works correctly.
- The `filterCards()` function, embedded in a `<script>` block, performs real-time DOM filtering
  by matching the search input against each card's full `textContent`. This covers IPs, banners,
  ports, hostnames, owner names, and CVE IDs without indexing.
- Summary stats computed: total hosts with open ports, total open ports, suspected honeypots,
  hosts with credentials, and total CVE count across all ports. The CVE count is a nested reduce
  over `port.cves[].cves[]` and is shown in orange in the stats bar.
- Stats are derived in a single pass over `data` before any HTML is generated — no additional
  passes are needed.

---

## report.js — Entry Point

**CLI syntax:**
```
node src/report.js <scan.json> [output.html] [--min-ports=N]
node src/report.js --help
```

**Argument parsing:**
- Positional args are extracted from `process.argv.slice(2)` after stripping all flag arguments
  (`--slow`, `--min-ports=N`, etc.). The first positional arg is `scanFile`; the second (if present
  and not a flag) is `outFile`. This means argument order relative to flags is flexible.
- `--min-ports=N`  — (optional) integer threshold; hosts with fewer than N open ports are excluded
- `--help` / `-h`  — print usage and exit 0; exit 1 if `scanFile` is also absent

**Behaviour:**
1. If `--help`, `-h`, or no `scanFile` argument is present, prints usage to stdout and exits.
2. Reads and parses the scan JSON synchronously.
3. If `--min-ports=N` is supplied (N > 0), filters the parsed data to only hosts whose `ports`
   map has at least N keys. Prints a `filtered: before → after hosts` line to stdout.
4. Determines the output path: the explicit `outFile` argument if provided, otherwise the input
   path with the `.json` extension replaced by `.html`.
5. Calls `buildHTML(scanFile, data)` and writes the result to the output path.
6. Prints the absolute resolved output path to stdout.

**Notes:**
- `--min-ports` and `--help`/`-h` are extracted by value from the raw args array. Positional
  arguments (`scanFile`, `outFile`) are whatever remains after all flag-shaped args are removed,
  regardless of where flags appear in the command line.
- Omitting `--min-ports` (or setting N to 0) includes all hosts; no filtering step is run.
- The process exits with code `1` when called with no arguments so that shell pipelines and
  scripts can detect a missing operand. `--help` with a valid `scanFile` exits with code `0`.
- No root or special privileges are required — the script only reads and writes ordinary files.

---

---

---

# vulnscan.js — Function Reference

All functions below are defined in `src/vulnscan.js`. They are listed in the order they appear in
the file.

---

## parseBanners(portInfo)

**Purpose:**
Extracts software name, version string, and CPE prefix from a port entry by running all parser
regexes against the combined text of the banner, HTTP response headers, and TLS certificate CN.
Supports both the current port-entry object format and the legacy plain-string format.

**Parameters:**
- `portInfo` `{object|string}` — port entry from the scan JSON; either an object with optional
  `banner`, `headers`, and `cert.cn` fields, or a legacy string prefixed with `"TCP:"` / `"TLS:"` etc.

**Returns:** `{{ name: string, version: string, cpe: string }[]}` — one entry per matched software;
empty array if no version strings are found

**Notes:**
- All text sources (banner, every header value, cert CN) are joined into a single string before
  matching so that a version appearing only in an HTTP header (e.g. `x-powered-by: PHP/8.2`) is
  still detected.
- The 11 supported parsers are defined in the module-level `PARSERS` constant. Each entry provides
  a human-readable name, a CPE 2.3 `vendor:product` prefix, and a version-extraction regex.
- A port entry can match more than one parser (e.g. nginx version from `Server` header and PHP
  version from `X-Powered-By`). All matches are returned.

**Example:**
```js
parseBanners({ banner: "SSH-2.0-OpenSSH_8.9p1", headers: { "x-powered-by": "PHP/8.2" } });
// => [
//      { name: "OpenSSH", version: "8.9p1", cpe: "openbsd:openssh" },
//      { name: "PHP",     version: "8.2",   cpe: "php:php" }
//    ]
```

---

## queryCVEs(cpe, version)

**Purpose:**
Queries the NVD REST API v2 for CVEs matching a product and version, returning up to 5 results
sorted by CVSS score descending.

**Parameters:**
- `cpe`     `{string}` — CPE `vendor:product` string (e.g. `"openbsd:openssh"`)
- `version` `{string}` — version string extracted by `parseBanners` (e.g. `"8.9p1"`)

**Returns:** `{Promise<Array>}` — array of CVE objects, each with:
- `id`       `{string}` — CVE identifier (e.g. `"CVE-2023-38408"`)
- `severity` `{string|null}` — `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, or `null`
- `score`    `{number|null}` — CVSS base score, or `null` if unavailable
- `summary`  `{string}` — English description truncated to 120 characters
- `url`      `{string}` — direct link to the NVD entry

**Notes:**
- The query uses a CPE 2.3 match string built from the `cpe` parameter and `version`, targeting
  the NVD `cpeName` search endpoint. This is more precise than a keyword search and avoids
  false-positive matches from unrelated products that share a common name.
- CVSS v3.1 metrics are preferred; the function falls back to CVSS v2 if v3.1 data is absent.
- Network errors and JSON parse failures both resolve to an empty array rather than rejecting, so
  a single unreachable NVD endpoint does not abort the entire scan.
- Results are sorted by `score` descending (highest severity first). Entries with no score sort to
  the bottom.

**Example:**
```js
const cves = await queryCVEs("openbsd:openssh", "8.9p1");
// => [{ id: "CVE-2023-38408", severity: "CRITICAL", score: 9.8, summary: "...", url: "..." }]
```

---

## vulnscan.js — Entry Point

**CLI syntax:**
```
node src/vulnscan.js <scan.json>
node src/vulnscan.js --help
```

**Argument parsing:**
- `process.argv[2]` (`scanFile`) — path to the scan JSON to enrich
- `--help` / `-h` — print usage and exit 0; exit 1 if `scanFile` is also absent

**Behaviour:**
1. If `--help`, `-h`, or no `scanFile` argument is present, prints usage to stdout and exits.
2. Reads and parses the scan JSON synchronously.
3. For every host, iterates all open port entries and calls `parseBanners()` on each.
4. For each matched software version, calls `queryCVEs()`. Pauses 6 seconds after every 5
   requests to stay within the NVD unauthenticated rate limit (~5 req/30 s).
5. If any CVEs are found for a port, writes `portInfo.cves = [{ software, cves[] }]` into the
   in-memory scan object.
6. Attempts to write the enriched JSON back to the original `scanFile`. If the write fails with
   `EACCES` (permission denied), saves to `$HOME/<basename>` instead and prints the fallback path.

**Notes:**
- Runs entirely as top-level `await` in ESM; no explicit `main()` wrapper.
- The rate-limit counter (`queriesMade`) is global across all hosts and ports so the pause
  interval is consistent regardless of how many ports are processed per host.
- A port entry receives a `cves` field only if at least one software match produced at least one
  CVE. Ports with unrecognised software, or recognised software with no known CVEs, are left
  unchanged.
- The script modifies the scan JSON in place. Run on a copy if you want to preserve the
  unenriched version.

---

*Documentation written with assistance from [Claude](https://claude.ai) — used for documentation, package understanding, and packet crafting reference.*
