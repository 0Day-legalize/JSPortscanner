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

## randomPrivateIP()

**Purpose:**
Generates a random IP address within one of the three RFC 1918 private ranges. Used exclusively as
the spoofed source address in decoy SYN packets. Private addresses are chosen because they are
non-routable on the public internet (no one can actually receive a reply to them) and because they
look like traffic originating from inside the target's own network, which is more disorienting to a
defender than an obviously external IP.

**Parameters:** none

**Returns:** `{string}` — dotted-decimal IP string, e.g. `"10.42.7.183"`

**Notes:**
- The last octet is constrained to `1–253` (`1 + rand(253)`) to avoid the `.0` network address and
  `.255` broadcast address.
- The three ranges covered: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. Each is selected with
  equal (1-in-3) probability regardless of range size.

**Example:**
```js
const fakeSource = randomPrivateIP();
// => "192.168.14.201"
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
Constructs a complete 40-byte raw IP/TCP packet with the SYN flag set and a spoofed source address.
This packet is handed directly to the raw socket and sent without kernel TCP stack involvement,
which is what allows the source IP to be anything we choose.

**Parameters:**
- `srcIP`   `{string}` — spoofed source IP in dotted-decimal, e.g. `"192.168.1.5"` (typically from `randomPrivateIP()`)
- `dstIP`   `{string}` — real destination IP in dotted-decimal
- `srcPort` `{number}` — source port number written into the TCP header (1024–65535)
- `dstPort` `{number}` — destination port number for the SYN

**Returns:** `{Buffer}` — 40-byte packet ready to pass to `socket.send()`

**Notes:**
- **IP ID** is randomised on every call. A fixed or incrementing ID is an easy scanner fingerprint.
- **TTL** is randomised in the range 64–127, covering both Linux (64) and Windows (128) defaults, so
  packets do not share a single identifiable hop count.
- **TCP sequence number** is randomised. A predictable ISN is a fingerprint even in decoy traffic.
- **Window size** is randomised with a minimum of `0x1000` (4096) bytes to avoid zero-window packets
  being filtered by network gear.
- The IP checksum is computed over bytes 0–19 only. The TCP checksum requires a 12-byte
  pseudo-header (source IP, dest IP, zero byte, protocol 6, TCP length) prepended to the TCP
  segment before checksumming — this is the RFC 793 pseudo-header construction.
- The packet has no TCP options and no payload, so the IP total length is always exactly 40 and the
  TCP data offset is always 5 (20 bytes / 4).

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
Each decoy has a different random private source IP, making it look like multiple hosts (potentially
inside the target's own network) are all connecting at the same time.

**Parameters:**
- `dstIP`   `{string}` — resolved destination IP in dotted-decimal
- `dstPort` `{number}` — port number being probed

**Returns:** `{void}`

**Notes:**
- Decoys are fired-and-forgotten; the `send` callback is a no-op. We do not wait for
  acknowledgement because decoy SYNs will never be acknowledged (the spoofed source IPs cannot
  receive packets).
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

## tryTCPConnect(host, port, useTLS, hostname)

**Purpose:**
Opens a single TCP or TLS connection to the target and attempts to elicit a banner by sending an
HTTP/1.1 HEAD request. Returns whatever the service sends back, or null if the connection could not
be established.

**Parameters:**
- `host`     `{string}`  — IP address or hostname to connect to
- `port`     `{number}`  — destination port (1–65535)
- `useTLS`   `{boolean}` — when `true`, wraps the socket in TLS (`rejectUnauthorized: false` so
  self-signed certificates do not abort the connection)
- `hostname` `{string}`  — value used in the TLS `servername` field and the HTTP `Host` header;
  typically a PTR-resolved hostname so traffic resembles a real browser session

**Returns:** `{Promise<string|null>}`
- Response text (possibly empty string `""`) if the connection was established
- `null` if the connection was refused, reset, or timed out without connecting

**Notes:**
- `rejectUnauthorized: false` is intentional — scanning infrastructure often uses self-signed certs
  and we care about open/closed state, not certificate validity.
- `servername` is omitted from the TLS options when `hostname` is a bare IP address. The TLS SNI
  extension requires a DNS name; passing an IP as `servername` causes handshake failures on some
  implementations.
- The HTTP HEAD probe is opportunistic. Services that do not speak HTTP will respond with their own
  banner (e.g. SSH, FTP, SMTP) or nothing at all. In both cases `responseData` holds whatever
  bytes arrived.
- `socket.destroy()` on timeout triggers the `close` event, which resolves the promise. Without
  this chain the promise would hang indefinitely after a timeout.
- The `error` event only resolves the promise with `null` when `isConnected` is false. If an error
  fires after connect (e.g. mid-transfer RST) the `close` event resolves it instead with whatever
  data arrived — partial responses are still useful.

**Example:**
```js
const data = await tryTCPConnect("10.0.0.1", 443, true, "example.com");
if (data !== null) console.log("443 is open, got:", data.slice(0, 80));
```

---

## scanTCPPort(host, port, hostname)

**Purpose:**
Orchestrates the TLS-first probe strategy for a single port. TLS is attempted first because
connecting with plain TCP to a TLS port produces no useful data (the server responds with a TLS
`ClientHello` requirement, not a plaintext banner). By trying TLS first we get banner data from
HTTPS, SMTPS, and similar services without a wasted round-trip.

**Parameters:**
- `host`     `{string}` — IP address or hostname
- `port`     `{number}` — TCP port number to scan
- `hostname` `{string}` — (optional, defaults to `host`) PTR-resolved hostname passed through to
  `tryTCPConnect` for use in TLS SNI and the HTTP `Host` header

**Returns:** `{Promise<{proto: string, port: number, data: string|null}>}`
- `proto` — `"TLS"` if the TLS probe succeeded, `"TCP"` otherwise
- `port`  — echoed back for result aggregation
- `data`  — response text, or `null` if the port is closed

**Notes:**
- Ports in `PLAINTEXT_PORTS` skip TLS entirely. Attempting a TLS handshake against port 22 (SSH) or
  port 3306 (MySQL) would always fail and waste two connection slots.
- If TLS returns `null` and plain TCP is attempted, the final result uses proto `"TCP"` regardless
  of whether plain TCP also returns null. The proto field reflects what protocol actually got data,
  not what was tried last.
- Both probes are never run simultaneously. The plain TCP probe only starts if TLS returned null,
  avoiding two simultaneous connections to the same port.

**Example:**
```js
const result = await scanTCPPort("192.168.1.1", 443);
// => { proto: "TLS", port: 443, data: "HTTP/1.1 200 OK\r\n..." }
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

## scanHost(host, firstPort, lastPort)

**Purpose:**
Scans the full port range on one host, running TCP and UDP pools concurrently, and returns a
structured result object. This is the main per-host orchestration function. It exists as a named
function (rather than inline code) so that `runPool` at the host level can parallelise across
multiple targets.

**Parameters:**
- `host`      `{string}` — IP address or hostname to scan
- `firstPort` `{number}` — start of port range, inclusive
- `lastPort`  `{number}` — end of port range, inclusive

**Returns:** `{Promise<{host: string, ports: object, scannedAt: string}>}`
- `host`      — echoed input value
- `ports`     — plain object keyed by port number string, values are proto/banner strings, e.g.
  `{ "22": "TCP: SSH-2.0-OpenSSH_8.9", "443": "TLS" }`; ports are sorted ascending before the
  object is built
- `scannedAt` — ISO 8601 timestamp of when the scan completed

**Notes:**
- DNS resolution happens twice per host: once with `dns.lookup()` to get the IP for decoy sending,
  and once with `dns.reverse()` to get the PTR hostname for use in TLS SNI and the HTTP `Host`
  header. Both lookups are silently skipped on failure.
- If DNS lookup fails the host is scanned normally but decoys are disabled (silently). The catch
  block intentionally has no body.
- `onPortResult` is an inner function rather than a top-level one because it closes over
  `openPorts` and `host`, keeping the per-host result accumulation self-contained.
- The `\r\x1b[K` escape sequence in `onPortResult` erases the rolling progress line that quiet
  hosts write, so open-port lines are never visually corrupted by the progress counter.
- TCP and UDP pools run with `Promise.all`, meaning both start simultaneously and `scanHost`
  resolves only after both finish. This halves elapsed time compared to running TCP then UDP
  sequentially.
- Results are sorted after both pools complete so the final JSON is deterministically ordered
  regardless of which port resolved first.

**Example:**
```js
const result = await scanHost("192.168.1.1", 1, 1024);
// => { host: "192.168.1.1", ports: { "22": "TCP: SSH-2.0-OpenSSH_8.9", "80": "TCP: HTTP/1.1 200 OK" }, scannedAt: "2026-05-29T..." }
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
- `scanner.js` calls it with `J_MIN = 10` / `J_MAX = 250`. `credtest.js` calls it with
  `JITTER_MIN_MS = 500` / `JITTER_MAX_MS = 2000`. The wider range in credtest keeps login
  attempt rates below account lockout thresholds.

**Example:**
```js
await jitter(10, 250);   // scanner — fast, wide
await jitter(500, 2000); // credtest — slow, wide
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
- `ports` `{object}` — port map from scan JSON, e.g. `{ "22": "TCP: SSH-2.0-OpenSSH_5.3", "23": "TCP" }`

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
- FTP banner matching checks ports whose value starts with `"TCP: 220"` against `FTP_HONEYPOT_BANNERS`
  using a substring search — covers banners where the scanner captured more text than the list entry.
- `TPOT_MATCH_MIN` (default 4) means at least 4 ports from the T-Pot set must be open before the
  combination is flagged, reducing false positives on hosts that legitimately run web + SSH + FTP.
- `SUSPICIOUS_THRESHOLD` (default 6) is intentionally low — real servers rarely expose that many
  services simultaneously.

**Example:**
```js
checkHost({ "22": "TCP: SSH-2.0-OpenSSH_5.3", "23": "TCP" });
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
inspecting the banner string from the scan for TLS or HTTP indicators.

**Parameters:**
- `portNum`   `{number}` — the port number key from the scan JSON
- `portValue` `{string}` — the proto/banner string stored for that port (e.g. `"TCP: SSH-2.0-OpenSSH_8.9"`, `"TLS"`)

**Returns:** `{"ssh"|"ftp"|"http"|"https"|null}` — service type, or `null` if the port is not a recognised testable service

**Notes:**
- Port-number matching takes priority over banner matching. If port 22 runs an HTTP server (unusual
  but possible), it will be treated as SSH. This is intentional — port numbers are the most reliable
  classification signal for the common case.
- Banner fallback (`portValue.startsWith("TLS")` → `"https"`) catches HTTPS running on non-standard
  ports (e.g. 8443 is covered by `HTTPS_PORTS`, but 9443 would fall through to the banner check).
- `null` is returned for UDP-only ports, database ports, or any service the tool does not support.
  `testHost` skips `null` entries entirely.

**Example:**
```js
detectService(22,   "TCP: SSH-2.0-OpenSSH_8.9")  // => "ssh"
detectService(443,  "TLS")                        // => "https"
detectService(8080, "TCP: HTTP/1.1 200 OK")       // => "http"
detectService(9999, "TLS: ...")                   // => "https" (banner fallback)
detectService(3306, "TCP: ...")                   // => null    (MySQL — not tested)
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
- `ports`       `{object}` — port map from scan JSON, e.g. `{ "22": "TCP: SSH-2.0-OpenSSH_8.9", "80": "TCP: HTTP/1.1 200 OK" }`
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
const { found, honeypot } = await testHost("10.0.0.5", { "22": "TCP", "80": "TCP: HTTP/1.1 200 OK" }, creds);
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

*Documentation written with assistance from [Claude](https://claude.ai) — used for documentation, package understanding, and packet crafting reference.*
