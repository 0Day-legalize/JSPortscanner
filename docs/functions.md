# Function Reference

All functions are defined in `src/scanner.js`. They are listed in the order they appear in the file.

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

## tryTCPConnect(host, port, useTLS)

**Purpose:**
Opens a single TCP or TLS connection to the target and attempts to elicit a banner by sending an
HTTP HEAD request. Returns whatever the service sends back, or null if the connection could not be
established.

**Parameters:**
- `host`   `{string}`  — IP address or hostname to connect to
- `port`   `{number}`  — destination port (1–65535)
- `useTLS` `{boolean}` — when `true`, wraps the socket in TLS (`rejectUnauthorized: false` so
  self-signed certificates do not abort the connection)

**Returns:** `{Promise<string|null>}`
- Response text (possibly empty string `""`) if the connection was established
- `null` if the connection was refused, reset, or timed out without connecting

**Notes:**
- `rejectUnauthorized: false` is intentional — scanning infrastructure often uses self-signed certs
  and we care about open/closed state, not certificate validity.
- The HTTP HEAD probe is opportunistic. Services that do not speak HTTP will respond with their own
  banner (e.g. SSH, FTP, SMTP) or nothing at all. In both cases `responseData` holds whatever
  bytes arrived.
- `socket.destroy()` on timeout triggers the `close` event, which resolves the promise. Without
  this chain the promise would hang indefinitely after a timeout.
- The `error` event only resolves the promise with `null` when `isConnected` is false. If an error
  fires after connect (e.g. mid-transfer RST) the `close` event resolves it instead with whatever
  data arrived — partial responses are still useful.
- `localPort` is set via `randomSourcePort()` on every call, not once per host.

**Example:**
```js
const data = await tryTCPConnect("10.0.0.1", 443, true);
if (data !== null) console.log("443 is open, got:", data.slice(0, 80));
```

---

## scanTCPPort(host, port)

**Purpose:**
Orchestrates the TLS-first probe strategy for a single port. TLS is attempted first because
connecting with plain TCP to a TLS port produces no useful data (the server responds with a TLS
`ClientHello` requirement, not a plaintext banner). By trying TLS first we get banner data from
HTTPS, SMTPS, and similar services without a wasted round-trip.

**Parameters:**
- `host` `{string}` — IP address or hostname
- `port` `{number}` — TCP port number to scan

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

**Returns:** `{Promise<{host: string, ports: Array, scannedAt: string}>}`
- `host`      — echoed input value
- `ports`     — array of open-port objects sorted ascending by port then proto, each:
  `{ port: number, proto: string, state: "open", banner: string[]|null }`
- `scannedAt` — ISO 8601 timestamp of when the scan completed

**Notes:**
- DNS resolution happens once per host at the top of this function, not once per port. The resolved
  IP is used only for decoy sending — `scanTCPPort` and `scanUDPPort` still use the original `host`
  string so that TLS SNI works correctly when `host` is a hostname.
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
// => { host: "192.168.1.1", ports: [{ port: 22, proto: "TCP", state: "open", banner: ["SSH-2.0-OpenSSH_8.9"] }], scannedAt: "2026-05-29T..." }
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
