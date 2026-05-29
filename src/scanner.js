import net                from "node:net";
import tls                from "node:tls";
import dgram              from "node:dgram";
import fs                 from "node:fs";
import path               from "node:path";
import dns                from "node:dns/promises";
import { createRequire }  from "node:module";

const require = createRequire(import.meta.url);

// raw-socket requires root — load it optionally so the scanner still works without it
let raw = null;
try { raw = require("raw-socket"); } catch { /* no root or package not installed */ }

/** Maximum number of TCP connections open at the same time per host */
const MAX_TCP_CONNECTIONS = 50;

/** Maximum number of UDP connections open at the same time per host */
const MAX_UDP_CONNECTIONS = 20;

/** How many hosts to scan in parallel */
const MAX_HOST_WORKERS = 50;

/** How long (ms) to wait for a socket response before giving up */
const SOCKET_TIMEOUT_MS = 2000;

/** Minimum random delay (ms) injected before each port probe */
const JITTER_MIN_MS = 10;

/** Maximum random delay (ms) injected before each port probe */
const JITTER_MAX_MS = 250;

/** Ports that never speak TLS natively — skip the TLS probe and go straight to plain TCP */
const PLAINTEXT_PORTS = new Set([21, 22, 23, 25, 53, 3306, 5432, 6379, 27017]);

/** Number of spoofed decoy SYN packets sent before each real TCP probe */
const DECOY_COUNT = 4;

// ─── Jitter ───────────────────────────────────────────────────────────────────

/**
 * Waits for a random number of milliseconds between JITTER_MIN_MS and JITTER_MAX_MS.
 * Breaks up the uniform timing pattern that IDS systems use to fingerprint scanners.
 *
 * @returns {Promise<void>}
 */
function jitter() {
    const delay = Math.floor(Math.random() * (JITTER_MAX_MS - JITTER_MIN_MS + 1)) + JITTER_MIN_MS;
    return new Promise((resolve) => setTimeout(resolve, delay));
}

// ─── Decoy IPs ────────────────────────────────────────────────────────────────

/**
 * Returns a random IP address from one of the three RFC1918 private ranges.
 * Private IPs are non-routable on the internet so they can never be traced
 * back to a real machine, and confuse defenders into thinking traffic came
 * from inside their own network.
 *
 * Ranges:
 *   10.0.0.0/8       (16 million addresses)
 *   172.16.0.0/12    (1 million addresses)
 *   192.168.0.0/16   (65k addresses)
 *
 * @returns {string} Dotted-decimal private IP string
 */
function randomPrivateIP() {
    const rand  = (n) => Math.floor(Math.random() * n);
    const pick  = rand(3);
    if (pick === 0) return `10.${rand(256)}.${rand(256)}.${1 + rand(253)}`;
    if (pick === 1) return `172.${16 + rand(16)}.${rand(256)}.${1 + rand(253)}`;
    return `192.168.${rand(256)}.${1 + rand(253)}`;
}

/**
 * Calculates the one's complement checksum used in IP and TCP headers.
 * Sums all 16-bit words in the buffer and folds the carry bits back in.
 *
 * @param {Buffer} buf - Raw bytes to checksum
 * @returns {number} 16-bit checksum value
 */
function oneComplementChecksum(buf) {
    let sum = 0;
    for (let i = 0; i < buf.length; i += 2) {
        sum += (i + 1 < buf.length) ? buf.readUInt16BE(i) : (buf[i] << 8);
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
}

/**
 * Builds a raw IP + TCP SYN packet with a spoofed source IP.
 * The packet is 40 bytes: 20 byte IP header + 20 byte TCP header, no payload.
 *
 * @param {string} srcIP   - Spoofed source IP address (private range)
 * @param {string} dstIP   - Real destination IP address
 * @param {number} srcPort - Random source port
 * @param {number} dstPort - Target destination port
 * @returns {Buffer} Complete raw packet ready to send
 */
function buildSynPacket(srcIP, dstIP, srcPort, dstPort) {
    const packet = Buffer.alloc(40);
    const src    = srcIP.split(".").map(Number);
    const dst    = dstIP.split(".").map(Number);

    // ── IP header (bytes 0–19) ────────────────────────────────────────────────
    packet[0] = 0x45;                                                // version=4, IHL=5
    packet[1] = 0x00;                                                // DSCP/ECN
    packet.writeUInt16BE(40, 2);                                     // total length
    packet.writeUInt16BE(Math.floor(Math.random() * 0xffff), 4);    // random ID
    packet.writeUInt16BE(0x4000, 6);                                 // DF flag, no fragment
    packet[8]  = 64 + Math.floor(Math.random() * 64);               // TTL 64–127
    packet[9]  = 6;                                                  // protocol = TCP
    packet.writeUInt16BE(0, 10);                                     // checksum placeholder
    packet[12] = src[0]; packet[13] = src[1]; packet[14] = src[2]; packet[15] = src[3];
    packet[16] = dst[0]; packet[17] = dst[1]; packet[18] = dst[2]; packet[19] = dst[3];
    packet.writeUInt16BE(oneComplementChecksum(packet.slice(0, 20)), 10); // IP checksum

    // ── TCP header (bytes 20–39) ──────────────────────────────────────────────
    packet.writeUInt16BE(srcPort, 20);                               // source port
    packet.writeUInt16BE(dstPort, 22);                               // dest port
    packet.writeUInt32BE(Math.floor(Math.random() * 0xffffffff) >>> 0, 24); // random seq
    packet.writeUInt32BE(0, 28);                                     // ack = 0
    packet[32] = 0x50;                                               // data offset = 5
    packet[33] = 0x02;                                               // SYN flag
    packet.writeUInt16BE(Math.floor(Math.random() * 0xffff) | 0x1000, 34); // window size
    packet.writeUInt16BE(0, 36);                                     // checksum placeholder
    packet.writeUInt16BE(0, 38);                                     // urgent pointer

    // TCP checksum needs a pseudo-header: src + dst + 0x00 + proto(6) + tcp_len(20)
    const pseudo = Buffer.alloc(12);
    pseudo[0] = src[0]; pseudo[1] = src[1]; pseudo[2] = src[2]; pseudo[3] = src[3];
    pseudo[4] = dst[0]; pseudo[5] = dst[1]; pseudo[6] = dst[2]; pseudo[7] = dst[3];
    pseudo[8]  = 0;
    pseudo[9]  = 6;
    pseudo.writeUInt16BE(20, 10);
    packet.writeUInt16BE(oneComplementChecksum(Buffer.concat([pseudo, packet.slice(20)])), 36);

    return packet;
}

/** Lazily created raw socket — reused across all decoy sends */
let rawSocket = null;

/**
 * Returns the shared raw socket, creating it on first call.
 * Returns null if raw-socket is unavailable or process lacks root.
 *
 * @returns {object|null}
 */
function getDecoySocket() {
    if (rawSocket) return rawSocket;
    if (!raw) return null;
    try {
        rawSocket = raw.createSocket({ protocol: raw.Protocol.None, addressFamily: raw.AddressFamily.IPv4 });
        // IP_HDRINCL tells the kernel we are providing the full IP header ourselves
        rawSocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL, Buffer.from([1, 0, 0, 0]), 4);
        return rawSocket;
    } catch {
        return null;
    }
}

/**
 * Fires DECOY_COUNT spoofed TCP SYN packets at dstIP:dstPort, each from a
 * random private source IP, before the real probe goes out.
 * Silently does nothing if raw-socket is unavailable or process is not root.
 *
 * @param {string} dstIP   - Resolved destination IP
 * @param {number} dstPort - Target port
 */
function sendDecoys(dstIP, dstPort) {
    const sock = getDecoySocket();
    if (!sock) return;
    for (let i = 0; i < DECOY_COUNT; i++) {
        const packet = buildSynPacket(randomPrivateIP(), dstIP, randomSourcePort(), dstPort);
        sock.send(packet, 0, packet.length, dstIP, () => {});
    }
}

// ─── TCP / TLS ────────────────────────────────────────────────────────────────

/**
 * Returns a random ephemeral source port (1024–65535).
 * Binding each connection to a different local port breaks the sequential
 * source-port pattern that IDS systems use to fingerprint scanners.
 *
 * @returns {number} Random port number between 1024 and 65535
 */
function randomSourcePort() {
    return Math.floor(Math.random() * (65535 - 1024 + 1)) + 1024;
}

/**
 * Builds a port list from firstPort to lastPort then randomly shuffles it
 * so the scan order is unpredictable and harder to detect.
 *
 * @param {number} firstPort - The lowest port number to include (e.g. 1)
 * @param {number} lastPort  - The highest port number to include (e.g. 1024)
 * @returns {number[]} Shuffled array of port numbers
 */
function shufflePorts(firstPort, lastPort) {
    const portList = [];
    for (let port = firstPort; port <= lastPort; port++) portList.push(port);

    // Fisher-Yates shuffle: walk backwards, swap each element with a random earlier one
    for (let index = portList.length - 1; index > 0; index--) {
        const swapIndex = Math.floor(Math.random() * (index + 1));
        [portList[index], portList[swapIndex]] = [portList[swapIndex], portList[index]];
    }
    return portList;
}

/**
 * Attempts a single TCP or TLS connection to host:port and returns any response data.
 * Sends a basic HTTP HEAD request once connected to try to grab a banner.
 *
 * @param {string}  host   - IP address or hostname to connect to
 * @param {number}  port   - Port number to connect to
 * @param {boolean} useTLS - If true, wraps the connection in TLS (HTTPS-style)
 * @returns {Promise<string|null>} Response text if connected, null if connection failed
 */
function tryTCPConnect(host, port, useTLS) {
    return new Promise((resolve) => {
        // Open either a plain TCP socket or a TLS-encrypted socket
        const localPort = randomSourcePort();
        const socket = useTLS
            ? tls.connect({ host, port, localPort, rejectUnauthorized: false })
            : net.createConnection({ host, port, localPort });

        let responseData = "";
        let isConnected  = false;

        // Kill the socket if nothing happens within the timeout window
        socket.setTimeout(SOCKET_TIMEOUT_MS);

        // Once connected, send a minimal HTTP request to provoke a banner response
        socket.on(useTLS ? "secureConnect" : "connect", () => {
            isConnected = true;
            socket.write("HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: Team Dangerous\r\nConnection: close\r\n\r\n");
        });

        // Collect any data the server sends back
        socket.on("data",    (chunk) => { responseData += chunk.toString("utf8"); });

        // Timeout fired — destroy the socket so the close event triggers
        socket.on("timeout", ()      => socket.destroy());

        // Connection refused or reset before we connected — port is closed
        socket.on("error",   ()      => { if (!isConnected) resolve(null); });

        // Socket fully closed — return whatever we collected (or null if never connected)
        socket.on("close",   ()      => resolve(isConnected ? responseData : null));
    });
}

/**
 * Scans a single TCP port by trying TLS first, then plain TCP.
 * TLS is tried first because a plain TCP attempt on a TLS port gives no useful data.
 *
 * @param {string} host - IP address or hostname to scan
 * @param {number} port - Port number to scan
 * @returns {Promise<{proto: string, port: number, data: string|null}>}
 */
async function scanTCPPort(host, port) {
    // Skip TLS entirely for ports known to speak plaintext
    if (PLAINTEXT_PORTS.has(port)) {
        const response = await tryTCPConnect(host, port, false);
        return { proto: "TCP", port, data: response };
    }

    const tlsResponse = await tryTCPConnect(host, port, true);

    // Only try plain TCP if TLS got nothing — avoids a double connection on TLS ports
    const tcpResponse = tlsResponse === null ? await tryTCPConnect(host, port, false) : null;

    const response = tlsResponse ?? tcpResponse;
    return { proto: tlsResponse === null ? "TCP" : "TLS", port, data: response };
}

// ─── UDP ──────────────────────────────────────────────────────────────────────

/**
 * Sends an empty UDP packet to host:port and waits for a response.
 * UDP has no handshake so silence usually means open|filtered (we can't tell which).
 * An ICMP port-unreachable error means the port is definitely closed.
 *
 * @param {string} host - IP address to probe
 * @param {number} port - UDP port number to probe
 * @returns {Promise<string|null>}
 *   - Response string if the service replied
 *   - "OPEN|FILTERED" if no reply within the timeout
 *   - null if the port is closed (ICMP unreachable)
 *   - "ERROR: ..." for unexpected socket errors
 */
function tryUDPConnect(host, port) {
    return new Promise((resolve) => {
        const socket   = dgram.createSocket("udp4");
        let isFinished = false;

        // Guard so we only resolve once even if multiple events fire
        function finish(result) {
            if (isFinished) return;
            isFinished = true;
            socket.close();
            resolve(result);
        }

        // No reply within the window — treat as open|filtered
        const timer = setTimeout(() => finish("OPEN|FILTERED"), SOCKET_TIMEOUT_MS);

        // The service sent something back — definitely open
        socket.on("message", (msg) => { clearTimeout(timer); finish(msg.toString("utf8")); });

        socket.on("error", (err) => {
            clearTimeout(timer);
            // ECONNREFUSED means the OS got an ICMP port-unreachable — port is closed
            finish(err.code === "ECONNREFUSED" ? null : `ERROR: ${err.message}`);
        });

        // Send an empty packet to trigger any response from the service
        const emptyPayload = Buffer.alloc(0);
        socket.send(emptyPayload, port, host, (err) => { if (err) { clearTimeout(timer); finish(null); } });
    });
}

/**
 * Wraps tryUDPConnect into the same shape as scanTCPPort for uniform handling.
 *
 * @param {string} host - IP address to scan
 * @param {number} port - UDP port number to scan
 * @returns {Promise<{proto: string, port: number, data: string|null}>}
 */
async function scanUDPPort(host, port) {
    const response = await tryUDPConnect(host, port);
    return { proto: "UDP", port, data: response };
}

// ─── Concurrency pool ─────────────────────────────────────────────────────────

/**
 * Runs an array of async tasks with a cap on how many run at the same time.
 * Think of it as a worker queue: workerLimit workers each grab the next task
 * as soon as they finish the previous one.
 *
 * @param {Array<() => Promise<any>>} taskList    - Array of zero-argument async functions
 * @param {number}                    workerLimit - Max tasks running simultaneously
 * @param {(result: any) => void}     onTaskDone  - Called with each task's return value
 * @returns {Promise<void>} Resolves when every task has finished
 */
async function runPool(taskList, workerLimit, onTaskDone) {
    let taskIndex = 0;

    // Each worker loops and grabs the next unstarted task until the list is empty
    async function worker() {
        while (taskIndex < taskList.length) {
            const result = await taskList[taskIndex++]();
            onTaskDone(result);
        }
    }

    // Spawn workerLimit workers (or fewer if the task list is shorter)
    await Promise.all(Array.from({ length: Math.min(workerLimit, taskList.length) }, worker));
}

// ─── Scan one host, return structured results ─────────────────────────────────

/**
 * Scans all ports in the given range on a single host, running TCP and UDP in parallel.
 * Ports are shuffled before scanning to avoid sequential-scan detection.
 * Only open ports are kept in the results.
 *
 * @param {string} host      - IP address or hostname to scan
 * @param {number} firstPort - Start of the port range (inclusive)
 * @param {number} lastPort  - End of the port range (inclusive)
 * @returns {Promise<{host: string, ports: Array, scannedAt: string}>}
 */
async function scanHost(host, firstPort, lastPort) {
    const portList  = shufflePorts(firstPort, lastPort);
    const openPorts = [];

    // Resolve hostname to IP once — raw socket needs a dotted-decimal address
    let resolvedIP = null;
    try {
        resolvedIP = /^\d+\.\d+\.\d+\.\d+$/.test(host)
            ? host
            : (await dns.lookup(host)).address;
    } catch { /* hostname unresolvable — decoys disabled for this host */ }

    /**
     * Receives a single port result and keeps it only if the port is open.
     *
     * @param {{proto: string, port: number, data: string|null}} result
     */
    function onPortResult({ proto, port, data }) {
        // Null means closed; "OPEN|FILTERED" means UDP silence — skip both
        const isOpen = data !== null && data !== "OPEN|FILTERED";
        if (!isOpen) return;

        // First line of the response is the most useful part of a banner
        const banner = typeof data === "string" && data.trim() ? data.trim().split(/\r?\n/) : null;

        // Clear the scanning progress line then print the hit on its own line
        process.stdout.write("\r\x1b[K");
        console.log(`  OPEN     ${host}:${port} [${proto}]${banner ? " " + banner[0] : ""}`);

        openPorts.push({ port, proto, state: "open", banner });
    }

    // Build one task per port for TCP and one for UDP — jitter + decoys fire before each probe
    const tcpTasks = portList.map((port) => async () => {
        await jitter();
        if (resolvedIP) sendDecoys(resolvedIP, port);
        return scanTCPPort(host, port);
    });
    const udpTasks = portList.map((port) => async () => { await jitter(); return scanUDPPort(host, port); });

    // Run TCP and UDP pools simultaneously
    await Promise.all([
        runPool(tcpTasks, MAX_TCP_CONNECTIONS, onPortResult),
        runPool(udpTasks, MAX_UDP_CONNECTIONS, onPortResult),
    ]);

    // Sort by port number, then protocol name, for a clean JSON output
    openPorts.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));

    return { host, ports: openPorts, scannedAt: new Date().toISOString() };
}

// ─── Parse IP list file ───────────────────────────────────────────────────────

/**
 * Expands a CIDR block (e.g. 192.168.1.0/24) into individual host IP strings.
 * Skips the network address (.0) and broadcast address (.255).
 * Supports prefix lengths from /16 to /32.
 *
 * @param {string} cidr - CIDR notation string, e.g. "10.0.0.0/24"
 * @returns {string[]} Array of individual IP address strings
 */
function expandCIDR(cidr) {
    const [baseIP, prefixLength] = cidr.split("/");
    const bits = Number.parseInt(prefixLength, 10);
    if (bits < 16 || bits > 32) throw new Error(`CIDR /${bits} not supported (use /16–/32)`);

    // Convert the dotted-decimal base IP into a single 32-bit integer
    const octets  = baseIP.split(".").map(Number);
    const baseInt = (octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]) >>> 0;

    // Total addresses in the block = 2^(32 - prefix). Subtract 2 for network + broadcast.
    const hostCount = 1 << (32 - bits);
    const hostList  = [];

    for (let offset = 1; offset < hostCount - 1; offset++) {
        const ipInt = (baseInt + offset) >>> 0;
        // Convert 32-bit integer back to dotted-decimal
        hostList.push(`${ipInt >>> 24}.${(ipInt >>> 16) & 0xff}.${(ipInt >>> 8) & 0xff}.${ipInt & 0xff}`);
    }
    return hostList;
}

/**
 * Reads a target file and returns a flat list of hosts to scan.
 * Each line can be a plain IP, a hostname, or a CIDR block.
 * Lines starting with # and blank lines are ignored.
 *
 * @param {string} filePath - Path to the targets file
 * @returns {string[]} Flat array of IP/hostname strings ready to scan
 */
function parseTargetFile(filePath) {
    const fileContent = fs.readFileSync(filePath, "utf8");
    const hostList    = [];

    for (const rawLine of fileContent.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;

        // CIDR blocks (contain a "/") get expanded to individual IPs
        if (line.includes("/")) {
            hostList.push(...expandCIDR(line));
        } else {
            hostList.push(line);
        }
    }
    return hostList;
}

// ─── Entry point ──────────────────────────────────────────────────────────────
// Usage: node udptcpmerged.js <targets.txt> <start-port> <end-port> [output.json]

const [targetFile, firstPortArg, lastPortArg, outputFile] = process.argv.slice(2);

if (!targetFile || !firstPortArg || !lastPortArg) {
    console.error("Usage: node udptcpmerged.js <targets.txt> <start-port> <end-port> [output.json]");
    console.error("Example: node udptcpmerged.js targets.txt 1 1024 results.json");
    process.exit(1);
}

const firstPort  = Number.parseInt(firstPortArg, 10);
const lastPort   = Number.parseInt(lastPortArg, 10);

if (process.getuid() !== 0) {
    console.error("Error: must be run as root (sudo) for raw socket decoy support.");
    process.exit(1);
}

// Default output goes to scans/ folder, timestamped so runs never overwrite each other
const now = new Date();

const timestamp =
    `${String(now.getDate()).padStart(2, "0")}.` +
    `${String(now.getMonth() + 1).padStart(2, "0")}.` +
    `${now.getFullYear()}T` +
    `${String(now.getHours()).padStart(2, "0")}:` +
    `${String(now.getMinutes()).padStart(2, "0")}`;

const outputPath = outputFile || `scan_${timestamp}.json`;

// Accept either a path to a targets file or a direct host/CIDR string
const hostList = fs.existsSync(targetFile)
    ? parseTargetFile(targetFile)
    : targetFile.includes("/") ? expandCIDR(targetFile) : [targetFile];
console.log(`Scanning ${hostList.length} host(s), ports ${firstPort}–${lastPort}\n`);

const scanResults  = [];
let hostsCompleted = 0;

const hostTasks = hostList.map((host) => async () => {
    const hostResult = await scanHost(host, firstPort, lastPort);

    // Only store hosts that have at least one open port
    if (hostResult.ports.length > 0) scanResults.push(hostResult);

    hostsCompleted++;

    if (hostResult.ports.length > 0) {
        // Print a dedicated line for hosts with findings
        console.log(`[${hostsCompleted}/${hostList.length}] ${host} — ${hostResult.ports.length} open`);
    } else {
        // Overwrite the same line for quiet hosts to avoid flooding the terminal
        process.stdout.write(`\r[${hostsCompleted}/${hostList.length}] scanning...`);
    }

    // Write after every host so partial results survive an early exit
    fs.writeFileSync(outputPath, JSON.stringify(scanResults, null, 2), "utf8");
});

await runPool(hostTasks, MAX_HOST_WORKERS, () => {});

console.log(`\nResults saved to ${path.resolve(outputPath)}`);
