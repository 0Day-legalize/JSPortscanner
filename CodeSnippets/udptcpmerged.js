import net   from "node:net";
import tls   from "node:tls";
import dgram from "node:dgram";
import fs    from "node:fs";
import path  from "node:path";

/** Maximum number of TCP connections open at the same time per host */
const MAX_TCP_CONNECTIONS = 50;

/** Maximum number of UDP connections open at the same time per host */
const MAX_UDP_CONNECTIONS = 20;

/** How many hosts to scan in parallel */
const MAX_HOST_WORKERS = 50;

/** How long (ms) to wait for a socket response before giving up */
const SOCKET_TIMEOUT_MS = 2000;

// ─── TCP / TLS ────────────────────────────────────────────────────────────────

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
        const socket = useTLS
            ? tls.connect({ host, port, rejectUnauthorized: false })
            : net.createConnection({ host, port });

        let responseData = "";
        let isConnected  = false;

        // Kill the socket if nothing happens within the timeout window
        socket.setTimeout(SOCKET_TIMEOUT_MS);

        // Once connected, send a minimal HTTP request to provoke a banner response
        socket.on(useTLS ? "secureConnect" : "connect", () => {
            isConnected = true;
            socket.write("HEAD / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
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

    // Build one task per port for TCP and one for UDP
    const tcpTasks = portList.map((port) => async () => scanTCPPort(host, port));
    const udpTasks = portList.map((port) => async () => scanUDPPort(host, port));

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

// Default output filename includes a timestamp so runs never overwrite each other
const outputPath = outputFile || `scan_${Date.now()}.json`;

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
