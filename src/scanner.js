import net               from "node:net";
import tls               from "node:tls";
import dgram             from "node:dgram";
import fs                from "node:fs";
import path              from "node:path";
import dns               from "node:dns/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

let raw = null;
try { raw = require("raw-socket"); } catch {}

// --- config ---

const cfg = JSON.parse(fs.readFileSync(new URL("../config/settings.json", import.meta.url), "utf8")).scanner;

const MAX_TCP  = cfg.maxTCPConnections;
const MAX_UDP  = cfg.maxUDPConnections;
const MAX_HOST = cfg.maxHostWorkers;
const TIMEOUT  = cfg.socketTimeoutMs;
const J_MIN    = cfg.jitterMinMs;
const J_MAX    = cfg.jitterMaxMs;
const DECOYS   = cfg.decoyCount;
const PLAIN    = new Set(cfg.plaintextPorts);

// --- obfuscation helpers ---

const rand = (n) => Math.floor(Math.random() * n);

function jitter() {
    return new Promise(r => setTimeout(r, rand(J_MAX - J_MIN + 1) + J_MIN));
}

function randomSourcePort() {
    return rand(65535 - 1024 + 1) + 1024;
}

function shufflePorts(first, last) {
    const list = Array.from({ length: last - first + 1 }, (_, i) => first + i);
    for (let i = list.length - 1; i > 0; i--) {
        const j = rand(i + 1);
        [list[i], list[j]] = [list[j], list[i]];
    }
    return list;
}

async function runPool(tasks, limit, onDone) {
    let i = 0;
    const worker = async () => {
        while (i < tasks.length) onDone(await tasks[i++]());
    };
    await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
}

// --- obfuscation decoy IPs ---

function randomPrivateIP() {
    const pick = rand(3);
    if (pick === 0) return `10.${rand(256)}.${rand(256)}.${1 + rand(253)}`;
    if (pick === 1) return `172.${16 + rand(16)}.${rand(256)}.${1 + rand(253)}`;
    return `192.168.${rand(256)}.${1 + rand(253)}`;
}

// one's complement checksum per RFC 791
function checksum(buf) {
    let sum = 0;
    for (let i = 0; i < buf.length; i += 2)
        sum += (i + 1 < buf.length) ? buf.readUInt16BE(i) : (buf[i] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
}

function buildSynPacket(srcIP, dstIP, srcPort, dstPort) {
    // 40 bytes total: 20 IP header + 20 TCP header, no payload
    const pkt = Buffer.alloc(40);
    const src = srcIP.split(".").map(Number);
    const dst = dstIP.split(".").map(Number);

    // ── IP header (bytes 0–19) ──────────────────────────────────────
    pkt[0] = 0x45;                        // version=4, IHL=5 (20 byte header)
    pkt[1] = 0x00;                        // DSCP/ECN — default, no QoS
    pkt.writeUInt16BE(40, 2);             // total packet length (IP + TCP)
    pkt.writeUInt16BE(rand(0xffff), 4);   // random ID — avoids fingerprinting
    pkt.writeUInt16BE(0x4000, 6);         // DF flag set, fragment offset=0
    pkt[8] = 64 + rand(64);              // TTL randomised 64–127 — breaks OS detection
    pkt[9] = 6;                           // protocol=TCP
    pkt.writeUInt16BE(0, 10);             // checksum placeholder (filled below)
    pkt[12]=src[0]; pkt[13]=src[1]; pkt[14]=src[2]; pkt[15]=src[3]; // spoofed source IP
    pkt[16]=dst[0]; pkt[17]=dst[1]; pkt[18]=dst[2]; pkt[19]=dst[3]; // real destination IP
    pkt.writeUInt16BE(checksum(pkt.slice(0, 20)), 10); // IP header checksum

    // ── TCP header (bytes 20–39) ────────────────────────────────────
    pkt.writeUInt16BE(srcPort, 20);                    // source port (random)
    pkt.writeUInt16BE(dstPort, 22);                    // destination port
    pkt.writeUInt32BE(rand(0xffffffff) >>> 0, 24);     // random sequence number
    pkt.writeUInt32BE(0, 28);                          // ack=0 (SYN has no ack)
    pkt[32] = 0x50;                                    // data offset=5 (20 byte header)
    pkt[33] = 0x02;                                    // flags: SYN only
    pkt.writeUInt16BE(rand(0xffff) | 0x1000, 34);      // random window size
    pkt.writeUInt16BE(0, 36);                          // checksum placeholder (filled below)
    pkt.writeUInt16BE(0, 38);                          // urgent pointer=0

    // ── TCP checksum — requires pseudo header (RFC 793) ────────────
    // Pseudo header = src IP + dst IP + zero byte + protocol + TCP length
    // It is not sent on the wire — only used for checksum calculation
    const pseudo = Buffer.alloc(12);
    pseudo[0]=src[0]; pseudo[1]=src[1]; pseudo[2]=src[2]; pseudo[3]=src[3];
    pseudo[4]=dst[0]; pseudo[5]=dst[1]; pseudo[6]=dst[2]; pseudo[7]=dst[3];
    pseudo[8]=0; pseudo[9]=6;            // zero byte + protocol=TCP
    pseudo.writeUInt16BE(20, 10);        // TCP segment length (header only, no payload)
    pkt.writeUInt16BE(checksum(Buffer.concat([pseudo, pkt.slice(20)])), 36);

    return pkt;
}

let rawSocket = null;

function getDecoySocket() {
    if (rawSocket) return rawSocket;
    if (!raw) return null;
    try {
        rawSocket = raw.createSocket({ protocol: raw.Protocol.None, addressFamily: raw.AddressFamily.IPv4 });
        rawSocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL, Buffer.from([1, 0, 0, 0]), 4);
        return rawSocket;
    } catch { return null; }
}

function sendDecoys(dstIP, dstPort) {
    const sock = getDecoySocket();
    if (!sock) return;
    for (let i = 0; i < DECOYS; i++) {
        const pkt = buildSynPacket(randomPrivateIP(), dstIP, randomSourcePort(), dstPort);
        sock.send(pkt, 0, pkt.length, dstIP, () => {});
    }
}

// --- port scanning + banner grabbing ---

function tryTCPConnect(host, port, useTLS, hostname) {
    return new Promise((resolve) => {
        // servername must be a hostname, not an IP — skip it if no PTR record was found
        const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
        const socket = useTLS
            ? tls.connect({ host, port, rejectUnauthorized: false, ...(isIP ? {} : { servername: hostname }) })
            : net.createConnection({ host, port });

        let data = "";
        let connected = false;

        socket.setTimeout(TIMEOUT);

        socket.on(useTLS ? "secureConnect" : "connect", () => {
            connected = true;
            // banner grab — send HTTP HEAD to provoke a response from web services
            socket.write(
                `HEAD / HTTP/1.1\r\n` +
                `Host: ${hostname}\r\n` +
                `User-Agent: Team Dangerous\r\n` +
                `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n` +
                `Accept-Language: en-US,en;q=0.5\r\n` +
                `Accept-Encoding: gzip, deflate\r\n` +
                `Connection: close\r\n\r\n`
            );
        });

        socket.on("data",    (chunk) => { data += chunk.toString("utf8"); });
        socket.on("timeout", ()      => socket.destroy());
        socket.on("error",   ()      => { if (!connected) resolve(null); });
        socket.on("close",   ()      => resolve(connected ? data : null));
    });
}

async function scanTCPPort(host, port, hostname = host) {
    if (PLAIN.has(port)) {
        const res = await tryTCPConnect(host, port, false, hostname);
        return { proto: "TCP", port, data: res };
    }

    const tlsRes = await tryTCPConnect(host, port, true, hostname);
    const tcpRes = tlsRes === null ? await tryTCPConnect(host, port, false, hostname) : null;
    const res    = tlsRes ?? tcpRes;

    return { proto: tlsRes === null ? "TCP" : "TLS", port, data: res };
}

// --- udp port scanning ---

function tryUDPConnect(host, port) {
    return new Promise((resolve) => {
        const socket = dgram.createSocket("udp4");
        let done = false;

        // guard against multiple events resolving the same promise
        function finish(result) {
            if (done) return;
            done = true;
            socket.close();
            resolve(result);
        }

        const timer = setTimeout(() => finish("OPEN|FILTERED"), TIMEOUT);

        socket.on("message", (msg) => { clearTimeout(timer); finish(msg.toString("utf8")); });
        socket.on("error", (err) => {
            clearTimeout(timer);
            // ECONNREFUSED = ICMP port unreachable = definitely closed
            finish(err.code === "ECONNREFUSED" ? null : `ERROR: ${err.message}`);
        });

        socket.send(Buffer.alloc(0), port, host, (err) => {
            if (err) { clearTimeout(timer); finish(null); }
        });
    });
}

async function scanUDPPort(host, port) {
    const res = await tryUDPConnect(host, port);
    return { proto: "UDP", port, data: res };
}

// --- host scan ---

async function scanHost(host, firstPort, lastPort) {
    const portList  = shufflePorts(firstPort, lastPort);
    const openPorts = [];

    let resolvedIP = null;
    try {
        resolvedIP = /^\d+\.\d+\.\d+\.\d+$/.test(host)
            ? host
            : (await dns.lookup(host)).address;
    } catch {}

    // use PTR hostname in HTTP Host header so traffic looks like browsing, not scanning
    let hostname = host;
    try {
        if (resolvedIP) {
            const ptrs = await dns.reverse(resolvedIP);
            if (ptrs.length > 0) hostname = ptrs[0];
        }
    } catch {}

    function onResult({ proto, port, data }) {
        if (!data || data === "OPEN|FILTERED" || data.startsWith("ERROR:")) return;

        const banner = typeof data === "string" && data.trim()
            ? data.trim().split(/\r?\n/)
            : null;

        process.stdout.write("\r\x1b[K");
        console.log(`  OPEN  ${host}:${port} [${proto}]${banner ? "  " + banner[0] : ""}`);

        openPorts.push({ port, value: banner ? `${proto}: ${banner[0]}` : proto });
    }

    const tcpTasks = portList.map((port) => async () => {
        await jitter();
        if (resolvedIP) sendDecoys(resolvedIP, port);
        return scanTCPPort(host, port, hostname);
    });

    const udpTasks = portList.map((port) => async () => {
        await jitter();
        return scanUDPPort(host, port);
    });

    await Promise.all([
        runPool(tcpTasks, MAX_TCP, onResult),
        runPool(udpTasks, MAX_UDP, onResult),
    ]);

    openPorts.sort((a, b) => a.port - b.port);

    const ports = {};
    for (const { port, value } of openPorts) ports[port] = value;

    return { host, ports, scannedAt: new Date().toISOString() };
}

// --- target parsing ---

function expandCIDR(cidr) {
    const [baseIP, prefix] = cidr.split("/");
    const bits = Number.parseInt(prefix, 10);
    if (bits < 16 || bits > 32) throw new Error(`CIDR /${bits} not supported (use /16–/32)`);

    const oct = baseIP.split(".").map(Number);
    const base = (oct[0] << 24 | oct[1] << 16 | oct[2] << 8 | oct[3]) >>> 0;
    const count = 1 << (32 - bits);
    const out = [];

    for (let i = 1; i < count - 1; i++) {
        const ip = (base + i) >>> 0;
        out.push(`${ip >>> 24}.${(ip >>> 16) & 0xff}.${(ip >>> 8) & 0xff}.${ip & 0xff}`);
    }
    return out;
}

function parseTargetFile(filePath) {
    const hosts = [];
    for (const line of fs.readFileSync(filePath, "utf8").split("\n").map(l => l.trim())) {
        if (!line || line.startsWith("#")) continue;
        line.includes("/") ? hosts.push(...expandCIDR(line)) : hosts.push(line);
    }
    return hosts;
}

// --- main ---

if (process.getuid() !== 0) {
    console.error("must be run as root (sudo)");
    process.exit(1);
}

const [targetFile, firstPortArg, lastPortArg, outputFile] = process.argv.slice(2);

if (!targetFile || !firstPortArg || !lastPortArg) {
    console.error("usage: sudo node src/scanner.js <target> <start-port> <end-port> [output.json]");
    process.exit(1);
}

const firstPort  = Number.parseInt(firstPortArg, 10);
const lastPort   = Number.parseInt(lastPortArg, 10);
const outputPath = outputFile || `scans/scan_${Date.now()}.json`;

fs.mkdirSync(path.dirname(outputPath), { recursive: true });

function resolveTargets(target) {
    if (fs.existsSync(target))   return parseTargetFile(target);
    if (target.includes("/"))    return expandCIDR(target);
    return [target];
}

const hosts = resolveTargets(targetFile);

console.log(`scanning ${hosts.length} host(s), ports ${firstPort}–${lastPort}\n`);

const results = [];
let done = 0;

const tasks = hosts.map((host) => async () => {
    const result = await scanHost(host, firstPort, lastPort);
    const count  = Object.keys(result.ports).length;

    if (count > 0) results.push(result);
    done++;

    if (count > 0) {
        console.log(`[${done}/${hosts.length}] ${host} — ${count} open`);
    } else {
        process.stdout.write(`\r[${done}/${hosts.length}] scanning...`);
    }

    fs.writeFileSync(outputPath, JSON.stringify(results, null, 2), "utf8");
});

await runPool(tasks, MAX_HOST, () => {});

console.log(`\nsaved to ${path.resolve(outputPath)}`);
