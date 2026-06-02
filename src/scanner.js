import net               from "node:net";
import tls               from "node:tls";
import dgram             from "node:dgram";
import fs                from "node:fs";
import path              from "node:path";
import dns               from "node:dns/promises";
import { createRequire } from "node:module";
import { jitter, runPool } from "./utils.js";

const require = createRequire(import.meta.url);

let raw = null;
try { raw = require("raw-socket"); } catch {}

// --- ʕ•ᴥ•ʔ config ʕ•ᴥ•ʔ ---

const cfg = JSON.parse(fs.readFileSync(new URL("../config/settings.json", import.meta.url), "utf8")).scanner;

const MAX_TCP   = cfg.maxTCPConnections;
const MAX_UDP   = cfg.maxUDPConnections;
const MAX_HOST  = cfg.maxHostWorkers;
const TIMEOUT   = cfg.socketTimeoutMs;
const J_MIN     = cfg.jitterMinMs;
const J_MAX     = cfg.jitterMaxMs;
const DECOYS    = cfg.decoyCount;
const PLAIN     = new Set(cfg.plaintextPorts);
const UA_LIST   = cfg.userAgents;
const HTTP_PATHS = cfg.httpPaths;
const REFERERS   = cfg.referers;
const LANGUAGES  = cfg.acceptLanguages;
const COOKIES    = cfg.fakeCookies;

const REUSE_REQUESTS   = cfg.connectionReuseRequests;
const FRAGMENT_DECOYS  = cfg.fragmentDecoys;
const PASSIVE_PORTS    = new Set(cfg.passiveBannerPorts);
const SMTP_PORTS       = new Set(cfg.smtpPorts);
const SLOW_J_MIN       = cfg.slowJitterMinMs;
const SLOW_J_MAX       = cfg.slowJitterMaxMs;
const SLOW_MAX_HOST    = cfg.slowMaxHostWorkers;
const SLOW_MAX_TCP     = cfg.slowMaxTCPConnections;

const randomUA       = () => UA_LIST[rand(UA_LIST.length)];
const randomPath     = () => HTTP_PATHS[rand(HTTP_PATHS.length)];
const randomReferer  = () => REFERERS[rand(REFERERS.length)];
const randomLanguage = () => LANGUAGES[rand(LANGUAGES.length)];
const randomCookie   = () => COOKIES[rand(COOKIES.length)];

// builds one HTTP HEAD request — all headers randomised per call so each request
// in the pipeline looks like it came from a different browser state.
// keepAlive=true on all but the last request; the final one sends Connection: close
// so the server knows to close after responding, matching real browser keep-alive behaviour.
const buildRequest = (hostname, keepAlive) =>
    `HEAD ${randomPath()} HTTP/1.1\r\n` +
    `Host: ${hostname}\r\n` +
    `User-Agent: ${randomUA()}\r\n` +
    `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n` +
    `Accept-Language: ${randomLanguage()}\r\n` +
    `Accept-Encoding: gzip, deflate\r\n` +
    `Referer: ${randomReferer()}\r\n` +
    `Cookie: ${randomCookie()}\r\n` +
    `Connection: ${keepAlive ? "keep-alive" : "close"}\r\n\r\n`;

// --- ʕ•ᴥ•ʔ obfuscation helpers ʕ•ᴥ•ʔ ---

const rand = (n) => Math.floor(Math.random() * n);

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

// --- ʕ•ᴥ•ʔ obfuscation decoy IPs ʕ•ᴥ•ʔ ---

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
    // 60 bytes: 20 IP header + 20 TCP header + 20 TCP options
    // TCP options make the packet indistinguishable from a real Linux SYN
    const pkt = Buffer.alloc(60);
    const src = srcIP.split(".").map(Number);
    const dst = dstIP.split(".").map(Number);

    // ── IP header (bytes 0–19) ──────────────────────────────────────
    pkt[0] = 0x45;                        // version=4, IHL=5 (20 byte header)
    pkt[1] = 0x00;                        // DSCP/ECN — default, no QoS
    pkt.writeUInt16BE(60, 2);             // total length: 20 IP + 20 TCP + 20 options
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
    pkt[32] = 0xA0;                                    // data offset=10 (40 byte header with options)
    pkt[33] = 0x02;                                    // flags: SYN only
    pkt.writeUInt16BE(rand(0xffff) | 0x1000, 34);      // random window size
    pkt.writeUInt16BE(0, 36);                          // checksum placeholder (filled below)
    pkt.writeUInt16BE(0, 38);                          // urgent pointer=0

    // ── TCP options (bytes 40–59) — matches real Linux SYN fingerprint ──
    // MSS (kind=2, len=4): 1460 = standard Ethernet MTU
    pkt[40] = 0x02; pkt[41] = 0x04; pkt.writeUInt16BE(1460, 42);
    // SACK permitted (kind=4, len=2)
    pkt[44] = 0x04; pkt[45] = 0x02;
    // Timestamps (kind=8, len=10): random TSval, TSecr=0
    pkt[46] = 0x08; pkt[47] = 0x0a;
    pkt.writeUInt32BE(rand(0xffffffff) >>> 0, 48);     // TSval — random
    pkt.writeUInt32BE(0, 52);                          // TSecr=0 (no previous timestamp)
    // NOP (kind=1) for alignment
    pkt[56] = 0x01;
    // Window scale (kind=3, len=3): scale=7 matches Ubuntu/Debian default
    pkt[57] = 0x03; pkt[58] = 0x03; pkt[59] = 0x07;

    // ── TCP checksum — requires pseudo header (RFC 793) ────────────
    const tcpLen = 40; // TCP header (20) + options (20)
    const pseudo = Buffer.alloc(12);
    pseudo[0]=src[0]; pseudo[1]=src[1]; pseudo[2]=src[2]; pseudo[3]=src[3];
    pseudo[4]=dst[0]; pseudo[5]=dst[1]; pseudo[6]=dst[2]; pseudo[7]=dst[3];
    pseudo[8]=0; pseudo[9]=6;
    pseudo.writeUInt16BE(tcpLen, 10);
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

/**
 * Splits a complete SYN packet into two IP fragments.
 * Fragment 1 carries the first 16 bytes of the TCP section, fragment 2 the remaining 24.
 * Some IDS systems inspect fragments individually and miss the SYN because they
 * can't reassemble fast enough — the target OS reassembles normally.
 *
 * @param {Buffer} full - Complete 60-byte packet from buildSynPacket
 * @returns {[Buffer, Buffer]} Two IP fragment buffers
 */
function fragmentPacket(full) {
    // split the 40-byte TCP section (header+options) into two fragments of 16 + 24 bytes
    const id  = rand(0xffff);
    const ttl = full[8];
    const src = full.slice(12, 16);
    const dst = full.slice(16, 20);

    // fragment 1: IP header + first 16 bytes of TCP+options (MF=1, offset=0)
    const f1 = Buffer.alloc(36); // 20 IP + 16 TCP
    f1[0] = 0x45; f1[1] = 0x00;
    f1.writeUInt16BE(36, 2);
    f1.writeUInt16BE(id, 4);
    f1.writeUInt16BE(0x2000, 6);         // MF=1, offset=0
    f1[8] = ttl; f1[9] = 6;
    f1.writeUInt16BE(0, 10);
    src.copy(f1, 12); dst.copy(f1, 16);
    full.copy(f1, 20, 20, 36);           // first 16 TCP bytes
    f1.writeUInt16BE(checksum(f1.slice(0, 20)), 10);

    // fragment 2: IP header + last 24 bytes of TCP+options (MF=0, offset=2 meaning 16 bytes)
    const f2 = Buffer.alloc(44); // 20 IP + 24 TCP
    f2[0] = 0x45; f2[1] = 0x00;
    f2.writeUInt16BE(44, 2);
    f2.writeUInt16BE(id, 4);
    f2.writeUInt16BE(0x0002, 6);         // MF=0, offset=2 (=16 bytes)
    f2[8] = ttl; f2[9] = 6;
    f2.writeUInt16BE(0, 10);
    src.copy(f2, 12); dst.copy(f2, 16);
    full.copy(f2, 20, 36, 60);           // last 24 TCP bytes
    f2.writeUInt16BE(checksum(f2.slice(0, 20)), 10);

    return [f1, f2];
}

/**
 * Returns a random IP from the same /24 subnet as the destination,
 * skipping the real destination and the .0 and .255 addresses.
 * Looks like internal server-to-server traffic rather than a private RFC1918 address
 * which is impossible on the public internet and trivially flagged.
 *
 * @param {string} dstIP
 * @returns {string}
 */
function randomSubnetIP(dstIP) {
    const parts  = dstIP.split(".").map(Number);
    const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
    let host;
    do { host = 1 + rand(253); } while (host === parts[3]);
    return `${prefix}.${host}`;
}

function sendDecoys(dstIP, dstPort) {
    const sock = getDecoySocket();
    if (!sock) return;
    for (let i = 0; i < DECOYS; i++) {
        // use target's own subnet — looks like neighbor server traffic, not a private IP
        const pkt = buildSynPacket(randomSubnetIP(dstIP), dstIP, randomSourcePort(), dstPort);
        if (FRAGMENT_DECOYS && rand(2) === 0) {
            // alternate between normal and fragmented decoys to mix traffic patterns
            const [f1, f2] = fragmentPacket(pkt);
            sock.send(f1, 0, f1.length, dstIP, () => {});
            sock.send(f2, 0, f2.length, dstIP, () => {});
        } else {
            sock.send(pkt, 0, pkt.length, dstIP, () => {});
        }
    }
}

// --- ʕ•ᴥ•ʔ half-open SYN scan ʕ•ᴥ•ʔ ---

/** Tracks in-flight SYN probes keyed by our local source port number. */
const pendingSYNs = new Map();
let synRecvSocket = null;

/**
 * Detects the machine's real outbound IP address using the UDP routing trick.
 * A UDP socket is connected (without sending anything) so the OS selects the
 * correct source address; that address is read back and the socket is closed.
 *
 * @returns {Promise<string|null>} Dotted-decimal source IP, or null on failure
 */
function getOutboundIP() {
    return new Promise((resolve) => {
        const s = dgram.createSocket("udp4");
        s.connect(53, "8.8.8.8", () => { resolve(s.address().address); s.close(); });
        s.on("error", () => resolve(null));
    });
}

/**
 * Sets up a raw TCP receiving socket that listens for inbound SYN-ACK packets.
 * For each received packet it strips the IP header, checks the flags, and
 * resolves the matching pending probe from `pendingSYNs` keyed by the
 * destination port (our local source port).
 *
 * @returns {boolean} true if the raw socket was created successfully, false if
 *   raw-socket is unavailable or the process lacks the required privileges
 */
function initSYNReceiver() {
    if (!raw) return false;
    try {
        synRecvSocket = raw.createSocket({ protocol: raw.Protocol.TCP });
        synRecvSocket.on("message", (buffer, source) => {
            if (buffer.length < 40) return;

            // IP header is included — skip it to reach the TCP header
            const ipHdrLen = (buffer[0] & 0x0f) * 4;
            if (buffer.length < ipHdrLen + 14) return;

            const responseSrcPort = buffer.readUInt16BE(ipHdrLen);      // target's port
            const responseDstPort = buffer.readUInt16BE(ipHdrLen + 2);  // our local port
            const flags           = buffer[ipHdrLen + 13];
            const isSYNACK        = (flags & 0x12) === 0x12;

            const pending = pendingSYNs.get(responseDstPort);
            if (!pending || pending.dstIP !== source || pending.dstPort !== responseSrcPort) return;

            clearTimeout(pending.timer);
            pendingSYNs.delete(responseDstPort);
            pending.resolve(isSYNACK);
        });
        return true;
    } catch { return false; }
}

/**
 * Sends a real-source-IP SYN and waits for a SYN-ACK response without
 * completing the handshake. Because the three-way handshake never finishes,
 * application-layer daemons (SSH, NGINX, Apache, Cowrie) never log the
 * connection attempt.
 *
 * @param {string} dstIP   - Destination IP in dotted-decimal
 * @param {number} dstPort - TCP port to probe
 * @param {string} srcIP   - Real outbound IP (from getOutboundIP) so the
 *   SYN-ACK is routed back to this host
 * @returns {Promise<boolean>} true if a SYN-ACK was received within TIMEOUT ms,
 *   false on timeout or if the raw socket is unavailable
 */
function probeSYNHalfOpen(dstIP, dstPort, srcIP) {
    return new Promise((resolve) => {
        const sock = getDecoySocket();
        if (!sock || !synRecvSocket) { resolve(false); return; }

        const srcPort = randomSourcePort();
        const timer   = setTimeout(() => {
            pendingSYNs.delete(srcPort);
            resolve(false);
        }, TIMEOUT);

        pendingSYNs.set(srcPort, { dstIP, dstPort, resolve, timer });

        // use our real IP so the SYN-ACK is routed back to us
        const pkt = buildSynPacket(srcIP, dstIP, srcPort, dstPort);
        sock.send(pkt, 0, pkt.length, dstIP, () => {});
    });
}

// --- ʕ•ᴥ•ʔ service-appropriate probes ʕ•ᴥ•ʔ ---

// Services that send a banner immediately on connect — just read passively
// Sending HTTP to SSH/FTP/SMTP is a scanner fingerprint
function probeBannerOnly(host, port) {
    return new Promise((resolve) => {
        const socket = net.createConnection({ host, port });
        let data = "";

        socket.setTimeout(TIMEOUT);
        socket.on("data",    (chunk) => { data += chunk.toString("utf8"); socket.destroy(); });
        socket.on("timeout", ()      => socket.destroy());
        socket.on("error",   ()      => resolve(null));
        socket.on("close",   ()      => resolve(data.trim() || null));
    });
}

// SMTP requires a greeting exchange — send EHLO to get capability list
function probeSMTP(host, port) {
    return new Promise((resolve) => {
        const socket = net.createConnection({ host, port });
        let data = "";
        let greeted = false;

        socket.setTimeout(TIMEOUT);

        socket.on("data", (chunk) => {
            data += chunk.toString("utf8");
            // SMTP opens with a 220 greeting — only after that can we send EHLO
            if (!greeted && data.includes("220")) {
                greeted = true;
                socket.write("EHLO mail.example.com\r\n");
            }
            // 250 (single-line) or 250- (multi-line continuation) signals EHLO accepted
            if (greeted && (data.includes("250 ") || data.includes("250-"))) {
                socket.destroy();
            }
        });

        socket.on("timeout", () => socket.destroy());
        socket.on("error",   () => resolve(null));
        socket.on("close",   () => resolve(data.trim() || null));
    });
}

// --- ʕ•ᴥ•ʔ port scanning + banner grabbing ʕ•ᴥ•ʔ ---

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
            let payload = "";
            for (let i = 0; i < REUSE_REQUESTS; i++)
                payload += buildRequest(hostname, i < REUSE_REQUESTS - 1);
            socket.write(payload);
        });

        socket.on("data",    (chunk) => { data += chunk.toString("utf8"); });
        socket.on("timeout", ()      => socket.destroy());
        socket.on("error",   ()      => { if (!connected) resolve(null); });
        socket.on("close",   ()      => resolve(connected ? data : null));
    });
}

/**
 * Extracts useful fields from a TLS certificate — common name, SANs, org, issuer, expiry.
 * SANs reveal all domain names tied to the IP which identifies the owner.
 *
 * @param {import("tls").TLSSocket} socket
 * @returns {object|null}
 */
function extractCert(socket) {
    try {
        const cert    = socket.getPeerCertificate();
        if (!cert || !cert.subject) return null;

        const sans = cert.subjectaltname
            ? cert.subjectaltname.split(", ").map(s => s.replace(/^DNS:|^IP Address:/, ""))
            : [];

        return {
            cn:      cert.subject.CN   || null,
            org:     cert.subject.O    || null,
            issuer:  cert.issuer?.O    || null,
            sans:    sans.length > 0   ? sans : null,
            expires: cert.valid_to     || null,
        };
    } catch { return null; }
}

/**
 * Parses HTTP response headers from raw response text into a key/value object.
 * Captures Server, X-Powered-By, Content-Type and other useful fingerprinting headers.
 *
 * @param {string} raw - Full HTTP response text
 * @returns {object}
 */
function parseHeaders(raw) {
    const headers = {};
    const lines   = raw.split(/\r?\n/).slice(1); // skip status line
    const useful  = new Set(["server", "x-powered-by", "content-type", "location", "x-generator", "x-drupal-cache", "x-wordpress-cache"]);

    for (const line of lines) {
        const sep = line.indexOf(":");
        if (sep === -1) break;
        const key = line.slice(0, sep).trim().toLowerCase();
        if (useful.has(key)) headers[key] = line.slice(sep + 1).trim();
    }
    return Object.keys(headers).length > 0 ? headers : null;
}

function tryTLSConnect(host, port, hostname) {
    return new Promise((resolve) => {
        const isIP   = /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
        const socket = tls.connect({
            host, port,
            rejectUnauthorized: false,
            ...(isIP ? {} : { servername: hostname }),
        });

        let data = "";
        let cert = null;

        socket.setTimeout(TIMEOUT);

        socket.on("secureConnect", () => {
            cert = extractCert(socket);
            // pipeline REUSE_REQUESTS requests — earlier ones keep-alive, last one close
            let payload = "";
            for (let i = 0; i < REUSE_REQUESTS; i++)
                payload += buildRequest(hostname, i < REUSE_REQUESTS - 1);
            socket.write(payload);
        });

        socket.on("data",    (chunk) => { data += chunk.toString("utf8"); });
        socket.on("timeout", ()      => socket.destroy());
        socket.on("error",   ()      => resolve(null));
        socket.on("close",   ()      => resolve(data ? { data, cert } : null));
    });
}

async function scanTCPPort(host, port, hostname = host) {
    // service-specific probes — avoids sending HTTP to non-HTTP services
    if (PASSIVE_PORTS.has(port)) {
        const res = await probeBannerOnly(host, port);
        return { proto: "TCP", port, data: res, cert: null, headers: null };
    }

    if (SMTP_PORTS.has(port)) {
        const res = await probeSMTP(host, port);
        return { proto: "SMTP", port, data: res, cert: null, headers: null };
    }

    // for everything else try TLS first then plain TCP with HTTP banner grab
    const tlsRes = await tryTLSConnect(host, port, hostname);
    if (tlsRes !== null) {
        const headers = tlsRes.data ? parseHeaders(tlsRes.data) : null;
        return { proto: "TLS", port, data: tlsRes.data, cert: tlsRes.cert, headers };
    }

    const tcpRes = await tryTCPConnect(host, port, false, hostname);
    const headers = tcpRes ? parseHeaders(tcpRes) : null;
    return { proto: "TCP", port, data: tcpRes, cert: null, headers };
}

// --- ʕ•ᴥ•ʔ udp port scanning ʕ•ᴥ•ʔ ---

function tryUDPConnect(host, port) {
    return new Promise((resolve) => {
        const socket = dgram.createSocket("udp4");
        let done = false;

        // both message and error can fire before close — this guard ensures
        // the promise resolves exactly once regardless of event order
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

// --- ʕ•ᴥ•ʔ host scan ʕ•ᴥ•ʔ ---

/**
 * Scans the full TCP and UDP port range on a single host and returns a
 * structured result. TCP and UDP pools run concurrently. In --syn mode the TCP
 * tasks call probeSYNHalfOpen instead of scanTCPPort.
 *
 * @param {string}   host       - IP address or hostname to scan
 * @param {number}   firstPort  - Start of port range, inclusive
 * @param {number}   lastPort   - End of port range, inclusive
 * @param {Function} onProgress - Called once per completed probe for the progress bar
 * @param {string|null} srcIP   - Real outbound IP passed to probeSYNHalfOpen in
 *   --syn mode; null in normal mode
 * @returns {Promise<{host: string, hostname?: string, ports: object, scannedAt: string}>}
 */
async function scanHost(host, firstPort, lastPort, onProgress, srcIP = null) {
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

    function onResult({ proto, port, data, cert, headers }) {
        if (onProgress) onProgress();
        if (!data || data === "OPEN|FILTERED" || data.startsWith("ERROR:")) return;

        const banner = typeof data === "string" && data.trim()
            ? data.trim().split(/\r?\n/)
            : null;

        const entry = { banner: banner ? banner[0] : null };
        if (cert)    entry.cert    = cert;
        if (headers) entry.headers = headers;

        openPorts.push({ port, proto, entry });
    }

    const jMin = slowMode ? SLOW_J_MIN : J_MIN;
    const jMax = slowMode ? SLOW_J_MAX : J_MAX;
    const maxTCP = slowMode ? SLOW_MAX_TCP : MAX_TCP;

    const tcpTasks = portList.map((port) => async () => {
        await jitter(jMin, jMax);
        if (resolvedIP) sendDecoys(resolvedIP, port);

        // half-open SYN scan — never completes TCP handshake, no application logs
        if (synMode && srcIP && resolvedIP) {
            const open = await probeSYNHalfOpen(resolvedIP, port, srcIP);
            return { proto: "SYN", port, data: open ? "OPEN" : null, cert: null, headers: null };
        }

        return scanTCPPort(host, port, hostname);
    });

    const udpTasks = portList.map((port) => async () => {
        await jitter(jMin, jMax);
        return scanUDPPort(host, port);
    });

    await Promise.all([
        runPool(tcpTasks, maxTCP, onResult),
        runPool(udpTasks, MAX_UDP, onResult),
    ]);

    openPorts.sort((a, b) => a.port - b.port);

    const ports = {};
    for (const { port, proto, entry } of openPorts) {
        ports[port] = { proto, ...entry };
    }

    return { host, hostname: hostname !== host ? hostname : undefined, ports, scannedAt: new Date().toISOString() };
}

// --- ʕ•ᴥ•ʔ target parsing ʕ•ᴥ•ʔ ---

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

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const rawArgs    = process.argv.slice(2);
const slowMode   = rawArgs.includes("--slow");
const synMode    = rawArgs.includes("--syn");
const cleanArgs  = rawArgs.filter(a => a !== "--slow" && a !== "--syn");

if (rawArgs.includes("--help") || rawArgs.includes("-h")) {
    console.log(`
  RCN Port Scanner

  usage:
    sudo node src/scanner.js <target> <start-port> <end-port> [output.json] [flags]

  target:
    IP address        37.27.7.154
    CIDR range        37.27.7.128/26
    targets file      config/targets.txt

  flags:
    --slow            jitter 5–60s per probe, 5 concurrent hosts — stays under IDS thresholds
    --syn             half-open SYN scan — never completes TCP handshake, no application logs
    --help / -h       show this help

  flags can be combined:
    sudo node src/scanner.js config/targets.txt 1 1025 --syn --slow

  examples:
    sudo node src/scanner.js 37.27.7.128/26 22 22
    sudo node src/scanner.js config/targets.txt 1 1025 scans/out.json --slow
    sudo node src/scanner.js 37.27.7.154 1 65535 --syn
`);
    process.exit(0);
}

const [targetFile, firstPortArg, lastPortArg, outputFile] = cleanArgs;

if (process.getuid() !== 0) {
    console.error("must be run as root (sudo)");
    process.exit(1);
}

if (slowMode) console.log("slow mode enabled — jitter 5–60s, 5 concurrent hosts\n");

let srcIP = null;
if (synMode) {
    if (!initSYNReceiver()) {
        console.error("--syn requires raw-socket to be installed and root access");
        process.exit(1);
    }
    srcIP = await getOutboundIP();
    if (!srcIP) { console.error("could not detect outbound IP"); process.exit(1); }
    console.log(`half-open SYN scan — source IP ${srcIP} (no application logs on target)\n`);
}

if (!targetFile || !firstPortArg || !lastPortArg) {
    console.error("usage: sudo node src/scanner.js <target> <start-port> <end-port> [output.json]");
    process.exit(1);
}

const firstPort  = Number.parseInt(firstPortArg, 10);
const lastPort   = Number.parseInt(lastPortArg, 10);

if (isNaN(firstPort) || isNaN(lastPort) || firstPort < 1 || lastPort > 65535 || firstPort > lastPort) {
    console.error("invalid port range — must be 1–65535 with start <= end");
    process.exit(1);
}

const outputPath = outputFile || `scans/scan_${Date.now()}.json`;

fs.mkdirSync(path.dirname(outputPath), { recursive: true });

function resolveTargets(target) {
    if (fs.existsSync(target))   return parseTargetFile(target);
    if (target.includes("/"))    return expandCIDR(target);
    return [target];
}

const hosts = resolveTargets(targetFile);

console.log(`scanning ${hosts.length} host(s), ports ${firstPort}–${lastPort}\n`);

const results     = [];
let hits          = 0;
let portsScanned  = 0;
const totalPorts  = hosts.length * (lastPort - firstPort + 1) * 2; // TCP + UDP per host
const BAR         = 30;

function renderBar() {
    const pct       = totalPorts > 0 ? portsScanned / totalPorts : 0;
    const filled    = Math.floor(pct * BAR);
    const raccoon   = "ʕ•ᴥ•ʔ";
    const eaten     = "·".repeat(filled);
    const remaining = "·".repeat(Math.max(0, BAR - filled));
    const pctStr    = String(Math.floor(pct * 100)).padStart(3, " ");
    process.stdout.write(`\r${eaten}${raccoon}${remaining}  ${pctStr}%  * ${hits}`);
}

function onPortProgress() {
    portsScanned++;
    renderBar();
}

const tasks = hosts.map((host) => async () => {
    const result = await scanHost(host, firstPort, lastPort, onPortProgress, srcIP);
    const count  = Object.keys(result.ports).length;

    if (count > 0) { results.push(result); hits += count; }

    fs.writeFileSync(outputPath, JSON.stringify(results, null, 2), "utf8");
});

// flush results on Ctrl+C so partial scans aren't lost
process.on("SIGINT", () => {
    fs.writeFileSync(outputPath, JSON.stringify(results, null, 2), "utf8");
    console.log(`\n\ninterrupted — partial results saved to ${path.resolve(outputPath)}`);
    process.exit(0);
});

await runPool(tasks, slowMode ? SLOW_MAX_HOST : MAX_HOST, () => {});

console.log(`\nsaved to ${path.resolve(outputPath)}`);
