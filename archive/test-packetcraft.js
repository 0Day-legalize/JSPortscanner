import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

let raw = null;
try { raw = require("raw-socket"); } catch { console.error("raw-socket not installed — run: npm install raw-socket"); process.exit(1); }

// --- ʕ•ᴥ•ʔ helpers ʕ•ᴥ•ʔ ---

const rand = (n) => Math.floor(Math.random() * n);

// one's complement checksum per RFC 791
function checksum(buf) {
    let sum = 0;
    for (let i = 0; i < buf.length; i += 2)
        sum += (i + 1 < buf.length) ? buf.readUInt16BE(i) : (buf[i] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
}

// --- ʕ•ᴥ•ʔ packet builders ʕ•ᴥ•ʔ ---

/**
 * Builds a raw IP + TCP SYN packet (60 bytes).
 * Includes full TCP options (MSS, SACK, Timestamps, NOP, Window Scale)
 * to match a real Linux kernel SYN fingerprint.
 *
 * @param {string} srcIP   - Source IP address
 * @param {string} dstIP   - Destination IP address
 * @param {number} srcPort - Source port
 * @param {number} dstPort - Destination port
 * @returns {Buffer} 60-byte raw packet
 */
function buildSYN(srcIP, dstIP, srcPort, dstPort) {
    const pkt = Buffer.alloc(60);
    const src = srcIP.split(".").map(Number);
    const dst = dstIP.split(".").map(Number);

    // ── IP header (bytes 0–19) ──────────────────────────────────────
    pkt[0] = 0x45;                          // version=4, IHL=5 (20 byte header)
    pkt[1] = 0x00;                          // DSCP/ECN
    pkt.writeUInt16BE(60, 2);               // total length: 20 IP + 20 TCP + 20 options
    pkt.writeUInt16BE(rand(0xffff), 4);     // random ID
    pkt.writeUInt16BE(0x4000, 6);           // DF flag, no fragment
    pkt[8] = 64 + rand(64);                // TTL randomised 64–127
    pkt[9] = 6;                             // protocol=TCP
    pkt.writeUInt16BE(0, 10);               // checksum placeholder
    pkt[12]=src[0]; pkt[13]=src[1]; pkt[14]=src[2]; pkt[15]=src[3];
    pkt[16]=dst[0]; pkt[17]=dst[1]; pkt[18]=dst[2]; pkt[19]=dst[3];
    pkt.writeUInt16BE(checksum(pkt.slice(0, 20)), 10);

    // ── TCP header (bytes 20–39) ────────────────────────────────────
    pkt.writeUInt16BE(srcPort, 20);         // source port
    pkt.writeUInt16BE(dstPort, 22);         // destination port
    pkt.writeUInt32BE(rand(0xffffffff) >>> 0, 24); // random sequence number
    pkt.writeUInt32BE(0, 28);               // ack=0 (SYN has no ack)
    pkt[32] = 0xA0;                         // data offset=10 (40 byte header with options)
    pkt[33] = 0x02;                         // flags: SYN only
    pkt.writeUInt16BE(rand(0xffff) | 0x1000, 34); // random window size
    pkt.writeUInt16BE(0, 36);               // checksum placeholder
    pkt.writeUInt16BE(0, 38);               // urgent pointer=0

    // ── TCP options (bytes 40–59) ───────────────────────────────────
    pkt[40] = 0x02; pkt[41] = 0x04; pkt.writeUInt16BE(1460, 42); // MSS=1460
    pkt[44] = 0x04; pkt[45] = 0x02;                               // SACK permitted
    pkt[46] = 0x08; pkt[47] = 0x0a;                               // Timestamps kind+len
    pkt.writeUInt32BE(rand(0xffffffff) >>> 0, 48);                 // TSval random
    pkt.writeUInt32BE(0, 52);                                      // TSecr=0
    pkt[56] = 0x01;                                                // NOP
    pkt[57] = 0x03; pkt[58] = 0x03; pkt[59] = 0x07;              // Window Scale=7

    // ── TCP checksum ────────────────────────────────────────────────
    const pseudo = Buffer.alloc(12);
    pseudo[0]=src[0]; pseudo[1]=src[1]; pseudo[2]=src[2]; pseudo[3]=src[3];
    pseudo[4]=dst[0]; pseudo[5]=dst[1]; pseudo[6]=dst[2]; pseudo[7]=dst[3];
    pseudo[8]=0; pseudo[9]=6;
    pseudo.writeUInt16BE(40, 10); // TCP header (20) + options (20)
    pkt.writeUInt16BE(checksum(Buffer.concat([pseudo, pkt.slice(20)])), 36);

    return pkt;
}

/**
 * Builds a TCP FIN packet (20 bytes IP + 20 bytes TCP, no options).
 * Used for FIN scans — closed ports reply with RST, open ports silently drop it.
 *
 * @param {string} srcIP
 * @param {string} dstIP
 * @param {number} srcPort
 * @param {number} dstPort
 * @returns {Buffer} 40-byte raw packet
 */
function buildFIN(srcIP, dstIP, srcPort, dstPort) {
    const pkt = Buffer.alloc(40);
    const src = srcIP.split(".").map(Number);
    const dst = dstIP.split(".").map(Number);

    // ── IP header ──────────────────────────────────────────────────
    pkt[0] = 0x45; pkt[1] = 0x00;
    pkt.writeUInt16BE(40, 2);
    pkt.writeUInt16BE(rand(0xffff), 4);
    pkt.writeUInt16BE(0x4000, 6);
    pkt[8] = 64 + rand(64); pkt[9] = 6;
    pkt.writeUInt16BE(0, 10);
    pkt[12]=src[0]; pkt[13]=src[1]; pkt[14]=src[2]; pkt[15]=src[3];
    pkt[16]=dst[0]; pkt[17]=dst[1]; pkt[18]=dst[2]; pkt[19]=dst[3];
    pkt.writeUInt16BE(checksum(pkt.slice(0, 20)), 10);

    // ── TCP header ──────────────────────────────────────────────────
    pkt.writeUInt16BE(srcPort, 20);
    pkt.writeUInt16BE(dstPort, 22);
    pkt.writeUInt32BE(rand(0xffffffff) >>> 0, 24);
    pkt.writeUInt32BE(0, 28);
    pkt[32] = 0x50;                         // data offset=5 (no options)
    pkt[33] = 0x01;                         // flags: FIN only
    pkt.writeUInt16BE(rand(0xffff) | 0x1000, 34);
    pkt.writeUInt16BE(0, 36);
    pkt.writeUInt16BE(0, 38);

    const pseudo = Buffer.alloc(12);
    pseudo[0]=src[0]; pseudo[1]=src[1]; pseudo[2]=src[2]; pseudo[3]=src[3];
    pseudo[4]=dst[0]; pseudo[5]=dst[1]; pseudo[6]=dst[2]; pseudo[7]=dst[3];
    pseudo[8]=0; pseudo[9]=6;
    pseudo.writeUInt16BE(20, 10);
    pkt.writeUInt16BE(checksum(Buffer.concat([pseudo, pkt.slice(20)])), 36);

    return pkt;
}

/**
 * Builds a TCP NULL packet — no flags set at all.
 * Same detection logic as FIN: closed ports RST, open ports drop it silently.
 *
 * @param {string} srcIP
 * @param {string} dstIP
 * @param {number} srcPort
 * @param {number} dstPort
 * @returns {Buffer} 40-byte raw packet
 */
function buildNULL(srcIP, dstIP, srcPort, dstPort) {
    const pkt = buildFIN(srcIP, dstIP, srcPort, dstPort);
    pkt[33] = 0x00; // clear the FIN flag — no flags set

    // recalculate TCP checksum with the updated flags byte
    const src = srcIP.split(".").map(Number);
    const dst = dstIP.split(".").map(Number);
    const pseudo = Buffer.alloc(12);
    pseudo[0]=src[0]; pseudo[1]=src[1]; pseudo[2]=src[2]; pseudo[3]=src[3];
    pseudo[4]=dst[0]; pseudo[5]=dst[1]; pseudo[6]=dst[2]; pseudo[7]=dst[3];
    pseudo[8]=0; pseudo[9]=6;
    pseudo.writeUInt16BE(20, 10);
    pkt.writeUInt16BE(0, 36); // clear old checksum before recalculating
    pkt.writeUInt16BE(checksum(Buffer.concat([pseudo, pkt.slice(20)])), 36);

    return pkt;
}

/**
 * Builds a TCP Xmas packet — FIN + URG + PSH flags all set.
 * "Lit up like a Christmas tree." Same detection logic as FIN/NULL.
 *
 * @param {string} srcIP
 * @param {string} dstIP
 * @param {number} srcPort
 * @param {number} dstPort
 * @returns {Buffer} 40-byte raw packet
 */
function buildXMAS(srcIP, dstIP, srcPort, dstPort) {
    const pkt = buildFIN(srcIP, dstIP, srcPort, dstPort);
    pkt[33] = 0x29; // FIN(0x01) + PSH(0x08) + URG(0x20)

    const src = srcIP.split(".").map(Number);
    const dst = dstIP.split(".").map(Number);
    const pseudo = Buffer.alloc(12);
    pseudo[0]=src[0]; pseudo[1]=src[1]; pseudo[2]=src[2]; pseudo[3]=src[3];
    pseudo[4]=dst[0]; pseudo[5]=dst[1]; pseudo[6]=dst[2]; pseudo[7]=dst[3];
    pseudo[8]=0; pseudo[9]=6;
    pseudo.writeUInt16BE(20, 10);
    pkt.writeUInt16BE(0, 36);
    pkt.writeUInt16BE(checksum(Buffer.concat([pseudo, pkt.slice(20)])), 36);

    return pkt;
}

// --- ʕ•ᴥ•ʔ send ʕ•ᴥ•ʔ ---

function send(packet, dstIP) {
    const sock = raw.createSocket({ protocol: raw.Protocol.None, addressFamily: raw.AddressFamily.IPv4 });
    sock.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL, Buffer.from([1, 0, 0, 0]), 4);
    sock.send(packet, 0, packet.length, dstIP, () => sock.close());
}

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const [type, srcIP, dstIP, srcPort, dstPort] = process.argv.slice(2);

if (!type || !srcIP || !dstIP || !srcPort || !dstPort) {
    console.log(`
  usage: sudo node packetcraft.js <type> <src-ip> <dst-ip> <src-port> <dst-port>

  types:
    syn    SYN packet with full TCP options (60 bytes)
    fin    FIN packet — closed=RST, open=silent
    null   NULL packet (no flags) — same as FIN
    xmas   Xmas packet (FIN+PSH+URG) — same as FIN

  example:
    sudo node packetcraft.js syn 10.0.0.1 37.27.7.154 54321 80
    sudo node packetcraft.js xmas 192.168.1.1 37.27.7.154 12345 22
`);
    process.exit(1);
}

const builders = { syn: buildSYN, fin: buildFIN, null: buildNULL, xmas: buildXMAS };
const builder  = builders[type.toLowerCase()];

if (!builder) {
    console.error(`unknown packet type: ${type}. use syn, fin, null, or xmas`);
    process.exit(1);
}

const pkt = builder(srcIP, dstIP, Number(srcPort), Number(dstPort));
send(pkt, dstIP);
console.log(`sent ${type.toUpperCase()} packet (${pkt.length} bytes) → ${dstIP}:${dstPort}`);
