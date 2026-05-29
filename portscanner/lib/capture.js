'use strict';

const { spawn } = require('child_process');

// Try native libpcap first (requires cap@0.2.x + Node ≤ 22)
let nativeCap = null;
try {
    nativeCap = require('cap');
} catch {
    // fall through to tcpdump
}

// TCP flag bitmasks matching tcpdump output
const FLAG_SYN = 0x02;
const FLAG_ACK = 0x10;
const FLAG_RST = 0x04;
const FLAG_FIN = 0x01;
const FLAG_PSH = 0x08;
const FLAG_URG = 0x20;

// Parse tcpdump -v flags string like "Flags [S.]" → numeric bitmask
function parseFlags(flagStr) {
    let f = 0;
    if (flagStr.includes('S')) f |= FLAG_SYN;
    if (flagStr.includes('.')) f |= FLAG_ACK;
    if (flagStr.includes('R')) f |= FLAG_RST;
    if (flagStr.includes('F')) f |= FLAG_FIN;
    if (flagStr.includes('P')) f |= FLAG_PSH;
    if (flagStr.includes('U')) f |= FLAG_URG;
    return f;
}

// tcpdump line format (with -n -v):
// HH:MM:SS.ffffff IP src.srcport > dst.dstport: Flags [XY], ...
function parseTcpdumpLine(line) {
    // Match IP packets
    const m = line.match(/IP\s+([\d.]+)\.(\d+)\s+>\s+([\d.]+)\.(\d+).*Flags\s+\[([^\]]+)\]/);
    if (!m) return null;
    return {
        srcIp:   m[1],
        srcPort: parseInt(m[2], 10),
        dstIp:   m[3],
        dstPort: parseInt(m[4], 10),
        flags:   parseFlags(m[5]),
    };
}

function startCaptureTcpdump(iface, onPacket) {
    const proc = spawn('tcpdump', [
        '-i', iface,
        '-n',          // no hostname resolution
        '-v',          // verbose (includes flags)
        '-l',          // line-buffered
        'tcp',
    ], { stdio: ['ignore', 'pipe', 'pipe'] });

    let buf = '';
    const handle = (chunk) => {
        buf += chunk.toString();
        const lines = buf.split('\n');
        buf = lines.pop(); // keep incomplete line
        for (const line of lines) {
            const pkt = parseTcpdumpLine(line);
            if (pkt) onPacket(pkt);
        }
    };

    proc.stdout.on('data', handle);
    proc.stderr.on('data', handle); // tcpdump writes to stderr with -v

    return {
        stop: () => { try { proc.kill('SIGTERM'); } catch {} }
    };
}

function startCaptureNative(iface, onPacket) {
    const { Cap, decoders } = nativeCap;
    const cap  = new Cap();
    const buf  = Buffer.alloc(65535);
    const link = cap.open(iface, 'tcp', 10 * 1024 * 1024, buf);
    cap.setMinBytes && cap.setMinBytes(0);

    cap.on('packet', () => {
        try {
            let offset = 0;
            if (link === 'ETHERNET') {
                const eth = decoders.Ethernet(buf);
                if (eth.info.type !== 2048) return;
                offset = eth.offset;
            }
            const ip  = decoders.IPV4(buf, offset);
            if (ip.info.protocol !== 6) return;
            offset += ip.hdrlen;
            const tcp = decoders.TCP(buf, offset);
            onPacket({
                srcIp:   ip.info.srcaddr,
                dstIp:   ip.info.dstaddr,
                srcPort: tcp.info.srcport,
                dstPort: tcp.info.dstport,
                flags:   tcp.info.flags,
            });
        } catch {}
    });

    return { stop: () => cap.close() };
}

function startCapture(iface, onPacket) {
    if (nativeCap) return startCaptureNative(iface, onPacket);
    return startCaptureTcpdump(iface, onPacket);
}

module.exports = { startCapture, FLAG_SYN, FLAG_ACK, FLAG_RST, FLAG_FIN };
