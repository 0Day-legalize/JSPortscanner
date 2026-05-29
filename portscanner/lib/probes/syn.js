'use strict';

const os     = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { buildTCPPacket, FLAGS } = require('../packet');
const { startCapture, FLAG_SYN, FLAG_ACK, FLAG_RST } = require('../capture');

// Try native raw-socket (requires Node ≤ 22 / NAN-compatible build)
let rawSocket = null;
try {
    rawSocket = require('raw-socket');
} catch {
    // fall through to Python sender
}

const TIMEOUT_MS = 3000;

const SCAN_FLAGS = {
    syn:  FLAGS.SYN,
    fin:  FLAGS.FIN,
    null: 0x00,
    xmas: FLAGS.FIN | FLAGS.PSH | FLAGS.URG,
};

function defaultIface() {
    const nets = os.networkInterfaces();
    for (const [name, addrs] of Object.entries(nets)) {
        if (addrs.some(a => a.family === 'IPv4' && !a.internal)) return name;
    }
    return 'eth0';
}

function getLocalIp(iface) {
    const nets = os.networkInterfaces();
    const addrs = (nets[iface] || []);
    const found = addrs.find(a => a.family === 'IPv4' && !a.internal);
    return found ? found.address : '127.0.0.1';
}

// Send raw packet via native raw-socket
function sendNative(dstIp, packet) {
    const socket = rawSocket.createSocket({ protocol: rawSocket.Protocol.TCP });
    socket.setOption(
        rawSocket.SocketLevel.IPPROTO_IP,
        rawSocket.SocketOption.IP_HDRINCL,
        Buffer.from([1, 0, 0, 0]),
        4
    );
    socket.send(packet, 0, packet.length, dstIp, () => socket.close());
}

// Send raw packet via Python (fallback when raw-socket not available)
// Requires: python3 with socket module (standard lib)
function sendPython(srcIp, dstIp, srcPort, dstPort, flagVal) {
    const code = `
import socket, struct, random

def checksum(data):
    s = 0
    for i in range(0, len(data)-1, 2):
        s += (data[i] << 8) + data[i+1]
    if len(data) % 2:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

src = '${srcIp}'
dst = '${dstIp}'
sp  = ${srcPort}
dp  = ${dstPort}
seq = random.randint(0, 0xffffffff)

ip = struct.pack('!BBHHHBBH4s4s',
    0x45, 0, 40, random.randint(0, 0xffff),
    0x4000, 64, 6, 0,
    socket.inet_aton(src), socket.inet_aton(dst))
ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]

tcp = struct.pack('!HHLLBBHHH', sp, dp, seq, 0, 0x50, ${flagVal}, 1024, 0, 0)
pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, 20)
tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.sendto(ip + tcp, (dst, 0))
s.close()
`;
    spawn('python3', ['-c', code], { stdio: 'ignore' });
}

async function probe(dstIp, dstPort, opts = {}) {
    const { type = 'syn', iface = defaultIface(), timeout = TIMEOUT_MS } = opts;
    const srcIp   = getLocalIp(iface);
    const srcPort = 1024 + Math.floor(Math.random() * 60000);
    const flagVal = SCAN_FLAGS[type];

    if (flagVal === undefined) throw new Error(`Unknown scan type: ${type}`);

    return new Promise((resolve) => {
        let done = false;
        const start = Date.now();

        const finish = (state) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            capture.stop();
            resolve({
                host: dstIp, port: dstPort, state,
                banner: null, latency: Date.now() - start,
                tls: false, service: null, scanType: type,
            });
        };

        const capture = startCapture(iface, (pkt) => {
            if (pkt.srcIp !== dstIp || pkt.srcPort !== dstPort || pkt.dstPort !== srcPort) return;

            if (type === 'syn') {
                const isSynAck = (pkt.flags & (FLAG_SYN | FLAG_ACK)) === (FLAG_SYN | FLAG_ACK);
                if (isSynAck)            finish('open');
                else if (pkt.flags & FLAG_RST) finish('closed');
            } else {
                // FIN / NULL / XMAS: RST = closed, no reply = open|filtered
                if (pkt.flags & FLAG_RST) finish('closed');
            }
        });

        // Send packet
        if (rawSocket) {
            const packet = buildTCPPacket(srcIp, dstIp, srcPort, dstPort, flagVal);
            sendNative(dstIp, packet);
        } else {
            sendPython(srcIp, dstIp, srcPort, dstPort, flagVal);
        }

        const timer = setTimeout(() => finish('filtered'), timeout);
    });
}

module.exports = { probe, SCAN_FLAGS };
