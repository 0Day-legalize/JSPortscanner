'use strict';

// TCP flag constants
const FLAGS = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10, URG: 0x20 };

// Internet checksum (RFC 1071)
function checksum(buf) {
    let sum = 0;
    for (let i = 0; i < buf.length - 1; i += 2) sum += buf.readUInt16BE(i);
    if (buf.length % 2) sum += buf[buf.length - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
}

// Build a raw IPv4 + TCP header buffer
function buildTCPPacket(srcIp, dstIp, srcPort, dstPort, flags, seqNum = Math.floor(Math.random() * 0xffffffff)) {
    const ipHeader  = Buffer.alloc(20);
    const tcpHeader = Buffer.alloc(20);

    // IP header
    ipHeader[0]  = 0x45;                          // version=4, IHL=5
    ipHeader[1]  = 0x00;                          // DSCP/ECN
    ipHeader.writeUInt16BE(40, 2);                // total length (20 IP + 20 TCP)
    ipHeader.writeUInt16BE(Math.floor(Math.random() * 0xffff), 4); // ID
    ipHeader[6]  = 0x40;                          // DF flag
    ipHeader[7]  = 0x00;                          // fragment offset
    ipHeader[8]  = 64;                            // TTL
    ipHeader[9]  = 0x06;                          // protocol: TCP
    ipHeader.writeUInt16BE(0, 10);                // checksum placeholder
    srcIp.split('.').forEach((o, i) => ipHeader.writeUInt8(parseInt(o), 12 + i));
    dstIp.split('.').forEach((o, i) => ipHeader.writeUInt8(parseInt(o), 16 + i));
    ipHeader.writeUInt16BE(checksum(ipHeader), 10);

    // TCP header
    tcpHeader.writeUInt16BE(srcPort,  0);
    tcpHeader.writeUInt16BE(dstPort,  2);
    tcpHeader.writeUInt32BE(seqNum,   4);
    tcpHeader.writeUInt32BE(0,        8);         // ack num
    tcpHeader[12] = 0x50;                         // data offset = 5 (20 bytes)
    tcpHeader[13] = flags;
    tcpHeader.writeUInt16BE(1024,    14);         // window size
    tcpHeader.writeUInt16BE(0,       16);         // checksum placeholder
    tcpHeader.writeUInt16BE(0,       18);         // urgent pointer

    // TCP pseudo-header checksum
    const pseudo = Buffer.alloc(12 + 20);
    srcIp.split('.').forEach((o, i) => pseudo.writeUInt8(parseInt(o), i));
    dstIp.split('.').forEach((o, i) => pseudo.writeUInt8(parseInt(o), 4 + i));
    pseudo[8]  = 0x00;
    pseudo[9]  = 0x06;                            // TCP
    pseudo.writeUInt16BE(20, 10);                 // TCP length
    tcpHeader.copy(pseudo, 12);
    tcpHeader.writeUInt16BE(checksum(pseudo), 16);

    return Buffer.concat([ipHeader, tcpHeader]);
}

module.exports = { buildTCPPacket, FLAGS, checksum };
