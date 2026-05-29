'use strict';

const dgram = require('dgram');

const TIMEOUT_MS = 3000;

// Common UDP payloads to elicit responses from known services
const PAYLOADS = {
    53:    Buffer.from('00010000000100000000000003777777006578616d706c6503636f6d0000010001', 'hex'), // DNS
    161:   Buffer.from('302602010004067075626c6963a019020400000000020100020100300b300906052b06010201050000', 'hex'), // SNMP
    123:   Buffer.alloc(48, 0x1b), // NTP
    default: Buffer.alloc(0),
};

function probe(host, port, opts = {}) {
    const { timeout = TIMEOUT_MS } = opts;
    const start = Date.now();

    return new Promise((resolve) => {
        const socket = dgram.createSocket('udp4');
        let responded = false;

        const done = (state, banner = null) => {
            if (responded) return;
            responded = true;
            clearTimeout(timer);
            socket.close();
            resolve({ host, port, state, banner, latency: Date.now() - start, tls: false, service: null, proto: 'udp' });
        };

        const timer = setTimeout(() => done('open|filtered'), timeout);

        socket.on('message', (msg) => done('open', msg.toString('utf8').slice(0, 256)));
        socket.on('error', (err) => {
            // ICMP port unreachable surfaces as ECONNREFUSED on Linux
            if (err.code === 'ECONNREFUSED') done('closed');
            else done('open|filtered');
        });

        const payload = PAYLOADS[port] || PAYLOADS.default;
        socket.send(payload, 0, payload.length, port, host);
    });
}

module.exports = { probe };
