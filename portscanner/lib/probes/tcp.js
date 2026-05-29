'use strict';

const net = require('net');
const tls = require('tls');
const { socksConnect, socksTLSConnect } = require('../socks');

const BANNER_BYTES = 4096;
const TIMEOUT_MS   = 3000;

// HTTP probe to elicit a response from web servers
const HTTP_PROBE = 'HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n';

function readBanner(socket) {
    return new Promise((resolve) => {
        let buf = '';
        const done = (val) => { socket.removeAllListeners(); socket.destroy(); resolve(val); };
        socket.setTimeout(TIMEOUT_MS);
        socket.on('data',    (d) => { buf += d.toString('utf8'); if (buf.length >= BANNER_BYTES) done(buf); });
        socket.on('timeout', ()  => done(buf || null));
        socket.on('error',   ()  => done(buf || null));
        socket.on('close',   ()  => done(buf || null));
    });
}

async function tcpConnect(host, port, opts = {}) {
    const { tor, proxy, timeout = TIMEOUT_MS } = opts;
    const start = Date.now();

    return new Promise(async (resolve) => {
        let socket;
        let connected = false;

        const fail = () => resolve({ host, port, state: 'closed', service: null, banner: null, latency: null, tls: false });

        try {
            if (tor) {
                socket = await socksConnect(host, port, proxy).catch(() => null);
                if (!socket) return fail();
                connected = true;
            } else {
                socket = net.createConnection({ host, port });
                await new Promise((res, rej) => {
                    socket.setTimeout(timeout);
                    socket.once('connect', () => { connected = true; res(); });
                    socket.once('timeout', rej);
                    socket.once('error',   rej);
                });
            }
        } catch {
            return fail();
        }

        // Send an HTTP probe to elicit a response
        socket.write(HTTP_PROBE.replace('{host}', host));
        const banner = await readBanner(socket);
        const latency = Date.now() - start;
        resolve({ host, port, state: 'open', banner, latency, tls: false, service: null });
    });
}

async function tlsConnect(host, port, opts = {}) {
    const { tor, proxy, timeout = TIMEOUT_MS } = opts;
    const start = Date.now();

    return new Promise(async (resolve) => {
        let socket;
        const fail = () => resolve(null);

        try {
            if (tor) {
                socket = await socksTLSConnect(host, port, proxy).catch(() => null);
                if (!socket) return fail();
            } else {
                socket = tls.connect({ host, port, rejectUnauthorized: false });
                await new Promise((res, rej) => {
                    socket.setTimeout(timeout);
                    socket.once('secureConnect', res);
                    socket.once('timeout', rej);
                    socket.once('error',   rej);
                });
            }
        } catch {
            return fail();
        }

        socket.write(HTTP_PROBE.replace('{host}', host));
        const banner = await readBanner(socket);
        const latency = Date.now() - start;
        resolve({ host, port, state: 'open', banner, latency, tls: true, service: null });
    });
}

// Try TLS first, fall back to plain TCP
async function probe(host, port, opts = {}) {
    const tlsResult = await tlsConnect(host, port, opts);
    if (tlsResult) return tlsResult;
    return tcpConnect(host, port, opts);
}

module.exports = { probe };
