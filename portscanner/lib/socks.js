'use strict';

const { SocksClient } = require('socks');
const net = require('net');
const tls = require('tls');

const DEFAULT_PROXY = { host: '127.0.0.1', port: 9050, type: 5 };

// Creates a plain TCP socket tunneled through SOCKS5 (e.g. Tor).
async function socksConnect(host, port, proxy = DEFAULT_PROXY) {
    const { socket } = await SocksClient.createConnection({
        proxy: { ...proxy, type: 5 },
        command: 'connect',
        destination: { host, port },
    });
    return socket;
}

// Creates a TLS socket tunneled through SOCKS5.
async function socksTLSConnect(host, port, proxy = DEFAULT_PROXY) {
    const rawSocket = await socksConnect(host, port, proxy);
    return new Promise((resolve, reject) => {
        const tlsSocket = tls.connect({
            host,
            port,
            socket: rawSocket,
            rejectUnauthorized: false,
        });
        tlsSocket.once('secureConnect', () => resolve(tlsSocket));
        tlsSocket.once('error', reject);
    });
}

module.exports = { socksConnect, socksTLSConnect, DEFAULT_PROXY };
