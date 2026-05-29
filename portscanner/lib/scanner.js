'use strict';

const EventEmitter = require('events');
const { pool }     = require('./pool');
const { detect }   = require('./service');
const tcpProbe     = require('./probes/tcp');
const synProbe     = require('./probes/syn');
const udpProbe     = require('./probes/udp');

class Scanner extends EventEmitter {
    constructor(opts = {}) {
        super();
        this.concurrency = opts.concurrency || 100;
        this.tor         = opts.tor         || false;
        this.proxy       = opts.proxy       || { host: '127.0.0.1', port: 9050, type: 5 };
        this.scanType    = opts.scanType    || 'connect'; // connect | syn | fin | null | xmas | udp
        this.timeout     = opts.timeout     || 3000;
        this.iface       = opts.iface       || null;
    }

    // Scan a single host+port, returns a result object
    async _probeOne(host, port) {
        const probeOpts = {
            tor:     this.tor,
            proxy:   this.proxy,
            timeout: this.timeout,
            ...(this.iface ? { iface: this.iface } : {}),
        };

        let result;

        if (this.scanType === 'udp') {
            result = await udpProbe.probe(host, port, probeOpts);
        } else if (this.scanType === 'connect') {
            result = await tcpProbe.probe(host, port, probeOpts);
        } else {
            // syn | fin | null | xmas — raw packet scans, incompatible with Tor
            if (this.tor) {
                this.emit('warning', `Raw scan type '${this.scanType}' cannot be used with --tor. Falling back to connect scan.`);
                result = await tcpProbe.probe(host, port, probeOpts);
            } else {
                result = await synProbe.probe(host, port, { ...probeOpts, type: this.scanType });
            }
        }

        result.service = detect(result.banner, port);
        return result;
    }

    // Scan all combinations of hosts × ports
    async scan(hosts, ports) {
        const results = [];
        const tasks = [];

        for (const host of hosts) {
            for (const port of ports) {
                tasks.push(async () => {
                    const r = await this._probeOne(host, port);
                    this.emit('result', r);
                    return r;
                });
            }
        }

        await pool(tasks, this.concurrency, (r) => results.push(r));
        return results;
    }
}

module.exports = { Scanner };
