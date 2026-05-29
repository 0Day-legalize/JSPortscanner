#!/usr/bin/env node
'use strict';

const { Command }      = require('commander');
const { Scanner }      = require('../lib/scanner');
const { parseTargets } = require('../lib/target');
const { parsePorts }   = require('../lib/ports');
const { printResult, printHeader, printSummary } = require('../lib/output');

const program = new Command();

program
    .name('rcn-scan')
    .description('RCN port scanner — TCP/SYN/UDP/banner with optional Tor routing')
    .version('1.0.0')
    .argument('<targets...>', 'Hosts to scan: IPs, CIDR, ranges, hostnames')
    .option('-p, --ports <spec>',       'Port spec: 80, 80-1024, 80,443,8080-8090', '1-1024')
    .option('-s, --scan-type <type>',   'Scan type: connect, syn, fin, null, xmas, udp', 'connect')
    .option('-c, --concurrency <n>',    'Max parallel probes', '100')
    .option('-t, --timeout <ms>',       'Probe timeout in ms', '3000')
    .option('--tor',                    'Route TCP connections through Tor (127.0.0.1:9050)')
    .option('--proxy <host:port>',      'Custom SOCKS5 proxy (overrides --tor default)')
    .option('--iface <name>',           'Network interface for raw scans (default: auto)')
    .option('--open',                   'Only show open ports')
    .option('--json',                   'Output JSON instead of human-readable text')
    .parse();

const opts    = program.opts();
const targets = program.args;

const proxyOpts = opts.proxy
    ? (() => { const [h, p] = opts.proxy.split(':'); return { host: h, port: parseInt(p, 10), type: 5 }; })()
    : { host: '127.0.0.1', port: 9050, type: 5 };

const scanner = new Scanner({
    scanType:    opts.scanType,
    concurrency: parseInt(opts.concurrency, 10),
    timeout:     parseInt(opts.timeout, 10),
    tor:         opts.tor || !!opts.proxy,
    proxy:       proxyOpts,
    iface:       opts.iface || null,
});

scanner.on('warning', (msg) => process.stderr.write(`\x1b[33m[warn]\x1b[0m ${msg}\n`));

const results = [];

if (!opts.json) printHeader();

scanner.on('result', (r) => {
    results.push(r);
    if (opts.json) return;
    printResult(r, { onlyOpen: opts.open });
});

const start  = Date.now();
const hosts  = parseTargets(targets);
const ports  = parsePorts(opts.ports);

(async () => {
    try {
        await scanner.scan(hosts, ports);

        if (opts.json) {
            const out = opts.open ? results.filter(r => r.state === 'open') : results;
            console.log(JSON.stringify(out, null, 2));
        } else {
            printSummary(results, Date.now() - start);
        }
    } catch (err) {
        process.stderr.write(`\x1b[31m[error]\x1b[0m ${err.message}\n`);
        process.exit(1);
    }
})();
