    #!/usr/bin/env node

    'use strict';

    const net    = require('net');
    const dgram  = require('dgram');
    const dns    = require('dns').promises;
    const { parseArgs } = require('util');

    // ── ANSI colours ────────────────────────────────────────────────────────────
    const C = {
    reset:  '\x1b[0m',
    green:  '\x1b[32m',
    red:    '\x1b[31m',
    yellow: '\x1b[33m',
    cyan:   '\x1b[36m',
    bold:   '\x1b[1m',
    dim:    '\x1b[2m',
    };

    function colorStatus(status) {
    if (status === 'open')           return C.green  + status + C.reset;
    if (status === 'closed')         return C.red    + status + C.reset;
    if (status === 'open|filtered')  return C.yellow + status + C.reset;
    if (status === 'filtered')       return C.dim    + status + C.reset;
    return status;
    }

    // ── Port range parser ────────────────────────────────────────────────────────
    // Accepts: "22", "80,443", "1-1024", "22,80,8000-9000"
    function parsePorts(str) {
    const ports = new Set();
    for (const part of str.split(',')) {
        const trimmed = part.trim();
        if (trimmed.includes('-')) {
        const [a, b] = trimmed.split('-').map(Number);
        if (isNaN(a) || isNaN(b) || a < 1 || b > 65535 || a > b)
            throw new Error(`Invalid range: ${trimmed}`);
        for (let p = a; p <= b; p++) ports.add(p);
        } else {
        const p = Number(trimmed);
        if (isNaN(p) || p < 1 || p > 65535)
            throw new Error(`Invalid port: ${trimmed}`);
        ports.add(p);
        }
    }
    return [...ports].sort((a, b) => a - b);
    }

    // ── TCP scan ─────────────────────────────────────────────────────────────────
    function scanTCP(host, port, timeout) {
    return new Promise((resolve) => {
        const sock = new net.Socket();
        let done = false;

        function finish(status) {
        if (done) return;
        done = true;
        sock.destroy();
        resolve({ port, protocol: 'TCP', status });
        }

        sock.setTimeout(timeout);
        sock.on('connect', ()      => finish('open'));
        sock.on('timeout', ()      => finish('filtered'));
        sock.on('error', (err) => {
        if (err.code === 'ECONNREFUSED')                    finish('closed');
        else if (err.code === 'EHOSTUNREACH' ||
                err.code === 'ENETUNREACH')                finish('unreachable');
        else                                                finish('filtered');
        });

        sock.connect(port, host);
    });
    }

    // ── UDP scan ─────────────────────────────────────────────────────────────────
    // Uses a connected UDP socket so ICMP port-unreachable comes back as ECONNREFUSED.
    // Result: open (got data), closed (ICMP unreachable), open|filtered (timeout)
    function scanUDP(host, port, timeout) {
    return new Promise((resolve) => {
        const sock = dgram.createSocket('udp4');
        let done = false;

        function finish(status) {
        if (done) return;
        done = true;
        try { sock.close(); } catch {}
        resolve({ port, protocol: 'UDP', status });
        }

        sock.on('message', () => finish('open'));

        sock.on('error', (err) => {
        if (err.code === 'ECONNREFUSED') finish('closed');
        else                             finish('open|filtered');
        });

        // connect() makes it a "connected" UDP socket — required for ICMP feedback
        sock.connect(port, host, (err) => {
        if (err) return finish('error');

        // Service-specific probes improve open-port detection
        const probe = udpProbe(port);
        sock.send(probe, (sendErr) => {
            if (sendErr) return finish('error');
            setTimeout(() => finish('open|filtered'), timeout);
        });
        });
    });
    }

    // Basic service probes for common UDP ports
    function udpProbe(port) {
    switch (port) {
        case 53:   // DNS query for "."
        return Buffer.from([
            0xaa,0xbb, 0x01,0x00, 0x00,0x01, 0x00,0x00,
            0x00,0x00, 0x00,0x00, 0x00, 0x01,0x00,0x01
        ]);
        case 123:  // NTP client request
        return Buffer.from([0x1b, ...new Array(47).fill(0)]);
        case 161:  // SNMP GetRequest (v1, public)
        return Buffer.from('302602010004067075626c6963a01902046e4f13340201000201003082000a', 'hex');
        case 137:  // NetBIOS name query
        return Buffer.from([
            0xab,0xcd, 0x00,0x00, 0x00,0x01, 0x00,0x00,
            0x00,0x00, 0x00,0x00, 0x20,0x43,0x4b,0x41,
            0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
            0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
            0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
            0x41,0x41,0x41,0x41,0x41,0x00, 0x00,0x21,0x00,0x01
        ]);
        default:
        return Buffer.alloc(0);
    }
    }

    // ── Concurrency limiter ───────────────────────────────────────────────────────
    async function runConcurrent(tasks, concurrency, onResult) {
    let i = 0;
    async function worker() {
        while (i < tasks.length) {
        const result = await tasks[i++]();
        onResult(result);
        }
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));
    }

    // ── Progress bar ─────────────────────────────────────────────────────────────
    function makeProgress(total) {
    let done = 0;
    const width = 30;
    return function tick() {
        done++;
        const pct  = done / total;
        const filled = Math.round(pct * width);
        const bar  = '█'.repeat(filled) + '░'.repeat(width - filled);
        process.stderr.write(`\r${C.dim}[${bar}] ${done}/${total}${C.reset}`);
        if (done === total) process.stderr.write('\n');
    };
    }

    // ── Resolve hostname ──────────────────────────────────────────────────────────
    async function resolveHost(host) {
    try {
        const result = await dns.lookup(host);
        return result.address;
    } catch {
        throw new Error(`Cannot resolve host: ${host}`);
    }
    }

    // ── Main ──────────────────────────────────────────────────────────────────────
    async function main() {
    let parsed;
    try {
        parsed = parseArgs({
        options: {
            host:        { type: 'string',  short: 'h' },
            ports:       { type: 'string',  short: 'p', default: '1-1024' },
            protocol:    { type: 'string',  short: 'P', default: 'both' },
            timeout:     { type: 'string',  short: 't', default: '1000' },
            concurrency: { type: 'string',  short: 'c', default: '150' },
            all:         { type: 'boolean', short: 'a', default: false },
            json:        { type: 'boolean', short: 'j', default: false },
            help:        { type: 'boolean', short: '?', default: false },
        },
        strict: true,
        });
    } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }

    const { values } = parsed;

    if (values.help || !values.host) {
        console.log(`
    ${C.bold}PortScanner${C.reset} — TCP/UDP port scanner

    ${C.cyan}Usage:${C.reset}
    node portscanner.js -h <host> [options]

    ${C.cyan}Options:${C.reset}
    -h, --host         Target host (IP or hostname)
    -p, --ports        Port spec: 22 | 80,443 | 1-1024 | 22,8000-9000  (default: 1-1024)
    -P, --protocol     tcp | udp | both  (default: both)
    -t, --timeout      Timeout per port in ms  (default: 1000)
    -c, --concurrency  Parallel probes  (default: 150)
    -a, --all          Show closed/filtered ports too
    -j, --json         JSON output
    -?, --help         Show this help

    ${C.cyan}Examples:${C.reset}
    node portscanner.js -h 192.168.1.1
    node portscanner.js -h example.com -p 1-65535 -P tcp -c 500 -t 500
    node portscanner.js -h 10.0.0.1 -p 53,123,161 -P udp -a
    node portscanner.js -h 192.168.1.1 -j | jq '.[] | select(.status=="open")'
    `);
        process.exit(0);
    }

    const protocol    = values.protocol.toLowerCase();
    const timeout     = parseInt(values.timeout, 10);
    const concurrency = parseInt(values.concurrency, 10);
    const showAll     = values.all;
    const jsonOutput  = values.json;

    if (!['tcp','udp','both'].includes(protocol)) {
        console.error('--protocol must be tcp, udp, or both');
        process.exit(1);
    }

    let ports;
    try {
        ports = parsePorts(values.ports);
    } catch (err) {
        console.error(`Port parse error: ${err.message}`);
        process.exit(1);
    }

    let ip;
    try {
        ip = await resolveHost(values.host);
    } catch (err) {
        console.error(err.message);
        process.exit(1);
    }

    const tasks = [];
    for (const port of ports) {
        if (protocol === 'tcp' || protocol === 'both') tasks.push(() => scanTCP(ip, port, timeout));
        if (protocol === 'udp' || protocol === 'both') tasks.push(() => scanUDP(ip, port, timeout));
    }

    if (!jsonOutput) {
        console.log(`\n${C.bold}Target:${C.reset}  ${values.host}${ip !== values.host ? ` (${ip})` : ''}`);
        console.log(`${C.bold}Ports:${C.reset}   ${ports.length} port(s)  |  Protocol: ${protocol.toUpperCase()}  |  Timeout: ${timeout}ms  |  Concurrency: ${concurrency}`);
        console.log(`${C.bold}Tasks:${C.reset}   ${tasks.length} total probes\n`);
        console.log(`${C.dim}PROTO   PORT    STATUS${C.reset}`);
        console.log('─'.repeat(32));
    }

    const results = [];
    const tick = makeProgress(tasks.length);

    await runConcurrent(tasks, concurrency, (result) => {
        tick();
        results.push(result);

        if (!jsonOutput) {
        const { protocol: proto, port, status } = result;
        const show = showAll || status === 'open' || status === 'open|filtered';
        if (show) {
            const line = `${proto.padEnd(6)}  ${String(port).padStart(5)}   ${colorStatus(status)}`;
            // Print above the progress bar by clearing the line first
            process.stdout.write(`\r\x1b[K${line}\n`);
        }
        }
    });

    // Sort results for clean output
    results.sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));

    if (jsonOutput) {
        const out = showAll ? results : results.filter(r => r.status === 'open' || r.status === 'open|filtered');
        console.log(JSON.stringify(out, null, 2));
        return;
    }

    const open         = results.filter(r => r.status === 'open');
    const openFiltered = results.filter(r => r.status === 'open|filtered');

    console.log('─'.repeat(32));
    console.log(`\n${C.bold}Summary${C.reset}`);
    console.log(`  ${C.green}Open:${C.reset}          ${open.length}`);
    console.log(`  ${C.yellow}Open|Filtered:${C.reset} ${openFiltered.length}`);
    console.log(`  Total probed:  ${results.length}\n`);
    }

    main().catch((err) => {
    console.error(`Fatal: ${err.message}`);
    process.exit(1);
    });
