'use strict';

// Expands targets into a flat array of IP strings.
// Accepts: single IP, CIDR, dash-range, or hostname.

function ipToLong(ip) {
    return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function longToIp(n) {
    return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

function parseCIDR(cidr) {
    const [base, bits] = cidr.split('/');
    const mask = bits === '32' ? 0xffffffff : ~(0xffffffff >>> parseInt(bits, 10)) >>> 0;
    const network = ipToLong(base) & mask;
    const broadcast = network | (~mask >>> 0);
    const ips = [];
    for (let i = network + 1; i < broadcast; i++) ips.push(longToIp(i));
    if (bits === '32') return [base];
    return ips;
}

function parseDashRange(range) {
    const parts = range.split('-');
    // Support both 192.168.1.1-192.168.1.254 and 192.168.1.1-254
    let endIp;
    if (parts[1].includes('.')) {
        endIp = parts[1];
    } else {
        const prefix = parts[0].split('.').slice(0, 3).join('.');
        endIp = `${prefix}.${parts[1]}`;
    }
    const start = ipToLong(parts[0]);
    const end = ipToLong(endIp);
    const ips = [];
    for (let i = start; i <= end; i++) ips.push(longToIp(i));
    return ips;
}

function isIPv4(str) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(str);
}

function parseTarget(target) {
    if (target.includes('/')) return parseCIDR(target);
    if (target.includes('-')) return parseDashRange(target);
    return [target]; // single IP or hostname
}

function parseTargets(targets) {
    return targets.flatMap(parseTarget);
}

module.exports = { parseTargets, parseTarget, ipToLong, longToIp };
