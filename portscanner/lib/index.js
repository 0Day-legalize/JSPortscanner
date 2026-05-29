'use strict';

const { Scanner }      = require('./scanner');
const { parseTargets } = require('./target');
const { parsePorts }   = require('./ports');

// Convenience wrapper — scan(targets, portSpec, opts) → Promise<results[]>
async function scan(targets, portSpec, opts = {}) {
    const hosts   = parseTargets(Array.isArray(targets) ? targets : [targets]);
    const ports   = parsePorts(portSpec);
    const scanner = new Scanner(opts);
    return scanner.scan(hosts, ports);
}

module.exports = { Scanner, scan, parseTargets, parsePorts };
