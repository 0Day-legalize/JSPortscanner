'use strict';

const chalk = require('chalk');

const STATE_COLOR = {
    open:           chalk.green,
    closed:         chalk.gray,
    filtered:       chalk.yellow,
    'open|filtered': chalk.yellow,
    error:          chalk.red,
};

function colorState(state) {
    return (STATE_COLOR[state] || chalk.white)(state.toUpperCase().padEnd(14));
}

function formatResult(r) {
    const proto   = r.proto === 'udp' ? 'UDP' : (r.tls ? 'TLS' : 'TCP');
    const service = r.service ? chalk.cyan(r.service.padEnd(16)) : ''.padEnd(16);
    const latency = r.latency ? chalk.dim(`${r.latency}ms`) : '';
    const scan    = r.scanType ? chalk.dim(`[${r.scanType}]`) : '';
    return `${colorState(r.state)} ${chalk.bold(r.host.padEnd(18))} ${String(r.port).padEnd(6)} ${proto.padEnd(4)} ${service} ${latency} ${scan}`;
}

function printResult(r, opts = {}) {
    if (opts.onlyOpen && r.state !== 'open') return;
    console.log(formatResult(r));
}

function printHeader() {
    console.log(chalk.dim('STATE          HOST               PORT   PROTO SERVICE          LATENCY'));
    console.log(chalk.dim('─'.repeat(75)));
}

function printSummary(results, elapsed) {
    const open     = results.filter(r => r.state === 'open').length;
    const filtered = results.filter(r => r.state === 'filtered' || r.state === 'open|filtered').length;
    const total    = results.length;
    console.log(chalk.dim('─'.repeat(75)));
    console.log(`${chalk.green(open + ' open')}  ${chalk.yellow(filtered + ' filtered')}  ${chalk.gray((total - open - filtered) + ' closed')}  — ${(elapsed / 1000).toFixed(1)}s`);
}

module.exports = { printResult, printHeader, printSummary, formatResult };
