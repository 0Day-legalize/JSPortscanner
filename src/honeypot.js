import fs from "node:fs";

// --- known honeypot signatures ---

// Cowrie ships with hardcoded old OpenSSH banners — real servers don't run these
const COWRIE_SSH_BANNERS = [
    "SSH-2.0-OpenSSH_5.3",
    "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4",
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8",
    "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4",
    "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2",
];

// T-Pot runs many honeypot services simultaneously — this port combo is a strong signal
const TPOT_PORT_COMBO = new Set([21, 22, 23, 25, 80, 443, 445]);

// Ports that legitimate servers rarely expose all at once
const SUSPICIOUS_THRESHOLD = 6;

// --- detection logic ---

function checkHost(host, ports) {
    const reasons = [];
    const openPorts = Object.keys(ports).map(Number);

    // check SSH banner against known Cowrie fingerprints
    for (const [port, value] of Object.entries(ports)) {
        for (const banner of COWRIE_SSH_BANNERS) {
            if (value.includes(banner)) {
                reasons.push(`Cowrie SSH banner on port ${port}: "${banner}"`);
            }
        }
    }

    // check for T-Pot port combination
    const tpotMatches = openPorts.filter(p => TPOT_PORT_COMBO.has(p));
    if (tpotMatches.length >= 4) {
        reasons.push(`T-Pot port combination detected: ${tpotMatches.join(", ")}`);
    }

    // flag hosts with suspiciously many open ports
    if (openPorts.length >= SUSPICIOUS_THRESHOLD) {
        reasons.push(`${openPorts.length} ports open — unusually high for a single host`);
    }

    return reasons;
}

// --- main ---

const [scanFile] = process.argv.slice(2);

if (!scanFile) {
    console.error("usage: node src/honeypot.js <scan.json>");
    process.exit(1);
}

const scanResults = JSON.parse(fs.readFileSync(scanFile, "utf8"));
let flagged = 0;

for (const entry of scanResults) {
    const reasons = checkHost(entry.host, entry.ports);

    if (reasons.length > 0) {
        entry.honeypot = { suspected: true, reasons };
        flagged++;
        console.log(`[HONEYPOT] ${entry.host}`);
        for (const r of reasons) console.log(`  • ${r}`);
    } else {
        entry.honeypot = { suspected: false };
    }
}

fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2), "utf8");
console.log(`\n${flagged} suspected honeypot(s) flagged in ${scanFile}`);
