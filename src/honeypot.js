import fs from "node:fs";

const cfg = JSON.parse(fs.readFileSync(new URL("../config/settings.json", import.meta.url), "utf8")).honeypot;

const COWRIE_SSH_BANNERS   = cfg.cowrieSSHBanners;
const TPOT_PORT_COMBO      = new Set(cfg.tpotPortCombo);
const TPOT_MATCH_MIN       = cfg.tpotMatchMin;
const TELNET_PORT          = cfg.telnetPort;
const SUSPICIOUS_THRESHOLD = cfg.suspiciousPortThreshold;

// Real distro-packaged OpenSSH always includes an OS suffix — bare version strings are a Cowrie tell
const SSH_DISTRO_SUFFIX = new RegExp(`SSH-2\\.0-OpenSSH_[\\d.p]+\\s+(${cfg.sshDistroKeywords.join("|")})`, "i");

// --- detection logic ---

function checkHost(ports) {
    const reasons = [];
    const openPorts = Object.keys(ports).map(Number);

    for (const [port, value] of Object.entries(ports)) {
        const isSSH = value.startsWith("TCP: SSH-2.0-OpenSSH");

        // exact Cowrie banner match takes priority — skip bare-suffix check to avoid double-flagging
        const cowrieMatch = isSSH && COWRIE_SSH_BANNERS.find(b => value.includes(b));
        if (cowrieMatch) {
            reasons.push(`Cowrie SSH banner on port ${port}: "${cowrieMatch}"`);
            continue;
        }

        // bare version string with no OS suffix — real distro packages always include one
        if (isSSH && !SSH_DISTRO_SUFFIX.test(value)) {
            reasons.push(`SSH banner missing OS suffix on port ${port} — possible honeypot: "${value.replace("TCP: ", "")}"`);
        }
    }

    // Telnet open — not found on legitimate modern servers
    if (openPorts.includes(TELNET_PORT)) {
        reasons.push(`Telnet (port 23) open — almost always a honeypot on modern networks`);
    }

    // check for T-Pot port combination
    const tpotMatches = openPorts.filter(p => TPOT_PORT_COMBO.has(p));
    if (tpotMatches.length >= TPOT_MATCH_MIN) {
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
    const reasons = checkHost(entry.ports);

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
