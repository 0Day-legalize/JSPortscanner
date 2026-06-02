import fs  from "node:fs";
import net from "node:net";

const cfg = JSON.parse(fs.readFileSync(new URL("../config/settings.json", import.meta.url), "utf8")).honeypot;

const COWRIE_SSH_BANNERS   = cfg.cowrieSSHBanners;
const TPOT_PORT_COMBO      = new Set(cfg.tpotPortCombo);
const TPOT_MATCH_MIN       = cfg.tpotMatchMin;
const TELNET_PORT          = cfg.telnetPort;
const SUSPICIOUS_THRESHOLD = cfg.suspiciousPortThreshold;
const FTP_HONEYPOT_BANNERS = cfg.ftpHoneypotBanners;
const COWRIE_KEX_TELLS     = cfg.cowrieKexTells;
const COWRIE_MAC_TELLS     = cfg.cowrieMacTells;
const COWRIE_ENC_TELLS     = cfg.cowrieEncTells;
const COWRIE_HOSTKEY_TELLS = cfg.cowrieHostKeyTells;

// Real distro-packaged OpenSSH always includes an OS suffix — bare version strings are a Cowrie tell
const SSH_DISTRO_SUFFIX = new RegExp(`SSH-2\\.0-OpenSSH_[\\d.p]+\\s+(${cfg.sshDistroKeywords.join("|")})`, "i");

// --- ʕ•ᴥ•ʔ ssh kex fingerprint ʕ•ᴥ•ʔ ---

/**
 * Connects to an SSH port, reads the server's KEX_INIT packet, and returns
 * the algorithm lists. Cowrie (via twisted.conch) advertises legacy algorithms
 * that modern OpenSSH dropped — this detects it without needing credentials.
 *
 * @param {string} host
 * @param {number} port
 * @returns {Promise<{kexAlgos, hostKeyAlgos, encAlgos, macAlgos}|null>}
 */
function probeSSHFingerprint(host, port) {
    return new Promise((resolve) => {
        const socket = net.createConnection({ host, port });
        let buf        = Buffer.alloc(0);
        let bannerDone = false;

        socket.setTimeout(5000);
        socket.on("timeout", () => { socket.destroy(); resolve(null); });
        socket.on("error",   () => resolve(null));

        socket.on("connect", () => {
            // impersonate a real SSH client to avoid leaving an identifiable version string in logs
            socket.write("SSH-2.0-OpenSSH_9.9\r\n");
        });

        socket.on("data", (chunk) => {
            buf = Buffer.concat([buf, chunk]);

            // strip the banner line first
            if (!bannerDone) {
                const end = buf.indexOf("\r\n");
                if (end === -1) return;
                bannerDone = true;
                buf = buf.slice(end + 2);
            }

            // need at least the 4-byte packet length + 1-byte padding length + 1-byte msg type
            if (buf.length < 6) return;

            const packetLen   = buf.readUInt32BE(0);
            if (buf.length < 4 + packetLen) return;

            const paddingLen  = buf[4];
            const payload     = buf.slice(5, 4 + packetLen - paddingLen);

            // MSG_KEXINIT = 20
            if (payload[0] !== 20) { socket.destroy(); resolve(null); return; }

            // payload layout: 1 byte type + 16 bytes cookie + name-lists
            let offset = 17;

            function readNameList() {
                if (offset + 4 > payload.length) return [];
                const len = payload.readUInt32BE(offset); offset += 4;
                if (offset + len > payload.length) return [];
                const str = payload.slice(offset, offset + len).toString("utf8"); offset += len;
                return str ? str.split(",") : [];
            }

            const kexAlgos     = readNameList();
            const hostKeyAlgos = readNameList();
            const encAlgos     = readNameList(); // client→server
            readNameList();                      // enc server→client (skip)
            const macAlgos     = readNameList(); // client→server

            socket.destroy();
            resolve({ kexAlgos, hostKeyAlgos, encAlgos, macAlgos });
        });
    });
}

/**
 * Checks a parsed SSH KEX fingerprint against known Cowrie algorithm tells.
 * Returns an array of reason strings, empty if nothing suspicious.
 *
 * @param {{kexAlgos, hostKeyAlgos, encAlgos, macAlgos}} fp
 * @param {number} port
 * @returns {string[]}
 */
function checkSSHFingerprint(fp, port) {
    const reasons = [];

    for (const algo of COWRIE_KEX_TELLS)
        if (fp.kexAlgos.includes(algo))
            reasons.push(`Cowrie KEX algorithm on port ${port}: ${algo}`);

    for (const algo of COWRIE_MAC_TELLS)
        if (fp.macAlgos.includes(algo))
            reasons.push(`Cowrie MAC algorithm on port ${port}: ${algo}`);

    for (const algo of COWRIE_ENC_TELLS)
        if (fp.encAlgos.includes(algo))
            reasons.push(`Cowrie cipher on port ${port}: ${algo}`);

    for (const algo of COWRIE_HOSTKEY_TELLS)
        if (fp.hostKeyAlgos.includes(algo))
            reasons.push(`Cowrie host key type on port ${port}: ${algo}`);

    return reasons;
}

// --- ʕ•ᴥ•ʔ static detection ʕ•ᴥ•ʔ ---

/**
 * Checks scan result ports against static honeypot indicators.
 * Returns an array of reason strings.
 *
 * @param {object} ports - Port map from scan JSON { "22": { proto: "TCP", banner: "..." }, ... }
 * @returns {string[]}
 */
function checkHost(ports) {
    const reasons  = [];
    const openPorts = Object.keys(ports).map(Number);

    for (const [port, value] of Object.entries(ports)) {
        // support both old string format and new object format
        const proto  = typeof value === "object" ? value.proto   : value.split(":")[0].trim();
        const banner = typeof value === "object" ? (value.banner || "") : value.replace(/^TCP: |^TLS: /, "");

        const isSSH = proto === "TCP" && banner.startsWith("SSH-2.0-OpenSSH");
        const isFTP = proto === "TCP" && banner.startsWith("220");

        // exact Cowrie SSH banner — takes priority to avoid double-flagging
        const cowrieMatch = isSSH && COWRIE_SSH_BANNERS.find(b => banner.includes(b));
        if (cowrieMatch) {
            reasons.push(`Cowrie SSH banner on port ${port}: "${cowrieMatch}"`);
            continue;
        }

        // SSH banner with no OS distro suffix
        if (isSSH && !SSH_DISTRO_SUFFIX.test(banner)) {
            reasons.push(`SSH banner missing OS suffix on port ${port}: "${banner}"`);
        }

        // FTP banner matches known honeypot strings
        if (isFTP) {
            const ftpMatch = FTP_HONEYPOT_BANNERS.find(b => banner.includes(b));
            if (ftpMatch) reasons.push(`Honeypot FTP banner on port ${port}: "${ftpMatch}"`);
        }
    }

    // Telnet open — almost never legitimate on modern servers
    if (openPorts.includes(TELNET_PORT))
        reasons.push(`Telnet (port 23) open — almost always a honeypot`);

    // T-Pot port combination
    const tpotMatches = openPorts.filter(p => TPOT_PORT_COMBO.has(p));
    if (tpotMatches.length >= TPOT_MATCH_MIN)
        reasons.push(`T-Pot port combination: ${tpotMatches.join(", ")}`);

    // suspiciously many open ports
    if (openPorts.length >= SUSPICIOUS_THRESHOLD)
        reasons.push(`${openPorts.length} ports open — unusually high`);

    return reasons;
}

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const [scanFile] = process.argv.slice(2);

if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(`
  RCN Honeypot Detector

  usage:
    node src/honeypot.js <scan.json> [--help]

  what it checks:
    - known Cowrie SSH banners
    - SSH banners missing OS suffix (bare version strings)
    - live SSH KEX fingerprint (connects and reads algorithm lists)
    - known honeypot FTP banners
    - Telnet port 23 open
    - T-Pot port combination
    - suspiciously many open ports

  example:
    node src/honeypot.js scans/results.json
`);
    process.exit(0);
}

if (!scanFile) {
    console.error("usage: node src/honeypot.js <scan.json>");
    process.exit(1);
}

const scanResults = JSON.parse(fs.readFileSync(scanFile, "utf8"));
let flagged = 0;

for (const entry of scanResults) {
    const reasons = checkHost(entry.ports);

    // live SSH KEX fingerprint probe for any SSH port found
    for (const [portStr, value] of Object.entries(entry.ports)) {
        const proto  = typeof value === "object" ? value.proto   : value.split(":")[0].trim();
        const banner = typeof value === "object" ? (value.banner || "") : value.replace(/^TCP: /, "");
        if (proto !== "TCP" || !banner.startsWith("SSH")) continue;
        const fp = await probeSSHFingerprint(entry.host, Number(portStr));
        if (fp) reasons.push(...checkSSHFingerprint(fp, portStr));
    }

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
