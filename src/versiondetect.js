import fs   from "node:fs";
import path from "node:path";

// --- ʕ•ᴥ•ʔ version parsers ʕ•ᴥ•ʔ ---

/**
 * Each parser matches a specific service banner and extracts structured version info.
 * Ordered by specificity — more specific patterns first.
 *
 * @type {Array<{service: string, vendor: string, regex: RegExp, version: (m: RegExpMatchArray) => string}>}
 */
const PARSERS = [
    // SSH
    { service: "SSH",       vendor: "OpenSSH",    regex: /OpenSSH[_\s]([\d.p]+)(?:\s+(\S+))?/i,          version: m => m[1], os: m => m[2] || null },
    { service: "SSH",       vendor: "Dropbear",   regex: /dropbear[_\s]([\d.]+)/i,                        version: m => m[1] },

    // HTTP servers
    { service: "HTTP",      vendor: "nginx",      regex: /nginx\/([\d.]+)/i,                              version: m => m[1] },
    { service: "HTTP",      vendor: "Apache",     regex: /Apache\/([\d.]+)/i,                             version: m => m[1] },
    { service: "HTTP",      vendor: "lighttpd",   regex: /lighttpd\/([\d.]+)/i,                           version: m => m[1] },
    { service: "HTTP",      vendor: "Microsoft-IIS", regex: /Microsoft-IIS\/([\d.]+)/i,                   version: m => m[1] },
    { service: "HTTP",      vendor: "Caddy",      regex: /Caddy(?:\/([\d.]+))?/i,                         version: m => m[1] || "" },
    { service: "HTTP",      vendor: "OpenResty",  regex: /openresty\/([\d.]+)/i,                          version: m => m[1] },

    // App frameworks
    { service: "HTTP",      vendor: "PHP",        regex: /PHP\/([\d.]+)/i,                                version: m => m[1] },
    { service: "HTTP",      vendor: "WordPress",  regex: /WordPress\/([\d.]+)/i,                          version: m => m[1] },

    // FTP
    { service: "FTP",       vendor: "ProFTPD",    regex: /ProFTPD\s+([\d.]+)/i,                           version: m => m[1] },
    { service: "FTP",       vendor: "vsftpd",     regex: /vsftpd\s+([\d.]+)/i,                            version: m => m[1] },
    { service: "FTP",       vendor: "FileZilla",  regex: /FileZilla Server\s+([\d.]+)/i,                  version: m => m[1] },
    { service: "FTP",       vendor: "Pure-FTPd",  regex: /Pure-FTPd/i,                                    version: () => "" },

    // Mail
    { service: "SMTP",      vendor: "Postfix",    regex: /Postfix\s+([\d.]+)?/i,                          version: m => m[1] || "" },
    { service: "SMTP",      vendor: "Exim",       regex: /Exim\s+([\d.]+)/i,                              version: m => m[1] },
    { service: "SMTP",      vendor: "Sendmail",   regex: /Sendmail\s+([\d./]+)/i,                         version: m => m[1] },
    { service: "IMAP",      vendor: "Dovecot",    regex: /Dovecot\s+([\d.]+)?/i,                          version: m => m[1] || "" },
    { service: "POP3",      vendor: "Dovecot",    regex: /Dovecot\s+([\d.]+)?/i,                          version: m => m[1] || "" },
    { service: "SMTP",      vendor: "Exchange",   regex: /Microsoft ESMTP MAIL Service/i,                 version: () => "" },

    // Database
    { service: "MySQL",     vendor: "MySQL",      regex: /(\d+\.\d+\.\d+)-[Mm]y[Ss][Qq][Ll]/,            version: m => m[1] },
    { service: "MySQL",     vendor: "MariaDB",    regex: /(\d+\.\d+\.\d+)-[Mm]aria[Dd][Bb]/,             version: m => m[1] },
    { service: "PostgreSQL",vendor: "PostgreSQL", regex: /PostgreSQL\s+([\d.]+)/i,                        version: m => m[1] },
    { service: "Redis",     vendor: "Redis",      regex: /redis_version:([\d.]+)/i,                       version: m => m[1] },
    { service: "MongoDB",   vendor: "MongoDB",    regex: /MongoDB\s+([\d.]+)/i,                           version: m => m[1] },

    // Other
    { service: "OpenVPN",   vendor: "OpenVPN",    regex: /OpenVPN\s+([\d.]+)/i,                           version: m => m[1] },
    { service: "Telnet",    vendor: "telnetd",    regex: /telnet/i,                                       version: () => "" },
    { service: "RDP",       vendor: "Windows RDP",regex: /RDPNL|RDP/i,                                    version: () => "" },
];

// --- ʕ•ᴥ•ʔ detection ʕ•ᴥ•ʔ ---

/**
 * Collects all text visible from a port entry — banner, HTTP headers, cert CN.
 *
 * @param {object|string} portInfo - Port entry from scan JSON
 * @returns {string}
 */
function extractText(portInfo) {
    if (typeof portInfo === "string") return portInfo;
    return [
        portInfo.banner || "",
        ...Object.values(portInfo.headers || {}),
        portInfo.cert?.cn || "",
        portInfo.cert?.org || "",
    ].join(" ");
}

/**
 * Runs all parsers against the visible text from a port entry and returns
 * the first match as a structured version object.
 *
 * @param {object|string} portInfo
 * @returns {{ service: string, vendor: string, version: string, os?: string }|null}
 */
function detectVersion(portInfo) {
    const text = extractText(portInfo);
    if (!text.trim()) return null;

    for (const parser of PARSERS) {
        const m = text.match(parser.regex);
        if (!m) continue;

        const result = {
            service: parser.service,
            vendor:  parser.vendor,
            version: parser.version(m) || null,
        };
        if (parser.os) result.os = parser.os(m);
        return result;
    }
    return null;
}

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const [scanFile] = process.argv.slice(2);

if (process.argv.includes("--help") || process.argv.includes("-h") || !scanFile) {
    console.log(`
  RCN Version Detector

  usage:
    node src/versiondetect.js <scan.json>

  what it does:
    parses banners, HTTP headers, and certificate fields to extract
    structured service/vendor/version info for each open port.
    writes results back to the scan JSON under a "version" field per port.

  example:
    node src/versiondetect.js scans/results.json
`);
    process.exit(scanFile ? 0 : 1);
}

const scanResults = JSON.parse(fs.readFileSync(scanFile, "utf8"));
let detected = 0;

for (const host of scanResults) {
    for (const [portNum, portInfo] of Object.entries(host.ports || {})) {
        const version = detectVersion(portInfo);
        if (version) {
            portInfo.version = version;
            detected++;
            console.log(`  ${host.host}:${portNum} — ${version.vendor} ${version.version}${version.os ? ` (${version.os})` : ""}`);
        }
    }
}

// write back — fall back to home dir on permission denied
let outPath = scanFile;
try {
    fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2), "utf8");
} catch (e) {
    if (e.code === "EACCES") {
        outPath = path.join(process.env.HOME, path.basename(scanFile));
        fs.writeFileSync(outPath, JSON.stringify(scanResults, null, 2), "utf8");
    } else throw e;
}

console.log(`\n${detected} version(s) detected — saved to ${path.resolve(outPath)}`);
