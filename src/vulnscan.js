import fs   from "node:fs";
import path from "node:path";
import https from "node:https";

// --- ʕ•ᴥ•ʔ banner parsers ʕ•ᴥ•ʔ ---

// Each entry: { name, cpe, regex }
// name    = human-readable product name
// cpe     = CPE 2.3 vendor:product prefix used in NVD queries
// regex   = extracts version string from banner
const PARSERS = [
    { name: "OpenSSH",   cpe: "openbsd:openssh",       regex: /OpenSSH[_\s]([\d.p]+)/i },
    { name: "nginx",     cpe: "nginx:nginx",            regex: /nginx\/([\d.]+)/i },
    { name: "Apache",    cpe: "apache:http_server",     regex: /Apache\/([\d.]+)/i },
    { name: "Exim",      cpe: "exim:exim",              regex: /Exim\s+([\d.]+)/i },
    { name: "Postfix",   cpe: "postfix:postfix",        regex: /Postfix\s+([\d.]+)/i },
    { name: "Dovecot",   cpe: "dovecot:dovecot",        regex: /Dovecot\s+([\d.]+)/i },
    { name: "ProFTPD",   cpe: "proftpd:proftpd",        regex: /ProFTPD\s+([\d.]+)/i },
    { name: "vsftpd",    cpe: "vsftpd_project:vsftpd",  regex: /vsftpd\s+([\d.]+)/i },
    { name: "OpenSSL",   cpe: "openssl:openssl",        regex: /OpenSSL\/([\d.]+[a-z]*)/i },
    { name: "PHP",       cpe: "php:php",                regex: /PHP\/([\d.]+)/i },
    { name: "WordPress", cpe: "wordpress:wordpress",    regex: /WordPress\/([\d.]+)/i },
];

/**
 * Parses all banners and headers in a port entry and returns any matched software versions.
 *
 * @param {object} portInfo - Port entry from scan JSON ({ proto, banner, headers, ... })
 * @returns {{ name: string, version: string, cpe: string }[]}
 */
function parseBanners(portInfo) {
    // support both old string format ("TCP: SSH-2.0-...") and new object format
    const bannerText = typeof portInfo === "string"
        ? portInfo.replace(/^(TCP|TLS|UDP|SMTP):\s*/i, "")
        : portInfo.banner || "";

    const texts = [
        bannerText,
        ...Object.values(typeof portInfo === "object" ? (portInfo.headers || {}) : {}),
        typeof portInfo === "object" ? (portInfo.cert?.cn || "") : "",
    ].join(" ");

    const matches = [];
    for (const parser of PARSERS) {
        const m = texts.match(parser.regex);
        if (m) matches.push({ name: parser.name, version: m[1], cpe: parser.cpe });
    }
    return matches;
}

// --- ʕ•ᴥ•ʔ nvd api ʕ•ᴥ•ʔ ---

/**
 * Queries the NVD REST API for CVEs matching a CPE string and version.
 * Rate-limited by NVD to ~5 requests/30s without an API key.
 * Returns up to 5 CVEs sorted by severity.
 *
 * @param {string} cpe     - CPE vendor:product string (e.g. "openbsd:openssh")
 * @param {string} version - Version string (e.g. "8.2p1")
 * @returns {Promise<Array>}
 */
function queryCVEs(cpe, version) {
    return new Promise((resolve) => {
        const keyword = encodeURIComponent(`${cpe.split(":")[1]} ${version}`);
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`;

        https.get(url, { headers: { "User-Agent": "RCN-Scanner/1.0" } }, (res) => {
            let data = "";
            res.on("data", chunk => { data += chunk; });
            res.on("end", () => {
                try {
                    const json  = JSON.parse(data);
                    const items = (json.vulnerabilities || []).map(v => {
                        const cve     = v.cve;
                        const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];
                        const score   = metrics?.cvssData?.baseScore || null;
                        const sev     = metrics?.cvssData?.baseSeverity || metrics?.baseSeverity || null;
                        return {
                            id:          cve.id,
                            severity:    sev,
                            score:       score,
                            summary:     cve.descriptions?.find(d => d.lang === "en")?.value?.slice(0, 120) || "",
                            url:         `https://nvd.nist.gov/vuln/detail/${cve.id}`,
                        };
                    });
                    // sort by score descending — highest severity first
                    items.sort((a, b) => (b.score || 0) - (a.score || 0));
                    resolve(items);
                } catch { resolve([]); }
            });
        }).on("error", () => resolve([]));
    });
}

// NVD allows ~5 requests per 30 seconds without an API key
// sleep between requests to avoid 403 rate-limit responses
function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const [scanFile] = process.argv.slice(2);

if (process.argv.includes("--help") || process.argv.includes("-h") || !scanFile) {
    console.log(`
  RCN Vulnerability Scanner

  usage:
    node src/vulnscan.js <scan.json>

  what it does:
    parses software versions from banners and HTTP headers,
    queries the NVD API for matching CVEs, and writes results
    back into the scan JSON under a "cves" field per port.

  note:
    NVD rate-limits unauthenticated requests to ~5/30s.
    scans with many open ports will take a few minutes.

  example:
    node src/vulnscan.js scans/results.json
`);
    process.exit(scanFile ? 0 : 1);
}

const scanResults = JSON.parse(fs.readFileSync(scanFile, "utf8"));
let queriesMade   = 0;

for (const host of scanResults) {
    console.log(`[ ${host.host} ]`);

    for (const [portNum, portInfo] of Object.entries(host.ports)) {
        const software = parseBanners(portInfo);
        if (software.length === 0) continue;

        const allCVEs = [];

        for (const sw of software) {
            console.log(`  checking ${sw.name} ${sw.version} on port ${portNum}...`);

            // respect NVD rate limit — sleep every 5 requests
            if (queriesMade > 0 && queriesMade % 5 === 0) {
                process.stdout.write("  rate limit pause (6s)...\r");
                await sleep(6000);
            }

            const cves = await queryCVEs(sw.cpe, sw.version);
            queriesMade++;

            if (cves.length > 0) {
                allCVEs.push({ software: `${sw.name} ${sw.version}`, cves });
                console.log(`  found ${cves.length} CVE(s) for ${sw.name} ${sw.version}`);
                for (const c of cves) {
                    const sev = c.severity ? `[${c.severity}]` : "";
                    console.log(`    ${c.id} ${sev} score=${c.score ?? "?"} — ${c.summary}`);
                }
            } else {
                console.log(`  no CVEs found for ${sw.name} ${sw.version}`);
            }
        }

        if (allCVEs.length > 0) portInfo.cves = allCVEs;
    }
}

// write back — fall back to home dir if scans/ is owned by root
let outPath = scanFile;
try {
    fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2), "utf8");
} catch (e) {
    if (e.code === "EACCES") {
        outPath = path.join(process.env.HOME, path.basename(scanFile));
        fs.writeFileSync(outPath, JSON.stringify(scanResults, null, 2), "utf8");
    } else throw e;
}
console.log(`\nsaved to ${path.resolve(outPath)}`);
