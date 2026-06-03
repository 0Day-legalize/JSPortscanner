// code reviewed with Claude (https://claude.ai) + SonarQube — @claude
import fs  from "node:fs";
import net from "node:net";

// --- ʕ•ᴥ•ʔ whois lookup ʕ•ᴥ•ʔ ---

/**
 * Queries whois.ripe.net via TCP for a given IP and returns the raw response.
 * RIPE covers European IPs — most Hetzner addresses fall under RIPE.
 *
 * @param {string} ip
 * @returns {Promise<string|null>}
 */
function whoisLookup(ip) {
    return new Promise((resolve) => {
        const socket = net.createConnection({ host: "whois.ripe.net", port: 43 });
        let data = "";

        socket.setTimeout(5000);
        socket.on("timeout", () => { socket.destroy(); resolve(null); });
        socket.on("error",   () => resolve(null));

        socket.on("connect", () => socket.write(`${ip}\r\n`));
        socket.on("data",    (chunk) => { data += chunk.toString("utf8"); });
        socket.on("close",   () => resolve(data));
    });
}

/**
 * Parses a WHOIS response and extracts the organisation/network owner name.
 * Checks org-name, netname, and descr fields in order of reliability.
 *
 * @param {string} raw - Raw WHOIS response text
 * @returns {string} Owner name, or "unknown" if not found
 */
function parseOwner(raw) {
    if (!raw) return "unknown";

    const fields = ["org-name", "netname", "descr"];

    for (const field of fields) {
        const match = raw.match(new RegExp(`^${field}:\\s+(.+)$`, "im"));
        if (match) return match[1].trim();
    }

    return "unknown";
}

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const [scanFile] = process.argv.slice(2);

if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(`
  RCN WHOIS Enricher

  usage:
    node src/enrich.js <scan.json> [--help]

  what it does:
    queries whois.ripe.net for each host IP and adds an owner field
    to the scan JSON — useful for identifying Hetzner customers and
    other hosting providers.

  example:
    node src/enrich.js scans/results.json
`);
    process.exit(0);
}

if (!scanFile) {
    console.error("usage: node src/enrich.js <scan.json>");
    process.exit(1);
}

const scanResults = JSON.parse(fs.readFileSync(scanFile, "utf8"));

console.log(`Enriching ${scanResults.length} host(s) with WHOIS data...\n`);

let done = 0;

for (const entry of scanResults) {
    const raw   = await whoisLookup(entry.host);
    const owner = parseOwner(raw);

    entry.owner = owner;
    done++;

    process.stdout.write(`\r[${done}/${scanResults.length}] ${entry.host} — ${owner}`);
}

fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2), "utf8");
console.log(`\n\nDone. Results saved to ${scanFile}`);
