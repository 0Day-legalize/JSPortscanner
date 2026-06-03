// created with Claude (https://claude.ai) — @claude
import fs   from "node:fs";
import path from "node:path";
import http  from "node:http";

// --- ʕ•ᴥ•ʔ ip-api batch lookup ʕ•ᴥ•ʔ ---
// API reference: http://ip-api.com/docs/api:batch
// Free tier: 15 requests/minute, 100 IPs per batch request, no HTTPS

const BATCH_SIZE     = 100;  // ip-api batch endpoint maximum
const RATE_LIMIT_MS  = 4500; // 15 req/min = one batch every 4s to stay safe

/**
 * Queries ip-api.com batch endpoint for up to 100 IPs at once.
 * Returns an array of geo objects in the same order as the input.
 *
 * @param {string[]} ips - Array of IP addresses (max 100)
 * @returns {Promise<object[]>}
 */
function batchGeoLookup(ips) {
    return new Promise((resolve) => {
        const body = JSON.stringify(ips.map(ip => ({ query: ip, fields: "status,country,countryCode,city,lat,lon,isp,org,as" })));

        const req = http.request({
            hostname: "ip-api.com",
            path:     "/batch",
            method:   "POST",
            headers:  { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
        }, (res) => {
            let data = "";
            res.on("data", chunk => { data += chunk; });
            res.on("end", () => {
                try { resolve(JSON.parse(data)); }
                catch { resolve(ips.map(() => null)); }
            });
        });

        req.on("error", () => resolve(ips.map(() => null)));
        req.write(body);
        req.end();
    });
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const [scanFile] = process.argv.slice(2);

if (process.argv.includes("--help") || process.argv.includes("-h") || !scanFile) {
    console.log(`
  RCN Geolocate

  usage:
    node src/geolocate.js <scan.json>

  what it does:
    queries ip-api.com for country, city, lat/lon and ISP for each host
    and writes the results back into the scan JSON under a "geo" field.

  note:
    free tier — no signup needed, 15 batch requests per minute.
    does not use HTTPS (ip-api.com free tier limitation).

  example:
    node src/geolocate.js scans/results.json
`);
    process.exit(scanFile ? 0 : 1);
}

const scanResults = JSON.parse(fs.readFileSync(scanFile, "utf8"));
const ips         = scanResults.map(h => h.host);

console.log(`Geolocating ${ips.length} host(s) in batches of ${BATCH_SIZE}...\n`);

let processed = 0;

for (let i = 0; i < ips.length; i += BATCH_SIZE) {
    const batch     = ips.slice(i, i + BATCH_SIZE);
    const results   = await batchGeoLookup(batch);

    results.forEach((geo, idx) => {
        const entry = scanResults[i + idx];
        if (geo && geo.status === "success") {
            entry.geo = {
                country:     geo.country     ?? null,
                countryCode: geo.countryCode ?? null,
                city:        geo.city        ?? null,
                lat:         geo.lat         ?? null,
                lon:         geo.lon         ?? null,
                isp:         geo.isp         ?? null,
                org:         geo.org         ?? null,
                as:          geo.as          ?? null,
            };
            console.log(`  ${entry.host} — ${geo.city}, ${geo.country} (${geo.isp})`);
        } else {
            entry.geo = null;
            console.log(`  ${entry.host} — lookup failed`);
        }
        processed++;
    });

    process.stdout.write(`\r[${processed}/${ips.length}] done`);

    // respect rate limit between batches
    if (i + BATCH_SIZE < ips.length) await sleep(RATE_LIMIT_MS);
}

// write back — fall back to home dir if scans/ is root-owned
let outPath = scanFile;
try {
    fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2), "utf8");
} catch (e) {
    if (e.code === "EACCES") {
        outPath = path.join(process.env.HOME, path.basename(scanFile));
        fs.writeFileSync(outPath, JSON.stringify(scanResults, null, 2), "utf8");
    } else throw e;
}

console.log(`\n\nsaved to ${path.resolve(outPath)}`);
