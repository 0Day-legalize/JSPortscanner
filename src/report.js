import fs   from "node:fs";
import path from "node:path";

// --- ʕ•ᴥ•ʔ helpers ʕ•ᴥ•ʔ ---

/**
 * HTML-escapes a value for safe inline insertion into HTML attributes and text content.
 *
 * @param {*} s - Value to escape; coerced to string; `null`/`undefined` treated as empty string
 * @returns {string} HTML-safe string
 */
const esc = (s) => String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

/**
 * Renders a pill-shaped inline badge with the given background colour.
 *
 * @param {string} text  - Label text (HTML-escaped before insertion)
 * @param {string} color - CSS colour value for the badge background
 * @returns {string} HTML `<span>` element string
 */
function badge(text, color) {
    return `<span class="badge" style="background:${color}">${esc(text)}</span>`;
}

/**
 * Renders one table row for an open port, including its protocol badge, banner, TLS certificate
 * details, HTTP response headers, and any CVEs found by vulnscan.js.
 *
 * @param {string} port - Port number string used as the row label
 * @param {object} info - Port entry from the scan JSON (`proto`, `banner`, `cert`, `headers`, `cves`)
 * @returns {string} HTML `<tr>` element string
 */
function portRow(port, info) {
    const proto  = info.proto  || "";
    const banner = info.banner || "";
    const cert   = info.cert   || null;
    const hdrs   = info.headers || null;
    const cves   = info.cves   || null;

    const protoColor = proto === "TLS" ? "#4caf50" : proto === "SYN" ? "#ff9800" : proto === "SMTP" ? "#9c27b0" : "#2196f3";

    let certHtml = "";
    if (cert) {
        const sans = cert.sans ? cert.sans.slice(0, 5).join(", ") + (cert.sans.length > 5 ? ` +${cert.sans.length - 5} more` : "") : "";
        certHtml = `
            <div class="cert">
                ${cert.cn  ? `<div><b>CN:</b> ${esc(cert.cn)}</div>`      : ""}
                ${cert.org ? `<div><b>Org:</b> ${esc(cert.org)}</div>`    : ""}
                ${cert.issuer ? `<div><b>Issuer:</b> ${esc(cert.issuer)}</div>` : ""}
                ${sans ? `<div><b>SANs:</b> ${esc(sans)}</div>`           : ""}
                ${cert.expires ? `<div><b>Expires:</b> ${esc(cert.expires)}</div>` : ""}
            </div>`;
    }

    let hdrsHtml = "";
    if (hdrs) {
        hdrsHtml = `<div class="headers">${Object.entries(hdrs).map(([k, v]) => `<div><b>${esc(k)}:</b> ${esc(v)}</div>`).join("")}</div>`;
    }

    let cvesHtml = "";
    if (cves) {
        const sevColor = (s) => ({ CRITICAL: "#f44336", HIGH: "#ff9800", MEDIUM: "#ffeb3b", LOW: "#4caf50" })[s] || "#8b949e";
        cvesHtml = cves.map(sw => `
            <div class="cve-block">
                <div class="cve-software">${esc(sw.software)}</div>
                ${sw.cves.map(c => `
                <div class="cve-entry">
                    <a href="${esc(c.url)}" target="_blank" class="cve-id">${esc(c.id)}</a>
                    ${c.severity ? `<span class="badge" style="background:${sevColor(c.severity)};color:#000">${esc(c.severity)}</span>` : ""}
                    ${c.score ? `<span class="cve-score">${c.score}</span>` : ""}
                    <span class="cve-summary">${esc(c.summary)}</span>
                </div>`).join("")}
            </div>`).join("");
    }

    return `
        <tr>
            <td>${esc(port)}</td>
            <td>${badge(proto, protoColor)}</td>
            <td class="banner">${esc(banner)}</td>
            <td>${certHtml}${hdrsHtml}${cvesHtml}</td>
        </tr>`;
}

/**
 * Renders a full host card, including the header row, optional honeypot warning banner, port table,
 * and credential results block.
 *
 * @param {object} entry - Single host entry from the scan JSON array
 * @returns {string} HTML `<div class="card">` element string
 */
function hostCard(entry) {
    const isHoneypot   = entry.honeypot?.suspected === true;
    const honeypotNote = isHoneypot ? entry.honeypot.reasons?.join("<br>") : "";
    const portCount    = Object.keys(entry.ports || {}).length;
    const owner        = entry.owner && entry.owner !== "unknown" ? entry.owner : null;
    const creds        = entry.credentials && entry.credentials !== "none found" ? entry.credentials : null;

    const portRows = Object.entries(entry.ports || {}).map(([p, info]) => portRow(p, info)).join("");

    return `
    <div class="card ${isHoneypot ? "honeypot" : ""}">
        <div class="card-header">
            <div class="host-info">
                <span class="host">${esc(entry.host)}</span>
                ${entry.hostname ? `<span class="hostname">${esc(entry.hostname)}</span>` : ""}
                ${owner ? `<span class="owner">${esc(owner)}</span>` : ""}
            </div>
            <div class="card-meta">
                ${isHoneypot ? badge("HONEYPOT", "#f44336") : ""}
                <span class="port-count">${portCount} port${portCount !== 1 ? "s" : ""} open</span>
                <span class="scan-time">${esc(entry.scannedAt?.slice(0, 19).replace("T", " ") || "")}</span>
            </div>
        </div>

        ${isHoneypot ? `<div class="honeypot-reasons">${honeypotNote}</div>` : ""}

        <table class="port-table">
            <thead><tr><th>Port</th><th>Proto</th><th>Banner</th><th>Details</th></tr></thead>
            <tbody>${portRows}</tbody>
        </table>

        ${creds ? `
        <div class="creds">
            <b>Credentials found:</b>
            ${Object.entries(creds).map(([p, c]) =>
                `<span class="cred-entry">${esc(p)}/${esc(c.service)} — ${esc(c.user)}:${esc(c.pass)}${c.honeypot ? " ⚠ honeypot" : ""}</span>`
            ).join("")}
        </div>` : ""}
    </div>`;
}

// --- ʕ•ᴥ•ʔ html builder ʕ•ᴥ•ʔ ---

/**
 * Builds the complete self-contained HTML document for the scan report.
 * Computes five summary statistics (hosts, ports, honeypots, credentials, CVEs), renders every
 * host card, and embeds the search/filter script and all CSS inline so the file needs no external
 * assets.
 *
 * @param {string}   scanFile - Original scan file path, shown in the report header
 * @param {object[]} data     - Parsed scan JSON array (one entry per host)
 * @returns {string} Full HTML document as a string
 */
function buildHTML(scanFile, data) {
    const total       = data.length;
    const totalPorts  = data.reduce((n, h) => n + Object.keys(h.ports || {}).length, 0);
    const honeypots   = data.filter(h => h.honeypot?.suspected === true).length;
    const withCreds   = data.filter(h => h.credentials && h.credentials !== "none found").length;
    const totalCVEs   = data.reduce((n, h) =>
        n + Object.values(h.ports || {}).reduce((m, p) =>
            m + (p.cves ? p.cves.reduce((k, s) => k + s.cves.length, 0) : 0), 0), 0);
    const cards       = data.map(hostCard).join("\n");

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RCN Scan Report — ${esc(path.basename(scanFile))}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "Segoe UI", system-ui, sans-serif; background: #0d1117; color: #c9d1d9; font-size: 14px; }

  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 18px; font-weight: 600; color: #f0f6fc; }
  header .file { color: #8b949e; font-size: 12px; }

  .stats { display: flex; gap: 16px; padding: 20px 24px; background: #161b22; border-bottom: 1px solid #30363d; }
  .stat { background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 14px 20px; flex: 1; }
  .stat .value { font-size: 28px; font-weight: 700; color: #f0f6fc; }
  .stat .label { font-size: 12px; color: #8b949e; margin-top: 4px; }

  .controls { padding: 16px 24px; display: flex; gap: 12px; align-items: center; }
  .controls input { background: #21262d; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; padding: 8px 12px; font-size: 13px; width: 260px; }
  .controls input:focus { outline: none; border-color: #388bfd; }
  .controls label { color: #8b949e; font-size: 13px; display: flex; align-items: center; gap: 6px; cursor: pointer; }

  .cards { padding: 0 24px 24px; display: flex; flex-direction: column; gap: 16px; }

  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
  .card.honeypot { border-color: #f44336; }

  .card-header { display: flex; justify-content: space-between; align-items: flex-start; padding: 14px 16px; background: #21262d; gap: 12px; }
  .host-info { display: flex; flex-direction: column; gap: 4px; }
  .host { font-size: 16px; font-weight: 600; color: #f0f6fc; font-family: monospace; }
  .hostname { font-size: 12px; color: #8b949e; }
  .owner { font-size: 12px; color: #58a6ff; }
  .card-meta { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
  .port-count { font-size: 12px; color: #8b949e; }
  .scan-time { font-size: 11px; color: #484f58; }

  .honeypot-reasons { padding: 10px 16px; background: #1a0a0a; border-bottom: 1px solid #f44336; color: #ff7b72; font-size: 12px; line-height: 1.8; }

  .port-table { width: 100%; border-collapse: collapse; }
  .port-table th { padding: 8px 16px; text-align: left; font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid #21262d; }
  .port-table td { padding: 8px 16px; border-bottom: 1px solid #21262d; vertical-align: top; }
  .port-table tr:last-child td { border-bottom: none; }
  .port-table td:first-child { font-family: monospace; font-weight: 600; color: #f0f6fc; width: 60px; }

  .banner { font-family: monospace; font-size: 12px; color: #8b949e; max-width: 360px; word-break: break-all; }
  .cert { font-size: 12px; color: #8b949e; line-height: 1.8; }
  .cert b { color: #c9d1d9; }
  .headers { font-size: 12px; color: #8b949e; line-height: 1.8; margin-top: 6px; }
  .headers b { color: #c9d1d9; }

  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; color: #fff; }

  .creds { padding: 10px 16px; background: #0d1b0d; border-top: 1px solid #238636; font-size: 12px; }
  .creds b { color: #3fb950; }
  .cred-entry { display: inline-block; margin: 4px 8px 0 0; background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 2px 8px; font-family: monospace; }

  .cve-block { margin-top: 8px; }
  .cve-software { font-size: 11px; color: #8b949e; margin-bottom: 4px; font-weight: 600; }
  .cve-entry { display: flex; align-items: flex-start; gap: 6px; margin-bottom: 4px; flex-wrap: wrap; }
  .cve-id { color: #58a6ff; font-size: 12px; font-family: monospace; text-decoration: none; flex-shrink: 0; }
  .cve-id:hover { text-decoration: underline; }
  .cve-score { font-size: 11px; color: #8b949e; flex-shrink: 0; }
  .cve-summary { font-size: 11px; color: #8b949e; line-height: 1.5; }

  .hidden { display: none; }
</style>
</head>
<body>

<header>
  <div>
    <h1>ʕ•ᴥ•ʔ RCN Scan Report</h1>
    <div class="file">${esc(scanFile)}</div>
  </div>
</header>

<div class="stats">
  <div class="stat"><div class="value">${total}</div><div class="label">Hosts with open ports</div></div>
  <div class="stat"><div class="value">${totalPorts}</div><div class="label">Total open ports</div></div>
  <div class="stat"><div class="value" style="color:#f44336">${honeypots}</div><div class="label">Suspected honeypots</div></div>
  <div class="stat"><div class="value" style="color:#3fb950">${withCreds}</div><div class="label">Hosts with credentials</div></div>
  <div class="stat"><div class="value" style="color:#ff9800">${totalCVEs}</div><div class="label">CVEs found</div></div>
</div>

<div class="controls">
  <input type="text" id="search" placeholder="Filter by IP, banner, port, owner..." oninput="filterCards()">
  <label><input type="checkbox" id="honeypotOnly" onchange="filterCards()"> Honeypots only</label>
  <label><input type="checkbox" id="credsOnly" onchange="filterCards()"> With credentials only</label>
</div>

<div class="cards" id="cards">
${cards}
</div>

<script>
function filterCards() {
    const q            = document.getElementById("search").value.toLowerCase();
    const honeypotOnly = document.getElementById("honeypotOnly").checked;
    const credsOnly    = document.getElementById("credsOnly").checked;

    document.querySelectorAll(".card").forEach(card => {
        const text        = card.textContent.toLowerCase();
        const isHoneypot  = card.classList.contains("honeypot");
        const hasCreds    = card.querySelector(".creds") !== null;

        const matchSearch   = !q || text.includes(q);
        const matchHoneypot = !honeypotOnly || isHoneypot;
        const matchCreds    = !credsOnly    || hasCreds;

        card.classList.toggle("hidden", !(matchSearch && matchHoneypot && matchCreds));
    });
}
</script>
</body>
</html>`;
}

// --- ʕ•ᴥ•ʔ main ʕ•ᴥ•ʔ ---

const args     = process.argv.slice(2);
const positional = args.filter(a => !a.startsWith("--"));
const scanFile = positional[0] || null;
const outFile  = positional[1] || null;
const minPorts = (() => { const f = args.find(a => a.startsWith("--min-ports=")); return f ? Number(f.split("=")[1]) : 0; })();

if (args.includes("--help") || args.includes("-h")) {
    console.log(`
  RCN Report Generator

  usage:
    node src/report.js <scan.json> [output.html] [--min-ports=N]

  flags:
    --min-ports=N     only include hosts with N or more open ports
    --help / -h       show this help

  examples:
    node src/report.js scans/results.json
    node src/report.js scans/results.json report.html
    node src/report.js scans/results.json ~/report.html --min-ports=6
`);
    process.exit(0);
}

if (!scanFile) {
    console.error("usage: node src/report.js <scan.json> [output.html] [--min-ports=N]");
    process.exit(1);
}

let data = JSON.parse(fs.readFileSync(scanFile, "utf8"));
if (minPorts > 0) {
    const before = data.length;
    data = data.filter(h => Object.keys(h.ports || {}).length >= minPorts);
    console.log(`filtered: ${before} → ${data.length} hosts (>= ${minPorts} ports)`);
}
const outputPath = outFile || scanFile.replace(/\.json$/, ".html");
const html       = buildHTML(scanFile, data);

fs.writeFileSync(outputPath, html, "utf8");
console.log(`report saved to ${path.resolve(outputPath)}`);
