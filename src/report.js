import fs   from "node:fs";
import path from "node:path";

// --- ʕ•ᴥ•ʔ helpers ʕ•ᴥ•ʔ ---

const esc = (s) => String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

function badge(text, color) {
    return `<span class="badge" style="background:${color}">${esc(text)}</span>`;
}

function portRow(port, info) {
    const proto  = info.proto  || "";
    const banner = info.banner || "";
    const cert   = info.cert   || null;
    const hdrs   = info.headers || null;

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

    return `
        <tr>
            <td>${esc(port)}</td>
            <td>${badge(proto, protoColor)}</td>
            <td class="banner">${esc(banner)}</td>
            <td>${certHtml}${hdrsHtml}</td>
        </tr>`;
}

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

function buildHTML(scanFile, data) {
    const total       = data.length;
    const totalPorts  = data.reduce((n, h) => n + Object.keys(h.ports || {}).length, 0);
    const honeypots   = data.filter(h => h.honeypot?.suspected === true).length;
    const withCreds   = data.filter(h => h.credentials && h.credentials !== "none found").length;
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

const [scanFile, outFile] = process.argv.slice(2);

if (process.argv.includes("--help") || process.argv.includes("-h") || !scanFile) {
    console.log(`
  RCN Report Generator

  usage:
    node src/report.js <scan.json> [output.html]

  example:
    node src/report.js scans/results.json
    node src/report.js scans/results.json report.html
`);
    process.exit(scanFile ? 0 : 1);
}

const data       = JSON.parse(fs.readFileSync(scanFile, "utf8"));
const outputPath = outFile || scanFile.replace(/\.json$/, ".html");
const html       = buildHTML(scanFile, data);

fs.writeFileSync(outputPath, html, "utf8");
console.log(`report saved to ${path.resolve(outputPath)}`);
