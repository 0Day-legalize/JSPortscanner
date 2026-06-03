// test-syn.js — sends a SYN and waits for SYN-ACK
// usage: sudo node archive/test-syn.js <ip> <port>

import net from "node:net";

const [ip, port] = process.argv.slice(2);
if (!ip || !port) { console.error("usage: sudo node archive/test-syn.js <ip> <port>"); process.exit(1); }

const s = net.createConnection({ host: ip, port: Number(port) });
s.setTimeout(3000);
s.on("connect",  () => { console.log(`${ip}:${port} OPEN`); s.destroy(); });
s.on("timeout",  () => { console.log(`${ip}:${port} FILTERED`); s.destroy(); });
s.on("error", e  => console.log(`${ip}:${port} CLOSED — ${e.code}`));
