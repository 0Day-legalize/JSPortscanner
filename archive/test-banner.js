// test-banner.js — connects and reads the first banner line
// usage: node archive/test-banner.js <ip> <port>

import net from "node:net";

const [ip, port] = process.argv.slice(2);
if (!ip || !port) { console.error("usage: node archive/test-banner.js <ip> <port>"); process.exit(1); }

const s = net.createConnection({ host: ip, port: Number(port) });
s.setTimeout(3000);
s.on("data",    d => { console.log(d.toString("utf8").split("\n")[0].trim()); s.destroy(); });
s.on("timeout", () => { console.log("no banner (timeout)"); s.destroy(); });
s.on("error",  e => console.log(`error: ${e.code}`));
