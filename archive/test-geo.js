// test-geo.js — geolocates a single IP via ip-api.com
// usage: node archive/test-geo.js <ip>

import http from "node:http";

const [ip] = process.argv.slice(2);
if (!ip) { console.error("usage: node archive/test-geo.js <ip>"); process.exit(1); }

http.get(`http://ip-api.com/json/${ip}`, res => {
    let data = "";
    res.on("data", c => { data += c; });
    res.on("end",  () => {
        const g = JSON.parse(data);
        console.log(`${ip} — ${g.city}, ${g.country} (${g.isp})`);
        console.log(`lat: ${g.lat}  lon: ${g.lon}  AS: ${g.as}`);
    });
}).on("error", e => console.error(e.message));
