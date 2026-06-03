// test-cidr.js — expands a CIDR block and prints all IPs
// usage: node archive/test-cidr.js <cidr>

const [cidr] = process.argv.slice(2);
if (!cidr) { console.error("usage: node archive/test-cidr.js <cidr>  e.g. 37.27.7.128/26"); process.exit(1); }

const [base, prefix] = cidr.split("/");
const bits  = Number(prefix);
const oct   = base.split(".").map(Number);
const start = (oct[0] << 24 | oct[1] << 16 | oct[2] << 8 | oct[3]) >>> 0;
const count = 1 << (32 - bits);

console.log(`${cidr} — ${count - 2} usable hosts:\n`);
for (let i = 1; i < count - 1; i++) {
    const ip = (start + i) >>> 0;
    console.log(`${ip>>>24}.${(ip>>>16)&0xff}.${(ip>>>8)&0xff}.${ip&0xff}`);
}
