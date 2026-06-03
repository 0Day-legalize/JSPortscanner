// test-jitter.js — shows jitter timing distribution over N samples
// usage: node archive/test-jitter.js [samples] [min_ms] [max_ms]

const samples = Number(process.argv[2]) || 10;
const min     = Number(process.argv[3]) || 10;
const max     = Number(process.argv[4]) || 250;

function jitter() {
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    return new Promise(r => setTimeout(r, delay));
}

console.log(`jitter test: ${samples} samples, range ${min}–${max}ms\n`);

const times = [];
for (let i = 0; i < samples; i++) {
    const t = Date.now();
    await jitter();
    const elapsed = Date.now() - t;
    times.push(elapsed);
    console.log(`sample ${String(i+1).padStart(2)}: ${elapsed}ms`);
}

const avg = Math.round(times.reduce((a,b) => a+b, 0) / times.length);
console.log(`\navg: ${avg}ms  min: ${Math.min(...times)}ms  max: ${Math.max(...times)}ms`);
