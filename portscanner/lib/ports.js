'use strict';

const NAMED = {
    ftp: 21, ssh: 22, telnet: 23, smtp: 25, dns: 53,
    http: 80, pop3: 110, imap: 143, https: 443, smb: 445,
    rdp: 3389, mysql: 3306, postgres: 5432, redis: 6379,
    mongodb: 27017, http8080: 8080, http8443: 8443,
};

// Parses port specs into a sorted, deduplicated array of numbers.
// Accepts: "80", "80,443", "80-1024", "80,443,8080-8090", "http,https"
function parsePorts(spec) {
    const set = new Set();
    for (const part of spec.split(',')) {
        const trimmed = part.trim();
        if (NAMED[trimmed]) {
            set.add(NAMED[trimmed]);
        } else if (trimmed.includes('-')) {
            const [start, end] = trimmed.split('-').map(Number);
            for (let p = start; p <= end; p++) set.add(p);
        } else {
            const n = parseInt(trimmed, 10);
            if (!isNaN(n)) set.add(n);
        }
    }
    return [...set].sort((a, b) => a - b);
}

module.exports = { parsePorts, NAMED };
