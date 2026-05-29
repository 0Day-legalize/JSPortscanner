'use strict';

// Maps banner text and port number to a service name + version string.
const SIGNATURES = [
    { name: 'SSH',       re: /^SSH-(\S+)/i,              ver: m => m[1] },
    { name: 'FTP',       re: /^220[- ].*ftp/i,           ver: () => null },
    { name: 'FTP',       re: /^220[- ]/,                 ver: () => null },
    { name: 'SMTP',      re: /^220[- ].*smtp|postfix|sendmail|exim/i, ver: () => null },
    { name: 'HTTP',      re: /^HTTP\/[\d.]+\s+(\d+)/,    ver: m => m[1] },
    { name: 'MySQL',     re: /^\x4a\x00\x00\x00/,        ver: () => null },
    { name: 'Redis',     re: /^\+PONG|^-ERR.*redis/i,    ver: () => null },
    { name: 'MongoDB',   re: /ismaster|mongodb/i,        ver: () => null },
    { name: 'RDP',       re: /^\x03\x00/,                ver: () => null },
    { name: 'Telnet',    re: /^\xff[\xfb-\xfe]/,         ver: () => null },
    { name: 'POP3',      re: /^\+OK.*pop/i,              ver: () => null },
    { name: 'IMAP',      re: /^\* OK.*imap/i,            ver: () => null },
    { name: 'SMB',       re: /^\x00\x00\x00/,            ver: () => null },
];

const PORT_DEFAULTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP', 8443: 'HTTPS', 27017: 'MongoDB',
};

function detect(banner, port) {
    if (banner) {
        for (const sig of SIGNATURES) {
            const m = banner.match(sig.re);
            if (m) {
                const ver = sig.ver(m);
                return ver ? `${sig.name}/${ver}` : sig.name;
            }
        }
    }
    return PORT_DEFAULTS[port] || 'unknown';
}

module.exports = { detect };
