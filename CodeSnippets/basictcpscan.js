// Import the built-in Node.js module for plain TCP connections
const net = require("node:net");

// Import the built-in Node.js module for TLS/SSL encrypted connections (HTTPS)
const tls = require("node:tls");

// How many ports to scan at the same time
const CONCURRENCY = 50;

// This function tries to connect to a host:port using either TLS or plain TCP
// It returns the raw response text, or null if the port is closed/unreachable
function tryConnect(host, port, useTLS) {

    // Wrap the connection in a Promise so we can use async/await on it
    return new Promise((resolve) => {

        // Create either a TLS or plain TCP socket depending on useTLS
        // rejectUnauthorized: false allows self-signed certificates to work
        const s = useTLS
            ? tls.connect({ host, port, rejectUnauthorized: false })
            : net.createConnection({ host, port });

        // Stores all text data received from the server
        let data = "";

        // Tracks whether we successfully established a connection
        let connected = false;

        // If no response within 2000ms, give up on this port
        s.setTimeout(2000);

        // TLS sockets fire "secureConnect" once the handshake is done
        // Plain TCP sockets fire "connect" once the connection is open
        s.on(useTLS ? "secureConnect" : "connect", () => {

            // Mark the connection as successful
            connected = true;

            // Send an HTTP HEAD request to ask the server for its headers
            s.write("HEAD / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
        });

        // Each time data arrives from the server, append it to our buffer
        s.on("data", (chunk) => { data += chunk.toString("utf8"); });

        // When the timeout fires, force-close the socket
        s.on("timeout", () => s.destroy());

        // If an error occurs before we connected, the port is closed — resolve null
        s.on("error", () => { if (!connected) resolve(null); });

        // "close" always fires last — resolve with the data we collected (or null if never connected)
        s.on("close", () => resolve(connected ? data : null));
    });
}

// Scans a single port — tries TLS first, falls back to plain TCP
async function scanPort(host, port) {
    const tlsData = await tryConnect(host, port, true);
    const tcpData = tlsData === null ? await tryConnect(host, port, false) : null;
    const data = tlsData ?? tcpData;
    return { port, data, isTLS: tlsData !== null };
}

// Scans a range of ports in parallel batches and prints any that are open
async function scan(host, start, end) {

    // Build a list of every port number in the range
    const ports = [];
    for (let p = start; p <= end; p++) ports.push(p);

    // Process ports in chunks of CONCURRENCY size so we don't open too many sockets at once
    for (let i = 0; i < ports.length; i += CONCURRENCY) {

        // Grab the next batch of ports
        const batch = ports.slice(i, i + CONCURRENCY);

        // Show progress — which batch we are on out of the total
        process.stdout.write(`\rScanning ports ${batch[0]}–${batch[batch.length - 1]}...`);

        // Scan all ports in this batch at the same time
        const results = await Promise.all(batch.map((p) => scanPort(host, p)));

        // Loop through results and print any open ports
        for (const { port, data, isTLS } of results) {
            if (data !== null) {

                // \r moves cursor to start of line, \x1b[K clears to end — erases the "Scanning..." text
                process.stdout.write("\r\x1b[K");

                // Print the open port and whether it used TLS or plain TCP
                console.log(`\nOPEN ${host}:${port} [${isTLS ? "TLS" : "TCP"}]`);

                // If the server sent back any text, print it raw
                if (data.trim()) console.log(data);
            }
        }
    }

    // Clear the last progress line from the terminal
    process.stdout.write("\r\x1b[K");

    // Let the user know the scan has finished
    console.log("Done.");
}

// Read the three command-line arguments: host, start port, end port
// process.argv is [ 'node', 'basictcpscan.js', host, start, end ]
const [host, start, end] = process.argv.slice(2);

// Start the scan — the + converts the port strings to numbers
scan(host, +start, +end);
