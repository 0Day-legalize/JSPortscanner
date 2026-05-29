const dgram = require("node:dgram");


// Sendet ein UDP-Paket an host:port
// Gibt zurück:
// - Antwortdaten als String
// - "OPEN|FILTERED" wenn keine Antwort kam
// - null wenn der Port sicher geschlossen ist
function tryUDP(host, port) {

    return new Promise((resolve) => {

        // UDP Socket erstellen
        const s = dgram.createSocket("udp4");



        // Wurde bereits beendet?
        let finished = false;

        // Hilfsfunktion zum sicheren Beenden
        function done(result) {

            if (finished) return;

            finished = true;

            s.close();

            resolve(result);
        }

        // Timeout:
        // Viele UDP-Dienste antworten gar nicht.
        // Deshalb bedeutet Timeout nicht automatisch "geschlossen".
        const timeout = setTimeout(() => {

            done("OPEN|FILTERED");

        }, 2000);

        // Wenn eine Antwort kommt:
        s.on("message", (msg) => {

            clearTimeout(timeout);

            done(msg.toString("utf8"));
        });

        // Fehlerbehandlung
        s.on("error", (err) => {

            clearTimeout(timeout);

            // ECONNREFUSED bedeutet:
            // Zielport ist geschlossen
            if (err.code === "ECONNREFUSED") {

                done(null);

            } else {

                done(`ERROR: ${err.message}`);
            }
        });

        // UDP-Paket senden
        // Manche Dienste brauchen spezielle Daten,
        // aber ein einfacher Ping reicht oft für einen Scan.
        const payload = Buffer.from("");

        s.send(payload, port, host, (err) => {

            if (err) {

                clearTimeout(timeout);

                done(null);
            }
        });
    });
}

// Scan-Funktion
async function scan(host, start, end) {

    for (let port = start; port <= end; port++) {

        process.stdout.write(`\rScanning UDP ${port}...`);

        const result = await tryUDP(host, port);

        // null = geschlossen
        if (result !== null) {

            process.stdout.write("\r\x1b[K");

            console.log(`\nUDP ${host}:${port} OPEN`);

            if (typeof result === "string" && result.trim()) {

                console.log(result);
            }
        }
    }

    process.stdout.write("\r\x1b[K");

    console.log("Done.");
}

// CLI Argumente lesen
const [host, start, end] = process.argv.slice(2);

// Scan starten
scan(host, +start, +end);