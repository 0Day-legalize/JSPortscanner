
function shuffle(beginning_port, end_port) {

    let zahlen = [];

    while (zahlen.length < (end_port - beginning_port + 1)) {

        let rnd = Math.floor(Math.random() * (end_port - beginning_port + 1)) + beginning_port;

        if (!zahlen.includes(rnd)) {
            zahlen.push(rnd);
        }
    }

    console.log(zahlen);
}

shuffle(1, 100);