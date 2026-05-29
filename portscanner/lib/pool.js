'use strict';

// Runs async tasks with a max concurrency limit.
// tasks: array of () => Promise
// concurrency: max parallel tasks
async function pool(tasks, concurrency, onResult) {
    let index = 0;

    async function worker() {
        while (index < tasks.length) {
            const i = index++;
            const result = await tasks[i]();
            if (onResult) onResult(result);
        }
    }

    const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, worker);
    await Promise.all(workers);
}

module.exports = { pool };
