// shared helpers used by scanner.js and credtest.js

export function jitter(min, max) {
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    return new Promise(r => setTimeout(r, delay));
}

export async function runPool(tasks, limit, onDone) {
    let i = 0;
    const worker = async () => {
        while (i < tasks.length) onDone(await tasks[i++]());
    };
    await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
}
