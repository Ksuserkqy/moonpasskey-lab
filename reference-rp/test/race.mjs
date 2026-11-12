import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';

export async function race(t, value, bodies, { ordered = false, corePath } = {}) {
  const buffer = new SharedArrayBuffer(3 * Int32Array.BYTES_PER_ELEMENT);
  const gate = new Int32Array(buffer);
  let ready = 0;
  const versions = [];
  const workers = bodies.map((body, index) => new Worker(new URL('./race-worker.mjs', import.meta.url), {
    workerData: { path: value.path, session: value.session, config: value.config,
      body, buffer, ordered, corePath, role: index === 0 ? 'high' : 'low' },
  }));
  t.after(async () => { await Promise.all(workers.map(worker => worker.terminate())); });
  const results = workers.map(worker => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Worker race timed out')), 10_000);
    worker.on('message', message => {
      if (message.ready) {
        versions.push(message.version);
        ready += 1;
        if (ready === workers.length) { Atomics.store(gate, 1, 1); Atomics.notify(gate, 1); }
      } else { clearTimeout(timer); resolve(message); }
    });
    worker.on('error', error => { clearTimeout(timer); reject(error); });
  }));
  const output = await Promise.all(results);
  assert.equal(ready, 2, 'both workers verified the same initial snapshot before either committed');
  assert.deepEqual(versions, [0, 0]);
  return output;
}
