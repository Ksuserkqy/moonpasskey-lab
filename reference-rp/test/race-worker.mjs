import { parentPort, workerData } from 'node:worker_threads';
import { RpStore } from '../store.mjs';
import { CeremonyCoordinator } from '../coordinator.mjs';
import { storeTestCore } from './helpers.mjs';
import { loadCore } from '../core.mjs';

const { path, session, config, body, buffer, role, ordered, corePath } = workerData;
const gate = new Int32Array(buffer);
const observed = [];
const store = new RpStore(path, { initialize: false });
const actualCore = corePath ? await loadCore(corePath) : null;
const core = actualCore ? { host: input => {
  observed.push(input.credential.signCount);
  return actualCore.host(input);
} } : storeTestCore(observed);
const coordinator = new CeremonyCoordinator(store, core, config, {
  beforeCommit: async ({ attempt, snapshot }) => {
    if (attempt !== 0) return;
    parentPort.postMessage({ ready: true, version: snapshot.version });
    Atomics.add(gate, 0, 1);
    Atomics.notify(gate, 0);
    while (Atomics.load(gate, 1) === 0) Atomics.wait(gate, 1, 0);
    if (ordered && role === 'low') while (Atomics.load(gate, 2) === 0) Atomics.wait(gate, 2, 0);
  },
});
try {
  const result = await coordinator.assert(session, body);
  parentPort.postMessage({ result, observed });
} catch (error) {
  parentPort.postMessage({ error: error.kind ?? error.message, observed });
} finally {
  if (role === 'high') { Atomics.store(gate, 2, 1); Atomics.notify(gate, 2); }
  store.close();
}
