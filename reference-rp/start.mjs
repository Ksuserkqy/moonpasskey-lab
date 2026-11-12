import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCore } from './core.mjs';
import { createReferenceRp, openReferenceStore } from './server.mjs';

process.umask(0o077);
const directory = fileURLToPath(new URL('.', import.meta.url));
const port = Number(process.env.REFERENCE_RP_PORT ?? 8787);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid REFERENCE_RP_PORT.');
const origin = process.env.REFERENCE_RP_ORIGIN ?? `http://localhost:${port}`;
const certificate = process.env.REFERENCE_RP_TLS_CERT;
const key = process.env.REFERENCE_RP_TLS_KEY;
if (Boolean(certificate) !== Boolean(key)) throw new Error('Supply both TLS certificate and key.');
const core = await loadCore(process.env.REFERENCE_RP_CORE
  ?? resolve(directory, '../_build/js/debug/build/analysis/analysis.js'));
const store = openReferenceStore(process.env.REFERENCE_RP_DB ?? ':memory:');
const app = createReferenceRp({ store, core, port, origin,
  rpId: process.env.REFERENCE_RP_ID ?? 'localhost',
  userVerification: process.env.REFERENCE_RP_UV ?? 'preferred',
  counterPolicy: process.env.REFERENCE_RP_COUNTER ?? 'report-only',
  tls: certificate ? { cert: readFileSync(certificate), key: readFileSync(key) } : undefined,
});
await app.listen();
// Startup diagnostics contain only the public test origin and server policies.
console.log(`MoonPasskey Lab TEST ONLY reference RP listening at ${app.config.origin}`);
console.log(`UV ${app.config.userVerification}, counter ${app.config.counterPolicy}`);
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => {
  await app.close();
  store.close();
});
