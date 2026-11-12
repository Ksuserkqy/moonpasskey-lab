import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Synthetic loopback TLS only. Clients explicitly trust the generated certificate
// for these requests. The fixture never changes the operating system trust store.
export function ephemeralTls(t, hostname = 'localhost') {
  const directory = mkdtempSync(join(tmpdir(), 'moonpasskey-tls-'));
  const keyPath = join(directory, 'key.pem');
  const certPath = join(directory, 'cert.pem');
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const subjectAltName = hostname === 'localhost' ? 'DNS:localhost,IP:127.0.0.1' : `DNS:${hostname}`;
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-sha256', '-nodes', '-days', '1',
    '-subj', `/CN=${hostname}`, '-addext', `subjectAltName=${subjectAltName}`,
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe', timeout: 15_000 });
  chmodSync(keyPath, 0o600);
  return { key: readFileSync(keyPath), cert: readFileSync(certPath), keyPath, certPath };
}
