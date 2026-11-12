import assert from 'node:assert/strict';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scripts = fileURLToPath(new URL('../scripts/', import.meta.url));
const hostname = 'passkey-test.ksuser.cn';

function temporary(t) {
  // macOS /var is a symlink. Give the generators the real temporary path so
  // these tests exercise the same no-symlink policy as Ubuntu production.
  const directory = mkdtempSync(join(realpathSync(tmpdir()), 'moonpasskey-deploy-tls-'));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function generate(name, directory, extra = {}) {
  return spawnSync('bash', [join(scripts, `generate-backend-${name}.sh`), '--test-directory', directory], {
    encoding: 'utf8', ...extra,
  });
}

function succeeds(result) {
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

function refuses(result) {
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0, 'unsafe generation unexpectedly succeeded');
}

function mode(path) { return lstatSync(path).mode & 0o777; }
function openssl(args) { return spawnSync('openssl', args, { encoding: 'utf8' }); }

test('generators produce a separate protected CA and hostname-verified matching backend leaf', t => {
  const directory = temporary(t);
  succeeds(generate('ca', directory));
  succeeds(generate('cert', directory));
  assert.deepEqual(readdirSync(directory).sort(), ['backend', 'ca']);
  assert.deepEqual(readdirSync(join(directory, 'ca')).sort(), ['ca.crt', 'ca.key']);
  assert.deepEqual(readdirSync(join(directory, 'backend')).sort(), ['backend.crt', 'backend.key']);
  assert.equal(mode(join(directory, 'ca')), 0o700);
  assert.equal(mode(join(directory, 'ca/ca.key')), 0o600);
  assert.equal(mode(join(directory, 'ca/ca.crt')), 0o644);
  assert.equal(mode(join(directory, 'backend')), 0o750);
  assert.equal(mode(join(directory, 'backend/backend.key')), 0o640);
  assert.equal(mode(join(directory, 'backend/backend.crt')), 0o640);
  for (const path of ['ca', 'ca/ca.key', 'ca/ca.crt', 'backend', 'backend/backend.key', 'backend/backend.crt']) {
    assert.equal(lstatSync(join(directory, path)).uid, process.getuid());
  }

  const ca = new X509Certificate(readFileSync(join(directory, 'ca/ca.crt')));
  const leaf = new X509Certificate(readFileSync(join(directory, 'backend/backend.crt')));
  assert.equal(ca.ca, true);
  assert.equal(leaf.ca, false);
  assert.equal(ca.subject, ca.issuer);
  assert.equal(leaf.issuer, ca.subject);
  assert.notEqual(leaf.subject, leaf.issuer);
  assert.equal(ca.verify(ca.publicKey), true);
  assert.equal(leaf.verify(ca.publicKey), true);
  assert.equal(leaf.verify(leaf.publicKey), false);
  assert.equal(leaf.subjectAltName, `DNS:${hostname}`);
  assert.equal(leaf.checkHost(hostname), hostname);
  assert.equal(leaf.checkHost('other.ksuser.cn'), undefined);
  assert.equal(ca.checkPrivateKey(createPrivateKey(readFileSync(join(directory, 'ca/ca.key')))), true);
  assert.equal(leaf.checkPrivateKey(createPrivateKey(readFileSync(join(directory, 'backend/backend.key')))), true);
  assert.equal(leaf.checkPrivateKey(createPrivateKey(readFileSync(join(directory, 'ca/ca.key')))), false);
  const verification = ['verify', '-no-CApath', '-no-CAstore', '-x509_strict', '-purpose', 'sslserver',
    '-CAfile', join(directory, 'ca/ca.crt'), '-verify_hostname'];
  succeeds(openssl([...verification, hostname, join(directory, 'backend/backend.crt')]));
  const wrongHost = openssl([...verification, 'wrong.ksuser.cn', join(directory, 'backend/backend.crt')]);
  refuses(wrongHost);
  assert.match(wrongHost.stderr, /hostname mismatch/i);
});

test('existing CA and leaf outputs are never overwritten, including empty directories and broken symlinks', t => {
  const directory = temporary(t);
  succeeds(generate('ca', directory));
  succeeds(generate('cert', directory));
  const files = ['ca/ca.key', 'ca/ca.crt', 'backend/backend.key', 'backend/backend.crt'];
  const original = files.map(path => readFileSync(join(directory, path)));
  refuses(generate('ca', directory));
  refuses(generate('cert', directory));
  files.forEach((path, index) => assert.deepEqual(readFileSync(join(directory, path)), original[index]));
  assert.deepEqual(readdirSync(directory).sort(), ['backend', 'ca']);

  for (const kind of ['directory', 'symlink']) {
    const scratch = temporary(t);
    if (kind === 'directory') mkdirSync(join(scratch, 'ca'));
    else symlinkSync(join(scratch, 'missing'), join(scratch, 'ca'));
    refuses(generate('ca', scratch));
    assert.deepEqual(readdirSync(scratch), ['ca']);
    assert.equal(lstatSync(join(scratch, 'ca')).isSymbolicLink(), kind === 'symlink');
  }
});

test('generators reject relative, traversal, symlink, missing and insecure output directories', t => {
  const directory = temporary(t);
  const symlink = join(directory, 'alias');
  const protectedDirectory = join(directory, 'protected');
  mkdirSync(protectedDirectory, { mode: 0o700 });
  symlinkSync(protectedDirectory, symlink);
  for (const path of ['relative-output', `${directory}/../${directory.split('/').at(-1)}`,
    `${directory}/./protected`, `${directory}//protected`, symlink, join(symlink, 'child'),
    join(directory, 'missing'), `${directory}/`]) {
    for (const script of ['ca', 'cert']) refuses(generate(script, path));
  }
  chmodSync(protectedDirectory, 0o777);
  refuses(generate('ca', protectedDirectory));
  refuses(generate('cert', protectedDirectory));
  assert.deepEqual(readdirSync(protectedDirectory), []);
  const badArgument = spawnSync('bash', [join(scripts, 'generate-backend-ca.sh'), '--output-dir', directory],
    { encoding: 'utf8' });
  refuses(badArgument);
  assert.deepEqual(readdirSync(directory).sort(), ['alias', 'protected']);
});

test('leaf generation rejects missing, symlinked, hard-linked and excessively readable CA inputs', t => {
  const directory = temporary(t);
  refuses(generate('cert', directory));
  assert.deepEqual(readdirSync(directory), []);
  succeeds(generate('ca', directory));
  const key = join(directory, 'ca/ca.key');
  const certificate = join(directory, 'ca/ca.crt');
  const originalKey = readFileSync(key);
  for (const [path, unsafeMode, restoreMode] of [[key, 0o644, 0o600], [certificate, 0o666, 0o644],
    [join(directory, 'ca'), 0o750, 0o700]]) {
    chmodSync(path, unsafeMode);
    refuses(generate('cert', directory));
    chmodSync(path, restoreMode);
    assert.deepEqual(readdirSync(directory), ['ca']);
  }
  const alias = join(directory, 'key-alias');
  linkSync(key, alias);
  refuses(generate('cert', directory));
  rmSync(alias);
  rmSync(key);
  writeFileSync(alias, originalKey, { mode: 0o600 });
  symlinkSync(alias, key);
  refuses(generate('cert', directory));
  assert.deepEqual(readdirSync(directory).sort(), ['ca', 'key-alias']);
});

test('wrong CA key and corrupt CA certificates fail without publishing leaf artifacts or changing CA', t => {
  const directory = temporary(t);
  const other = temporary(t);
  succeeds(generate('ca', directory));
  succeeds(generate('ca', other));
  const key = join(directory, 'ca/ca.key');
  const certificate = join(directory, 'ca/ca.crt');
  const originalKey = readFileSync(key);
  const originalCertificate = readFileSync(certificate);
  writeFileSync(key, readFileSync(join(other, 'ca/ca.key')));
  refuses(generate('cert', directory));
  assert.deepEqual(readdirSync(directory), ['ca']);
  assert.deepEqual(readFileSync(certificate), originalCertificate);
  writeFileSync(key, originalKey);
  writeFileSync(certificate, 'not a certificate\n');
  refuses(generate('cert', directory));
  assert.deepEqual(readdirSync(directory), ['ca']);
  assert.deepEqual(readFileSync(key), originalKey);
});

test('OpenSSL failures after creating staged credentials leave no partial output or lock', t => {
  const wrapperDirectory = temporary(t);
  const realOpenSsl = spawnSync('which', ['openssl'], { encoding: 'utf8' }).stdout.trim();
  assert.ok(realOpenSsl.startsWith('/'));
  writeFileSync(join(wrapperDirectory, 'openssl'), `#!/usr/bin/env bash
"$TLS_REAL_OPENSSL" "$@"
status=$?
if [ "$1" = "$TLS_FAIL_COMMAND" ] && { [ "$1" != x509 ] || [ "\${2:-}" = -req ]; }; then exit 42; fi
exit "$status"
`, { mode: 0o700 });
  const env = { ...process.env, PATH: `${wrapperDirectory}:${process.env.PATH}`, TLS_REAL_OPENSSL: realOpenSsl };
  const directory = temporary(t);
  refuses(generate('ca', directory, { env: { ...env, TLS_FAIL_COMMAND: 'req' } }));
  assert.deepEqual(readdirSync(directory), []);
  succeeds(generate('ca', directory));
  const originalKey = readFileSync(join(directory, 'ca/ca.key'));
  refuses(generate('cert', directory, { env: { ...env, TLS_FAIL_COMMAND: 'x509' } }));
  assert.deepEqual(readdirSync(directory), ['ca']);
  assert.deepEqual(readFileSync(join(directory, 'ca/ca.key')), originalKey);
  succeeds(generate('cert', directory));
});
