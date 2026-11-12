import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const script = fileURLToPath(new URL('../scripts/rollback-site.sh', import.meta.url));
function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'moonpasskey-rollback-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const name of ['sites-available', 'sites-enabled']) mkdirSync(join(root, 'etc/nginx', name), { recursive: true });
  const available = join(root, 'etc/nginx/sites-available');
  const enabled = join(root, 'etc/nginx/sites-enabled');
  for (const name of ['moonpasskey-http.conf', 'moonpasskey-https.conf', 'other-site.conf']) {
    writeFileSync(join(available, name), `synthetic ${name}`);
    symlinkSync(join(available, name), join(enabled, name));
  }
  return { root, available, enabled };
}
function run(root, args = []) {
  return spawnSync('bash', [script, '--test-root', root, ...args], { encoding: 'utf8' });
}

test('rollback defaults to dry-run and preserves every link and file', t => {
  const { root, enabled } = fixture(t);
  const result = run(root);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /DRY_RUN/);
  for (const name of ['moonpasskey-http.conf', 'moonpasskey-https.conf', 'other-site.conf']) {
    assert.equal(lstatSync(join(enabled, name)).isSymbolicLink(), true);
  }
});

test('rollback apply removes only owned exact symlinks and preserves other websites and data', t => {
  const { root, available, enabled } = fixture(t);
  const database = join(root, 'var/lib/moonpasskey/reference-rp.sqlite');
  mkdirSync(dirname(database), { recursive: true });
  writeFileSync(database, 'synthetic retained data');
  const result = run(root, ['--apply']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(join(enabled, 'moonpasskey-http.conf')), false);
  assert.equal(existsSync(join(enabled, 'moonpasskey-https.conf')), false);
  assert.equal(lstatSync(join(enabled, 'other-site.conf')).isSymbolicLink(), true);
  assert.equal(readFileSync(join(available, 'other-site.conf'), 'utf8'), 'synthetic other-site.conf');
  assert.equal(readFileSync(database, 'utf8'), 'synthetic retained data');
  assert.equal(existsSync(join(available, 'moonpasskey-https.conf')), true);
});

test('rollback refuses foreign target before making any partial change', t => {
  const { root, available, enabled } = fixture(t);
  const link = join(enabled, 'moonpasskey-https.conf');
  rmSync(link);
  symlinkSync(join(available, 'other-site.conf'), link);
  const result = run(root, ['--apply']);
  assert.equal(result.status, 2);
  assert.equal(existsSync(join(enabled, 'moonpasskey-http.conf')), true);
  assert.equal(existsSync(link), true);
});

test('rollback refuses regular site files and symlinked parent directories', t => {
  const { root, enabled } = fixture(t);
  const link = join(enabled, 'moonpasskey-http.conf');
  rmSync(link);
  writeFileSync(link, 'foreign configuration');
  assert.equal(run(root, ['--apply']).status, 2);
  rmSync(enabled, { recursive: true });
  const elsewhere = join(root, 'elsewhere');
  mkdirSync(elsewhere);
  symlinkSync(elsewhere, enabled);
  assert.equal(run(root, ['--apply']).status, 2);
});

test('rollback is idempotent after disabling its own links', t => {
  const { root } = fixture(t);
  assert.equal(run(root, ['--apply']).status, 0);
  assert.equal(run(root, ['--apply']).status, 0);
});

test('an explicitly empty test root is rejected before any production paths are considered', () => {
  const result = run('', ['--apply']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /must not be empty/);
});
