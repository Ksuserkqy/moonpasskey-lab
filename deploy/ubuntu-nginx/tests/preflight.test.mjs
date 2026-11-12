import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:https';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { canAccessAs, inspectApplicationCore, inspectLiveHttps, inspectTls, parseEnvironmentText, requestHttps } from '../scripts/deployment-check.mjs';
import { ephemeralTls } from '../../../reference-rp/test/tls-fixtures.mjs';

const DOMAIN = 'passkey-test.ksuser.cn';
const preflight = fileURLToPath(new URL('../scripts/preflight.sh', import.meta.url));
const verify = fileURLToPath(new URL('../scripts/verify-deployment.sh', import.meta.url));
const scripts = fileURLToPath(new URL('../scripts/', import.meta.url));
// Use the real developer OpenSSL on macOS; production defaults remain the
// absolute Ubuntu /usr/bin/openssl path. No command or TLS result is mocked.
const openssl = spawnSync('/usr/bin/which', ['openssl'], { encoding: 'utf8' }).stdout.trim();

function fixture(t) {
  const directory = mkdtempSync(join(realpathSync(tmpdir()), 'moonpasskey-deployment-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  chmodSync(directory, 0o700);
  for (const kind of ['ca', 'cert']) {
    const result = spawnSync('/bin/bash', [join(scripts, `generate-backend-${kind}.sh`), '--test-directory', directory],
      { encoding: 'utf8', timeout: 15_000 });
    assert.equal(result.status, 0, result.stderr);
  }
  const keyPath = join(directory, 'backend/backend.key');
  const certPath = join(directory, 'backend/backend.crt');
  const caPath = join(directory, 'ca/ca.crt');
  const tls = { keyPath, certPath, key: readFileSync(keyPath), cert: readFileSync(certPath), ca: readFileSync(caPath) };
  const values = {
    REFERENCE_RP_PORT: '8787', REFERENCE_RP_ORIGIN: `https://${DOMAIN}`, REFERENCE_RP_ID: DOMAIN,
    REFERENCE_RP_UV: 'required', REFERENCE_RP_COUNTER: 'report-only',
    REFERENCE_RP_TLS_CERT: tls.certPath, REFERENCE_RP_TLS_KEY: tls.keyPath,
    REFERENCE_RP_TLS_CA: caPath, REFERENCE_RP_DB: join(directory, 'not-created.sqlite'),
    REFERENCE_RP_CORE: '/opt/moonpasskey/current/_build/js/release/build/analysis/analysis.js',
  };
  const text = Object.entries(values).map(([key, value]) => `${key}=${value}`).join('\n') + '\n';
  const envPath = join(directory, 'reference-rp.env');
  writeFileSync(envPath, text, { mode: 0o600 });
  return { directory, tls, values, text, envPath };
}

function run(script, config, args = []) {
  return spawnSync('/bin/bash', [script, '--node', process.execPath, '--env-file', config.envPath,
    '--openssl', openssl, '--edge-cert', config.tls.certPath, '--edge-key', config.tls.keyPath, '--json', ...args],
  { encoding: 'utf8', timeout: 30_000 });
}

test('strict environment format accepts complete literal systemd values and optional release core', t => {
  const config = fixture(t);
  const parsed = parseEnvironmentText(`# private deployment input\n\n${config.text}`);
  assert.deepEqual({ ...parsed }, config.values);
  assert.equal(Object.getPrototypeOf(parsed), null);
  const withoutCore = config.text.replace(/^REFERENCE_RP_CORE=.*\n/m, '');
  assert.equal(parseEnvironmentText(withoutCore).REFERENCE_RP_CORE, undefined);
});

for (const [name, change, expected] of [
  ['missing TLS CA', text => text.replace(/^REFERENCE_RP_TLS_CA=.*\n/m, ''), /MissingConfiguration:REFERENCE_RP_TLS_CA/],
  ['mismatched RP', text => text.replace(`REFERENCE_RP_ID=${DOMAIN}`, 'REFERENCE_RP_ID=other.example.test'), /DeploymentPolicyMismatch/],
  ['origin slash', text => text.replace(`https://${DOMAIN}`, `https://${DOMAIN}/`), /DeploymentPolicyMismatch/],
  ['weakened UV', text => text.replace('REFERENCE_RP_UV=required', 'REFERENCE_RP_UV=preferred'), /DeploymentPolicyMismatch/],
  ['changed counter', text => text.replace('REFERENCE_RP_COUNTER=report-only', 'REFERENCE_RP_COUNTER=reject'), /DeploymentPolicyMismatch/],
  ['external backend port', text => text.replace('REFERENCE_RP_PORT=8787', 'REFERENCE_RP_PORT=443'), /DeploymentPolicyMismatch/],
  ['relative SQLite file', text => text.replace(/^REFERENCE_RP_DB=.*$/m, 'REFERENCE_RP_DB=./local.sqlite'), /AbsolutePathRequired/],
  ['parent traversal', text => text.replace(/^REFERENCE_RP_DB=.*$/m, 'REFERENCE_RP_DB=/var/lib/../private.sqlite'), /AbsolutePathRequired/],
  ['shell export', text => text.replace(/^REFERENCE_RP_PORT=/m, 'export REFERENCE_RP_PORT='), /InvalidEnvironmentAssignment/],
  ['quoted value', text => text.replace('REFERENCE_RP_PORT=8787', "REFERENCE_RP_PORT='8787'"), /InvalidEnvironmentAssignment/],
  ['duplicate key', text => `${text}REFERENCE_RP_PORT=8787\n`, /DuplicateEnvironmentKey/],
  ['unknown setting', text => `${text}PRIVATE_SECRET=do-not-print-this-value\n`, /InvalidEnvironmentAssignment/],
  ['unresolved placeholder', text => text.replace(DOMAIN, '<owned-test-domain>'), /InvalidEnvironmentAssignment/],
]) {
  test(`strict environment rejects ${name}`, t => {
    const config = fixture(t);
    assert.throws(() => parseEnvironmentText(change(config.text)), expected);
  });
}

test('shell syntax is never executed and errors do not echo environment values', t => {
  const config = fixture(t);
  const marker = join(config.directory, 'must-not-exist');
  writeFileSync(config.envPath, config.text.replace(/^REFERENCE_RP_DB=.*$/m,
    `REFERENCE_RP_DB=$(touch ${marker})private-secret-sentinel`));
  const result = run(preflight, config);
  assert.equal(result.status, 2, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.checks.environment.status, 'FAIL');
  assert.equal(output.checks.environment.detail, 'InvalidEnvironmentAssignment');
  assert.equal(existsSync(marker), false);
  assert.equal(`${result.stdout}${result.stderr}`.includes('private-secret-sentinel'), false);
  assert.equal(`${result.stdout}${result.stderr}`.includes('PRIVATE KEY'), false);
});

test('real offline certificate validation includes explicit chain and SAN hostname', t => {
  const config = fixture(t);
  assert.match(inspectTls(config.values, openssl), /CA chain verified offline/);
  const other = ephemeralTls(t, DOMAIN);
  assert.throws(() => inspectTls({ ...config.values, REFERENCE_RP_TLS_CA: other.certPath }, openssl), /BackendCertificateChainUntrusted/);
  assert.throws(() => inspectTls({ ...config.values, REFERENCE_RP_TLS_KEY: other.keyPath }, openssl), /TlsKeyMismatch/);
  const wrongDomain = ephemeralTls(t, 'wrong.example.test');
  assert.throws(() => inspectTls({ ...config.values,
    REFERENCE_RP_TLS_CERT: wrongDomain.certPath, REFERENCE_RP_TLS_KEY: wrongDomain.keyPath }, openssl), /CertificateHostnameMismatch/);
  assert.throws(() => inspectTls({ ...config.values, REFERENCE_RP_TLS_CA: config.tls.certPath }, openssl), /IndependentBackendCaAndLeafRequired/);
  assert.throws(() => inspectTls({ ...config.values, REFERENCE_RP_TLS_CERT: other.certPath,
    REFERENCE_RP_TLS_KEY: other.keyPath, REFERENCE_RP_TLS_CA: other.certPath }, openssl), /IndependentBackendCaAndLeafRequired/);
});

test('Unix access checks require the requested service owner bits and traversable ancestors', t => {
  const config = fixture(t);
  const owner = { uid: process.getuid(), groups: [statSync(config.directory).gid] };
  assert.equal(canAccessAs(config.envPath, owner, 4), true);
  chmodSync(config.envPath, 0o200);
  assert.equal(canAccessAs(config.envPath, owner, 4), false);
  chmodSync(config.envPath, 0o600);
  chmodSync(config.directory, 0o600);
  assert.equal(canAccessAs(config.envPath, owner, 4), false);
  chmodSync(config.directory, 0o700);
});

test('compiled Core inspection rejects missing, unreadable and untrusted artifacts without executing them', t => {
  const config = fixture(t);
  const path = join(config.directory, 'analysis.js');
  const identity = { uid: process.getuid(), groups: [statSync(config.directory).gid] };
  assert.throws(() => inspectApplicationCore(path, identity), /ApplicationCoreMissing/);
  const code = 'throw new Error("Core artifact must never execute during preflight");\n';
  writeFileSync(path, code, { mode: 0o200 });
  assert.throws(() => inspectApplicationCore(path, identity), /ApplicationCoreNotReadableByService/);
  chmodSync(path, 0o620);
  assert.throws(() => inspectApplicationCore(path, identity), /UnsafeApplicationCorePermissions/);
  chmodSync(path, 0o600);
  // A developer-owned artifact or a fixture below a writable temporary parent
  // must not be mistaken for a root-controlled production release.
  assert.throws(() => inspectApplicationCore(path, identity), /UnsafeApplicationCore(?:Parent)?Permissions/);
  assert.equal(readFileSync(path, 'utf8'), code);
});

test('offline CLI reports unperformed DNS/live checks and never creates a SQLite probe', t => {
  const config = fixture(t);
  const before = readdirSync(config.directory);
  const result = run(preflight, config);
  const output = JSON.parse(result.stdout);
  assert.equal(output.scope, 'OFFLINE_READINESS');
  assert.equal(output.checks.environment.status, 'PASS');
  assert.equal(output.checks.backendTls.status, 'PASS');
  assert.equal(output.checks.applicationCore.status, 'FAIL');
  assert.equal(output.checks.dns.status, 'NOT_PERFORMED');
  assert.equal(output.checks.liveHttps.status, 'NOT_PERFORMED');
  assert.equal(existsSync(config.values.REFERENCE_RP_DB), false);
  assert.deepEqual(readdirSync(config.directory), before);
  assert.equal(readFileSync(config.envPath, 'utf8'), config.text);
  assert.equal(output.limitations.some(value => /No real-device/.test(value)), true);
  // The fixture intentionally has no public CA edge certificate. Do not claim a
  // successful deployment on a developer machine or with a synthetic CA.
  assert.equal(output.checks.edgeTls.status, 'FAIL');
  assert.equal(result.status, 2);
});

test('verify entrypoint remains offline without explicit network authorization', t => {
  const config = fixture(t);
  const result = run(verify, config);
  const output = JSON.parse(result.stdout);
  assert.equal(output.scope, 'OFFLINE_READINESS');
  assert.equal(output.checks.dns.status, 'NOT_PERFORMED');
  assert.equal(output.checks.liveHttps.status, 'NOT_PERFORMED');
});

test('network authorization and a credentials file are both required before any request', t => {
  const config = fixture(t);
  const direct = run(preflight, config, ['--network']);
  assert.equal(direct.status, 2);
  assert.match(direct.stderr, /NetworkRequiresVerifyMode/);
  assert.equal(direct.stdout, '');
  const noCredentials = run(verify, config, ['--network']);
  assert.equal(noCredentials.status, 2);
  assert.match(noCredentials.stderr, /CredentialsFileRequired/);
  assert.equal(noCredentials.stdout, '');
});

test('CLI rejects unknown arguments and relative executable overrides', t => {
  const config = fixture(t);
  const unknown = run(preflight, config, ['--pretend-success']);
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /UnknownOrIncompleteArgument/);
  const relative = run(preflight, config, ['--openssl', './openssl']);
  assert.equal(relative.status, 2);
  assert.match(relative.stderr, /AbsoluteOptionPathRequired/);
});

function captureChecks() {
  const checks = {};
  return { checks, add: async (name, inspect) => {
    try { checks[name] = { status: 'PASS', detail: await inspect() }; }
    catch (error) { checks[name] = { status: 'FAIL', detail: error.kind ?? 'RequestFailed' }; }
  } };
}

test('live verifier uses trusted HTTPS and validates Basic Auth, Host and Origin on synthetic loopback only', async t => {
  const config = fixture(t);
  const credentialsFile = join(config.directory, 'credentials');
  const credentials = 'loopback-test:private-password-sentinel';
  writeFileSync(credentialsFile, `${credentials}\n`, { mode: 0o600 });
  const expectedAuth = `Basic ${Buffer.from(credentials).toString('base64')}`;
  const seen = [];
  const server = createServer({ cert: config.tls.cert, key: config.tls.key }, (req, res) => {
    seen.push({ host: req.headers.host, auth: req.headers.authorization, origin: req.headers.origin });
    const status = req.headers.host !== DOMAIN ? 403
      : req.headers.origin && req.headers.origin !== `https://${DOMAIN}` ? 403
      : req.headers['x-fixture-edge'] === 'yes' && req.headers.authorization !== expectedAuth ? 401 : 200;
    res.writeHead(status); res.end('synthetic fixture');
  });
  await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
  t.after(() => new Promise(resolveClose => server.close(resolveClose)));
  const port = server.address().port;
  const capture = captureChecks();
  // Every target is forced to this process's loopback listener. The public DNS
  // name is used only as TLS SNI/Host, with the fixture certificate as local CA.
  const send = options => requestHttps({ ...options, hostname: '127.0.0.1', port,
    ca: config.tls.ca, headers: { Host: DOMAIN,
      ...(options.hostname === DOMAIN ? { 'X-Fixture-Edge': 'yes' } : {}), ...options.headers } });
  await inspectLiveHttps(capture.add, { credentialsFile }, config.values, send);
  assert.equal(Object.keys(capture.checks).length, 7);
  for (const value of Object.values(capture.checks)) assert.equal(value.status, 'PASS', value.detail);
  assert.equal(seen.length, 6);
  assert.equal(seen.slice(0, 3).every(value => value.auth === undefined), true);
  assert.equal(seen[3].auth, undefined);
  assert.equal(seen[4].auth, expectedAuth);
  assert.equal(JSON.stringify(capture.checks).includes('private-password-sentinel'), false);
});

test('live verifier rejects permissive or malformed credentials before any network request', async t => {
  const config = fixture(t);
  const credentialsFile = join(config.directory, 'credentials');
  let requests = 0;
  const send = async () => { requests++; return 200; };
  writeFileSync(credentialsFile, 'user:password\n', { mode: 0o644 });
  const unsafe = captureChecks();
  await inspectLiveHttps(unsafe.add, { credentialsFile }, config.values, send);
  assert.equal(unsafe.checks.verificationCredentials.status, 'FAIL');
  assert.equal(unsafe.checks.verificationCredentials.detail, 'UnsafePrivateFilePermissions');
  assert.equal(requests, 0);
  chmodSync(credentialsFile, 0o600);
  writeFileSync(credentialsFile, 'user:password\nsecond-line\n');
  const malformed = captureChecks();
  await inspectLiveHttps(malformed.add, { credentialsFile }, config.values, send);
  assert.equal(malformed.checks.verificationCredentials.detail, 'InvalidCredentialsFile');
  assert.equal(requests, 0);
});

test('HTTPS request helper fails a real loopback TLS connection with an unrelated CA', async t => {
  const config = fixture(t);
  const unrelated = ephemeralTls(t, DOMAIN);
  let handled = 0;
  const server = createServer({ cert: config.tls.cert, key: config.tls.key }, (_req, res) => {
    handled++; res.end('must not reach HTTP');
  });
  await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
  t.after(() => new Promise(resolveClose => server.close(resolveClose)));
  await assert.rejects(requestHttps({ hostname: '127.0.0.1', port: server.address().port,
    servername: DOMAIN, ca: unrelated.cert, headers: { Host: DOMAIN }, rejectUnauthorized: false }),
  /self.signed|certificate|unable to verify/i);
  assert.equal(handled, 0);
});
