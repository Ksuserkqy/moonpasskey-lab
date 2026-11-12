import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { RpStore } from '../store.mjs';
import { createReferenceRp } from '../server.mjs';
import { loadCore } from '../core.mjs';
import { ephemeralAuthenticator } from './signed-fixtures.mjs';
import { ephemeralTls } from './tls-fixtures.mjs';

async function setup(t, options = {}) {
  const core = await loadCore(fileURLToPath(new URL('../../_build/js/debug/build/analysis/analysis.js', import.meta.url)));
  const store = new RpStore(':memory:');
  const app = createReferenceRp({ store, core, origin: 'http://localhost:0', port: 0, ...options });
  await app.listen();
  t.after(async () => { await app.close(); store.close(); });
  const transport = options.tls ? httpsRequest : httpRequest;
  let cookie;
  let session;
  async function request(path, input, overrides = {}) {
    return new Promise((resolve, reject) => {
      const outgoing = transport(`${app.config.origin}${path}`, {
        method: input === undefined ? 'GET' : 'POST',
        ...(options.tls ? { ca: options.tls.cert, servername: new URL(app.config.origin).hostname } : {}),
        headers: { ...(cookie ? { cookie } : {}), ...(input === undefined ? {} : { origin: app.config.origin,
          'content-type': 'application/json', 'x-csrf-token': session.csrfToken }), ...overrides },
      }, response => {
        const chunks = [];
        const tlsAuthorized = response.socket.authorized;
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, tlsAuthorized,
          body: JSON.parse(Buffer.concat(chunks).toString()) }));
      });
      outgoing.on('error', reject);
      outgoing.end(Buffer.isBuffer(input) ? input : JSON.stringify(input));
    });
  }
  const init = await request('/api/session');
  cookie = init.headers['set-cookie'][0].split(';')[0];
  session = init.body;
  return { app, store, session, cookie, request, init };
}

test('real MoonBit Core completes HTTP test registration assertion state and sanitized reports', async t => {
  const { app, session, request } = await setup(t);
  const authenticator = ephemeralAuthenticator();
  const options = await request('/api/challenges', { purpose: 'registration' });
  assert.equal(options.status, 200);
  assert.equal(options.body.publicKey.attestation, 'none');
  assert.equal(options.body.publicKey.user.id, session.user.userHandle);
  const registration = await request('/api/register', authenticator.register(options.body, app.config));
  assert.equal(registration.status, 200, JSON.stringify(registration.body));
  assert.equal(registration.body.status, 'PASS');
  assert.equal(registration.body.credential.backupEligible, true);
  const issued = await request('/api/challenges', { purpose: 'assertion' });
  assert.equal(issued.body.publicKey.allowCredentials[0].id, authenticator.credentialId);
  const body = authenticator.assertion(issued.body, app.config, 7, { bs: true });
  const verified = await request('/api/assertions', body);
  assert.equal(verified.status, 200, JSON.stringify(verified.body));
  assert.equal(verified.body.report.checks.signature, 'PASS');
  assert.equal(verified.body.report.authenticatorData.flags.bs, true);
  assert.equal(verified.body.report.authenticatorData.signCount, 7);
  assert.equal(verified.body.report.redacted, true);
  assert.equal(verified.body.report.internal, undefined);
  const state = await request('/api/state');
  assert.equal(state.body.credentials[0].signCount, 7);
  assert.equal(state.body.credentials[0].backupState, true);
  const replay = await request('/api/assertions', body);
  assert.equal(replay.status, 409);
  assert.equal(replay.body.error.kind, 'ChallengeConsumed');
  const reports = await request('/api/reports');
  assert.equal(reports.body.reports.length, 2);
  const serialized = JSON.stringify(reports.body);
  for (const sensitive of [authenticator.credentialId, authenticator.publicKey, session.user.userHandle,
    body.clientDataJSON, body.authenticatorData, body.signature, body.challenge]) assert.ok(!serialized.includes(sensitive));
});

test('HTTP enforces Host Origin session CSRF content type and trusted server policy', async t => {
  const { app, request, cookie } = await setup(t);
  for (const [headers, kind] of [
    [{ host: 'attacker.test' }, 'HostMismatch'],
    [{ origin: 'https://attacker.test' }, 'OriginMismatch'],
    [{ 'x-csrf-token': 'wrong' }, 'CsrfMismatch'],
    [{ 'content-type': 'text/plain' }, 'JsonContentTypeRequired'],
  ]) {
    const result = await request('/api/challenges', { purpose: 'registration' }, headers);
    assert.ok(result.body.error, `Expected ${kind} for the supplied headers`);
    assert.equal(result.body.error.kind, kind);
  }
  const missing = await fetch(`${app.config.origin}/api/state`);
  assert.equal(missing.status, 401);
  const crossSite = await fetch(`${app.config.origin}/api/state`, { headers: { cookie, 'sec-fetch-site': 'cross-site' } });
  assert.equal(crossSite.status, 403);
  const options = await request('/api/challenges', { purpose: 'registration', policy: { uv: 'discouraged', rpId: 'attacker.test' } });
  assert.equal(options.body.publicKey.rp.id, 'localhost');
  assert.equal(options.body.publicKey.authenticatorSelection.userVerification, 'preferred');
});

test('invalid Core signature and binding failures preserve the outstanding challenge', async t => {
  const { app, store, cookie, request } = await setup(t);
  const authenticator = ephemeralAuthenticator();
  const registrationOptions = await request('/api/challenges', { purpose: 'registration' });
  await request('/api/register', authenticator.register(registrationOptions.body, app.config));
  const issued = await request('/api/challenges', { purpose: 'assertion' });
  const valid = authenticator.assertion(issued.body, app.config);
  const bad = { ...valid, signature: Buffer.alloc(8, 1).toString('base64url') };
  const rejected = await request('/api/assertions', bad);
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.report.status, 'FAIL');
  const session = store.session(cookie.split('=')[1]);
  assert.equal(store.challenge(session, { ...issued.body, ...app.config, purpose: 'assertion' }).consumed_at, null);
  const verified = await request('/api/assertions', valid);
  assert.equal(verified.status, 200);
});

test('analysis endpoint returns actual Core typed results without persisting imported raw data', async t => {
  const { store, session, request } = await setup(t);
  const input = { command: 'client-data', clientDataJSON: Buffer.from('{}').toString('base64url') };
  const result = await request('/api/analyze', input);
  assert.equal(result.body.status, 'FAIL');
  assert.equal(result.body.error.kind, 'MissingField');
  assert.equal(store.reports(session.user.id).length, 0);
});

test('HTTP rejects malformed UTF-8 transport before JSON parsing', async t => {
  const { request } = await setup(t);
  const raw = Buffer.concat([Buffer.from('{"purpose":"registration","'), Buffer.from([0xff]), Buffer.from('":0}')]);
  const result = await request('/api/challenges', raw);
  assert.equal(result.status, 400);
  assert.equal(result.body.error.kind, 'InvalidBodyUtf8');
});

test('reference service rejects public bind addresses and insecure remote origins', () => {
  assert.throws(() => createReferenceRp({ host: '0.0.0.0' }), /loopback/);
  assert.throws(() => createReferenceRp({ origin: 'http://example.test' }), /loopback/);
  assert.throws(() => createReferenceRp({ tls: { cert: 'invalid', key: 'invalid' } }), /HTTPS origin/);
});

test('required UV options come from trusted server policy for both ceremonies', async t => {
  const { app, request } = await setup(t, { userVerification: 'required' });
  const authenticator = ephemeralAuthenticator();
  const untrusted = { userVerification: 'discouraged', policy: { uv: 'discouraged', rpId: 'attacker.test' } };
  const registrationOptions = await request('/api/challenges', { purpose: 'registration', ...untrusted });
  assert.equal(registrationOptions.body.publicKey.authenticatorSelection.userVerification, 'required');
  assert.equal(registrationOptions.body.publicKey.rp.id, 'localhost');
  const registered = await request('/api/register', authenticator.register(registrationOptions.body, app.config));
  assert.equal(registered.status, 200, JSON.stringify(registered.body));
  const assertionOptions = await request('/api/challenges', { purpose: 'assertion', ...untrusted });
  assert.equal(assertionOptions.body.publicKey.userVerification, 'required');
  assert.equal(assertionOptions.body.publicKey.rpId, 'localhost');
});

test('actual Core rejects required UV registration without UV and preserves its challenge', async t => {
  const { app, store, cookie, request } = await setup(t, { userVerification: 'required' });
  const authenticator = ephemeralAuthenticator();
  const issued = await request('/api/challenges', { purpose: 'registration' });
  const rejected = await request('/api/register', authenticator.register(issued.body, app.config, 1, { uv: false }));
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.report.error.kind, 'UserVerificationRequired');
  assert.equal(rejected.body.report.checks.user_verification, 'FAIL');
  assert.equal(rejected.body.report.authenticatorData.flags.up, true);
  assert.equal(rejected.body.report.authenticatorData.flags.uv, false);
  assert.equal(rejected.body.databaseTransaction, undefined);
  const session = store.session(cookie.split('=')[1]);
  assert.equal(store.challenge(session, { ...issued.body, ...app.config, purpose: 'registration' }).consumed_at, null);
  assert.equal(store.credentials(session.userId).length, 0);
  assert.equal(store.reports(session.userId).length, 0);
  const accepted = await request('/api/register', authenticator.register(issued.body, app.config, 1, { uv: true }));
  assert.equal(accepted.status, 200, JSON.stringify(accepted.body));
  assert.equal(accepted.body.report.authenticatorData.flags.uv, true);
  assert.equal(accepted.body.report.checks.user_verification, 'PASS');
  assert.equal(store.credentials(session.userId).length, 1);
});

test('actual Core rejects signed UV false assertions under required and accepts UV true retry', async t => {
  const { app, store, cookie, request } = await setup(t, { userVerification: 'required' });
  const authenticator = ephemeralAuthenticator();
  const registrationOptions = await request('/api/challenges', { purpose: 'registration' });
  const registered = await request('/api/register', authenticator.register(registrationOptions.body, app.config));
  assert.equal(registered.status, 200, JSON.stringify(registered.body));
  const issued = await request('/api/challenges', { purpose: 'assertion' });
  const withoutUv = authenticator.assertion(issued.body, app.config, 2, { uv: false, bs: true });
  const analyzed = await request('/api/analyze', { command: 'authenticator-data', authenticatorData: withoutUv.authenticatorData });
  assert.equal(analyzed.body.status, 'PASS');
  assert.equal(analyzed.body.authenticatorData.flags.up, true);
  assert.equal(analyzed.body.authenticatorData.flags.uv, false);
  const rejected = await request('/api/assertions', { ...withoutUv, policy: { uv: 'discouraged' } });
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.report.error.kind, 'UserVerificationRequired');
  assert.equal(rejected.body.report.error.context, 'authData.flags.uv');
  assert.equal(rejected.body.report.checks.user_verification, 'FAIL');
  assert.equal(rejected.body.databaseTransaction, undefined);
  const session = store.session(cookie.split('=')[1]);
  assert.equal(store.challenge(session, { ...issued.body, ...app.config, purpose: 'assertion' }).consumed_at, null);
  const unchanged = store.getCredential(session.userId, authenticator.credentialId);
  assert.equal(unchanged.signCount, 1);
  assert.equal(unchanged.backupState, false);
  assert.equal(unchanged.version, 0);
  assert.equal(store.reports(session.userId).length, 1);
  const accepted = await request('/api/assertions', authenticator.assertion(issued.body, app.config, 2, { uv: true, bs: true }));
  assert.equal(accepted.status, 200, JSON.stringify(accepted.body));
  assert.equal(accepted.body.report.status, 'PASS');
  assert.equal(accepted.body.report.authenticatorData.flags.up, true);
  assert.equal(accepted.body.report.authenticatorData.flags.uv, true);
  assert.equal(accepted.body.report.checks.user_verification, 'PASS');
  assert.equal(accepted.body.report.checks.signature, 'PASS');
  assert.deepEqual(accepted.body.databaseTransaction, { status: 'COMMITTED', previousVersion: 0, version: 1 });
  const committed = store.getCredential(session.userId, authenticator.credentialId);
  assert.equal(committed.signCount, 2);
  assert.equal(committed.backupState, true);
  assert.equal(committed.version, 1);
});

for (const userVerification of ['preferred', 'discouraged']) {
  test(`actual Core preserves ${userVerification} options and accepts both UV states`, async t => {
    const { app, request } = await setup(t, { userVerification });
    for (const uv of [false, true]) {
      const authenticator = ephemeralAuthenticator();
      const registrationOptions = await request('/api/challenges', { purpose: 'registration' });
      assert.equal(registrationOptions.body.publicKey.authenticatorSelection.userVerification, userVerification);
      const registered = await request('/api/register', authenticator.register(registrationOptions.body, app.config, 1, { uv }));
      assert.equal(registered.status, 200, JSON.stringify(registered.body));
      assert.equal(registered.body.report.authenticatorData.flags.uv, uv);
      assert.equal(registered.body.report.checks.user_verification, 'PASS');
      const assertionOptions = await request('/api/challenges', { purpose: 'assertion' });
      assert.equal(assertionOptions.body.publicKey.userVerification, userVerification);
      const verified = await request('/api/assertions', authenticator.assertion(assertionOptions.body, app.config, 2, { uv }));
      assert.equal(verified.status, 200, JSON.stringify(verified.body));
      assert.equal(verified.body.report.authenticatorData.flags.uv, uv);
      assert.equal(verified.body.report.checks.user_verification, 'PASS');
      assert.equal(verified.body.report.checks.signature, 'PASS');
    }
  });
}

test('HTTPS verifies its test certificate and enforces exact Host Origin CSRF and forwarded-header boundaries', async t => {
  const tls = ephemeralTls(t);
  const { app, request, init } = await setup(t, { origin: 'https://localhost:0', tls });
  assert.equal(init.tlsAuthorized, true);
  assert.match(init.headers['set-cookie'][0], /; Secure(?:;|$)/);
  assert.equal(app.server.address().address, '127.0.0.1');
  await assert.rejects(new Promise((resolve, reject) => {
    const outgoing = httpsRequest(`${app.config.origin}/api/session`, response => {
      response.resume();
      response.on('end', resolve);
    });
    outgoing.on('error', reject);
    outgoing.end();
  }), { code: 'DEPTH_ZERO_SELF_SIGNED_CERT' });
  const configured = new URL(app.config.origin);
  for (const [headers, kind] of [
    [{ host: 'attacker.test', 'x-forwarded-host': configured.host, 'x-forwarded-proto': 'https' }, 'HostMismatch'],
    [{ host: configured.hostname }, 'HostMismatch'],
    [{ origin: `http://${configured.host}`, 'x-forwarded-proto': 'https' }, 'OriginMismatch'],
    [{ origin: `${app.config.origin}/` }, 'OriginMismatch'],
    [{ origin: 'https://localhost' }, 'OriginMismatch'],
    [{ origin: 'https://attacker.test', forwarded: `host=${configured.host};proto=https` }, 'OriginMismatch'],
    [{ origin: '' }, 'OriginRequired'],
    [{ 'x-csrf-token': 'wrong' }, 'CsrfMismatch'],
  ]) {
    const rejected = await request('/api/challenges', { purpose: 'registration' }, headers);
    assert.equal(rejected.status, 403);
    assert.equal(rejected.body.error.kind, kind);
    assert.equal(rejected.tlsAuthorized, true);
  }
  const accepted = await request('/api/challenges', { purpose: 'registration' }, {
    'x-forwarded-host': 'attacker.test', 'x-forwarded-proto': 'http',
  });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.publicKey.rp.id, 'localhost');
  assert.equal(accepted.tlsAuthorized, true);
});

test('actual Core HTTPS rejects signed wrong RP ID and origin then commits once and rejects replay', async t => {
  const tls = ephemeralTls(t);
  const { app, store, cookie, request } = await setup(t, { origin: 'https://localhost:0', tls, userVerification: 'required' });
  const authenticator = ephemeralAuthenticator();
  const options = await request('/api/challenges', { purpose: 'registration' });
  const registered = await request('/api/register', authenticator.register(options.body, app.config));
  assert.equal(registered.status, 200, JSON.stringify(registered.body));
  const issued = await request('/api/challenges', { purpose: 'assertion' });
  const session = store.session(cookie.split('=')[1]);
  for (const [config, kind] of [
    [{ ...app.config, rpId: 'attacker.test' }, 'RpIdHashMismatch'],
    [{ ...app.config, origin: 'https://localhost' }, 'OriginNotAllowed'],
  ]) {
    const rejected = await request('/api/assertions', authenticator.assertion(issued.body, config, 5));
    assert.equal(rejected.status, 400);
    assert.equal(rejected.body.report.error.kind, kind);
    assert.equal(rejected.body.databaseTransaction, undefined);
    assert.equal(store.challenge(session, { ...issued.body, ...app.config, purpose: 'assertion' }).consumed_at, null);
    assert.equal(store.getCredential(session.userId, authenticator.credentialId).version, 0);
  }
  const signed = authenticator.assertion(issued.body, app.config, 5, { bs: true });
  const accepted = await request('/api/assertions', signed);
  assert.equal(accepted.status, 200, JSON.stringify(accepted.body));
  assert.equal(accepted.tlsAuthorized, true);
  for (const check of ['challenge', 'origin', 'rp_id_hash', 'user_presence', 'user_verification', 'backup', 'signature']) {
    assert.equal(accepted.body.report.checks[check], 'PASS', check);
  }
  assert.deepEqual(accepted.body.databaseTransaction, { status: 'COMMITTED', previousVersion: 0, version: 1 });
  assert.equal(accepted.body.credential.signCount, 5);
  assert.equal(accepted.body.credential.backupState, true);
  const replay = await request('/api/assertions', signed);
  assert.equal(replay.status, 409);
  assert.equal(replay.body.error.kind, 'ChallengeConsumed');
  assert.equal(replay.body.databaseTransaction, undefined);
  assert.equal(store.getCredential(session.userId, authenticator.credentialId).version, 1);
  assert.equal(store.reports(session.userId).length, 2);
});

test('reference service rejects inexact origins and invalid trusted policies', () => {
  for (const origin of ['https://localhost/', 'https://localhost/path', 'https://localhost?query',
    'https://localhost#fragment', 'https://user:password@localhost', 'ftp://localhost']) {
    assert.throws(() => createReferenceRp({ origin }), /exact HTTP\(S\) origin/);
  }
  assert.throws(() => createReferenceRp({ userVerification: 'optional' }), /Invalid server policy/);
  assert.throws(() => createReferenceRp({ counterPolicy: 'ignore' }), /Invalid server policy/);
});

test('HTTPS configuration rejects missing incomplete malformed and mismatched TLS credentials', t => {
  for (const tls of [undefined, {}, { cert: 'invalid' }, { key: 'invalid' }]) {
    assert.throws(() => createReferenceRp({ origin: 'https://localhost:8787', tls }), /certificate and key/);
  }
  const store = new RpStore(':memory:');
  t.after(() => store.close());
  const config = { store, core: {}, origin: 'https://localhost:8787' };
  assert.throws(() => createReferenceRp({ ...config, tls: { cert: 'invalid', key: 'invalid' } }), /PEM|DECODER|unsupported/i);
  const first = ephemeralTls(t);
  const second = ephemeralTls(t);
  assert.throws(() => createReferenceRp({ ...config, tls: { cert: first.cert, key: second.key } }), /key values mismatch/i);
});

test('startup requires paired TLS environment paths before loading any credential files', () => {
  for (const supplied of ['REFERENCE_RP_TLS_CERT', 'REFERENCE_RP_TLS_KEY']) {
    const env = { ...process.env };
    delete env.REFERENCE_RP_TLS_CERT;
    delete env.REFERENCE_RP_TLS_KEY;
    env[supplied] = 'test-file-that-must-not-be-read.pem';
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('../start.mjs', import.meta.url))], {
      env, encoding: 'utf8', timeout: 5_000,
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Supply both TLS certificate and key/);
    assert.doesNotMatch(result.stderr, /ENOENT/);
  }
});

test('transaction evidence follows real commits and repeated assertions while rollbacks emit no commit result', async t => {
  const { app, store, cookie, request } = await setup(t);
  const authenticator = ephemeralAuthenticator();
  const session = store.session(cookie.split('=')[1]);
  const registrationOptions = await request('/api/challenges', { purpose: 'registration' });
  const registration = authenticator.register(registrationOptions.body, app.config);
  const insertReport = store.insertReport;
  store.insertReport = () => { throw new Error('Injected report transaction failure'); };
  const rolledBackRegistration = await request('/api/register', registration);
  assert.equal(rolledBackRegistration.status, 500);
  assert.equal(rolledBackRegistration.body.databaseTransaction, undefined);
  assert.equal(store.credentials(session.userId).length, 0);
  assert.equal(store.challenge(session, { ...registrationOptions.body, ...app.config, purpose: 'registration' }).consumed_at, null);
  store.insertReport = insertReport;
  const registered = await request('/api/register', registration);
  assert.equal(registered.status, 200, JSON.stringify(registered.body));
  assert.deepEqual(registered.body.databaseTransaction, { status: 'COMMITTED', previousVersion: null, version: 0 });
  assert.equal(store.getCredential(session.userId, authenticator.credentialId).version, 0);
  const issued = await request('/api/challenges', { purpose: 'assertion' });
  const signed = authenticator.assertion(issued.body, app.config, 2);
  store.insertReport = () => { throw new Error('Injected report transaction failure'); };
  const rolledBackAssertion = await request('/api/assertions', signed);
  assert.equal(rolledBackAssertion.status, 500);
  assert.equal(rolledBackAssertion.body.databaseTransaction, undefined);
  assert.equal(store.getCredential(session.userId, authenticator.credentialId).version, 0);
  assert.equal(store.challenge(session, { ...issued.body, ...app.config, purpose: 'assertion' }).consumed_at, null);
  store.insertReport = insertReport;
  const first = await request('/api/assertions', signed);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.deepEqual(first.body.databaseTransaction, { status: 'COMMITTED', previousVersion: 0, version: 1 });
  const repeatedOptions = await request('/api/challenges', { purpose: 'assertion' });
  const repeated = await request('/api/assertions', authenticator.assertion(repeatedOptions.body, app.config, 3, { bs: true }));
  assert.equal(repeated.status, 200, JSON.stringify(repeated.body));
  assert.deepEqual(repeated.body.databaseTransaction, { status: 'COMMITTED', previousVersion: 1, version: 2 });
  assert.equal(store.getCredential(session.userId, authenticator.credentialId).version, 2);
  assert.equal(store.getCredential(session.userId, authenticator.credentialId).signCount, 3);
  assert.equal(store.reports(session.userId).length, 3);
});
