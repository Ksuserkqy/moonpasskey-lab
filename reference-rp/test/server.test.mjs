import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { fileURLToPath } from 'node:url';
import { RpStore } from '../store.mjs';
import { createReferenceRp } from '../server.mjs';
import { loadCore } from '../core.mjs';
import { ephemeralAuthenticator } from './signed-fixtures.mjs';

async function setup(t) {
  const core = await loadCore(fileURLToPath(new URL('../../_build/js/debug/build/analysis/analysis.js', import.meta.url)));
  const store = new RpStore(':memory:');
  const app = createReferenceRp({ store, core, origin: 'http://localhost:0', port: 0 });
  await app.listen();
  t.after(async () => { await app.close(); store.close(); });
  const init = await fetch(`${app.config.origin}/api/session`);
  const cookie = init.headers.get('set-cookie').split(';')[0];
  const session = await init.json();
  async function request(path, input, overrides = {}) {
    return new Promise((resolve, reject) => {
      const outgoing = httpRequest(`${app.config.origin}${path}`, {
        method: input === undefined ? 'GET' : 'POST',
        headers: { cookie, ...(input === undefined ? {} : { origin: app.config.origin,
          'content-type': 'application/json', 'x-csrf-token': session.csrfToken }), ...overrides },
      }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }));
      });
      outgoing.on('error', reject);
      outgoing.end(Buffer.isBuffer(input) ? input : JSON.stringify(input));
    });
  }
  return { app, store, session, cookie, request };
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
