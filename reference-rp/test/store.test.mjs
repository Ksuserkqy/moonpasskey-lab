import test from 'node:test';
import assert from 'node:assert/strict';
import { statSync } from 'node:fs';
import { RpStore } from '../store.mjs';
import { CeremonyCoordinator, publicReport } from '../coordinator.mjs';
import { digest, transportBytes } from '../security.mjs';
import { fixture, assertionBody, storeTestCore } from './helpers.mjs';
import { race } from './race.mjs';

function binding(value, issued, purpose = 'assertion') {
  return { ...issued, ...value.config, purpose };
}

test('CSPRNG challenge generation stores only bound SHA256 digests', t => {
  const value = fixture(t);
  const first = value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  const second = value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  assert.notEqual(first.challenge, second.challenge);
  assert.equal(transportBytes(first.challenge).length, 32);
  const row = value.store.db.prepare('SELECT * FROM challenges WHERE id=?').get(first.challengeId);
  assert.deepEqual(Buffer.from(row.challenge_hash), digest(transportBytes(first.challenge)));
  assert.equal(row.session_id, value.session.sessionId);
  assert.equal(row.user_id, value.session.userId);
  assert.equal(row.rp_id, 'localhost');
  assert.equal(row.origin, 'http://localhost:8787');
  assert.equal(row.purpose, 'assertion');
  assert.equal(row.consumed_at, null);
  assert.ok(!JSON.stringify(row).includes(first.challenge));
  assert.ok(!JSON.stringify(value.store.db.prepare('SELECT * FROM sessions').all()).includes(value.created.token));
});

test('database and live WAL sidecars restrict file access to the current user', t => {
  const value = fixture(t);
  for (const path of [value.path, value.path + '-wal', value.path + '-shm']) {
    assert.equal(statSync(path).mode & 0o777, 0o600);
  }
});

test('challenge rejects expired values and session expiry at commit time', () => {
  let now = 1000;
  const store = new RpStore(':memory:', { now: () => now });
  try {
    const created = store.createSession({ lifetimeMs: 2000 });
    const session = store.session(created.token);
    const issued = store.issueChallenge(session, { rpId: 'localhost', origin: 'http://localhost', purpose: 'assertion', ttlMs: 1000 });
    now = 2000;
    assert.throws(() => store.challenge(session, { ...issued, rpId: 'localhost', origin: 'http://localhost', purpose: 'assertion' }), { kind: 'ChallengeExpired' });
    now = 3000;
    assert.throws(() => store.challenge(session, { ...issued, rpId: 'localhost', origin: 'http://localhost', purpose: 'assertion' }), { kind: 'SessionExpired' });
  } finally { store.close(); }
});

test('challenge binds user session purpose RP ID origin and original random value', t => {
  const value = fixture(t);
  const issued = value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  const bound = binding(value, issued);
  const other = value.store.createSession();
  assert.throws(() => value.store.challenge(value.store.session(other.token), bound), { kind: 'ChallengeSessionMismatch' });
  for (const [override, kind] of [
    [{ purpose: 'registration' }, 'ChallengePurposeMismatch'],
    [{ rpId: 'other.test' }, 'ChallengeRpIdMismatch'],
    [{ origin: 'http://other.test' }, 'ChallengeOriginMismatch'],
    [{ challenge: Buffer.alloc(32).toString('base64url') }, 'ChallengeMismatch'],
  ]) assert.throws(() => value.store.challenge(value.session, { ...bound, ...override }), { kind });
});

test('challenge caps active requests and rejects malformed canonical transport', t => {
  const value = fixture(t);
  for (let index = 0; index < 32; index += 1) value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  assert.throws(() => value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' }), { kind: 'ChallengeCapacity' });
  for (const text of ['AA==', '+/', 'A', 'AB', 'é']) assert.throws(() => transportBytes(text), { kind: 'InvalidTransportEncoding' });
});

test('duplicate registration rolls back challenge consumption and report', t => {
  const value = fixture(t);
  const issued = value.store.issueChallenge(value.session, { ...value.config, purpose: 'registration' });
  const before = value.store.reports(value.session.userId).length;
  assert.throws(() => value.store.commitRegistration(value.session, binding(value, issued, 'registration'), {
    credentialId: value.credentialId, publicKey: 'AA', signCount: 0, backupEligible: false, backupState: false,
  }, { status: 'PASS' }), { kind: 'CredentialAlreadyRegistered' });
  assert.equal(value.store.challenge(value.session, binding(value, issued, 'registration')).consumed_at, null);
  assert.equal(value.store.reports(value.session.userId).length, before);
});

test('failed Core verification preserves challenge and credential state', async t => {
  const value = fixture(t);
  const issued = value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  const coordinator = new CeremonyCoordinator(value.store, { host: async () => ({ status: 'FAIL', error: { kind: 'InvalidSignature' } }) }, value.config);
  const result = await coordinator.assert(value.session, assertionBody({ ...issued, credentialId: value.credentialId }));
  assert.equal(result.status, 'FAIL');
  assert.equal(value.store.getCredential(value.session.userId, value.credentialId).version, 0);
  assert.equal(value.store.challenge(value.session, binding(value, issued)).consumed_at, null);
});

test('commit rollback restores both challenge and credential after report-write failure', t => {
  const value = fixture(t);
  const issued = value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  const snapshot = value.store.getCredential(value.session.userId, value.credentialId);
  value.store.insertReport = () => { throw new Error('Injected transaction failure'); };
  assert.throws(() => value.store.commitAssertion(value.session, binding(value, issued), snapshot,
    { signCount: 8, backupEligible: true, backupState: true }, { status: 'PASS' }), /Injected transaction failure/);
  assert.equal(value.store.getCredential(value.session.userId, value.credentialId).signCount, 1);
  assert.equal(value.store.getCredential(value.session.userId, value.credentialId).version, 0);
  assert.equal(value.store.challenge(value.session, binding(value, issued)).consumed_at, null);
});

test('reports omit original bytes challenge identity and internal key records', () => {
  const result = publicReport({ status: 'PASS', record: { publicKey: 'secret' }, credentialUpdate: { credentialId: 'secret' },
    clientData: { challenge: 'secret', origin: 'http://localhost' }, nested: { signature: 'secret', flags: { uv: true } } });
  assert.deepEqual(result, { status: 'PASS', clientData: { origin: 'http://localhost' }, nested: { flags: { uv: true } } });
});

test('reports preserve Core safe challenge key and authenticator metadata', () => {
  assert.deepEqual(publicReport({ internal: true, redacted: false,
    clientData: { challenge: { redacted: true, encodedLength: 43 } },
    authenticatorData: { flags: { uv: true, be: true, bs: false }, signCount: 9, length: 37 },
    publicKey: { algorithm: 'ES256', curve: 'P-256', validated: true },
    checks: { challenge: 'PASS', signature: 'PASS', public_key: 'PASS' } }), {
    redacted: true, clientData: { challenge: { redacted: true, encodedLength: 43 } },
    authenticatorData: { flags: { uv: true, be: true, bs: false }, signCount: 9, length: 37 },
    publicKey: { algorithm: 'ES256', curve: 'P-256', validated: true },
    checks: { challenge: 'PASS', signature: 'PASS', public_key: 'PASS' },
  });
});

test('two real workers competing for one challenge permit exactly one commit', async t => {
  const value = fixture(t);
  const issued = value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  const body = assertionBody({ ...issued, credentialId: value.credentialId }, 4);
  const results = await race(t, value, [body, body]);
  assert.equal(results.filter(result => result.result?.status === 'PASS').length, 1);
  assert.equal(results.filter(result => result.error === 'ChallengeConsumed').length, 1);
  assert.equal(value.store.getCredential(value.session.userId, value.credentialId).version, 1);
});

test('different challenges race and CAS retries against the latest counter', async t => {
  const value = fixture(t);
  const challenges = [0, 1].map(() => value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' }));
  const results = await race(t, value, challenges.map(issued => assertionBody({ ...issued, credentialId: value.credentialId }, 5)));
  assert.equal(results.filter(result => result.result?.status === 'PASS').length, 2);
  assert.deepEqual(results.map(result => result.observed.length).sort(), [1, 2]);
  assert.ok(results.some(result => result.result.report.counter.status === 'WARNING'));
  const record = value.store.getCredential(value.session.userId, value.credentialId);
  assert.equal(record.signCount, 5);
  assert.equal(record.version, 2);
});

test('high count wins first and ReportOnly re-verifies the later lower count with BS change', async t => {
  const value = fixture(t);
  const challenges = [0, 1].map(() => value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' }));
  const bodies = [assertionBody({ ...challenges[0], credentialId: value.credentialId }, 9, false),
    assertionBody({ ...challenges[1], credentialId: value.credentialId }, 3, true)];
  const results = await race(t, value, bodies, { ordered: true });
  assert.deepEqual(results[1].observed, [1, 9]);
  assert.equal(results[1].result.report.counter.status, 'WARNING');
  assert.equal(results[1].result.report.counter.stored, 9);
  const record = value.store.getCredential(value.session.userId, value.credentialId);
  assert.equal(record.signCount, 9);
  assert.equal(record.backupState, true);
  assert.equal(record.version, 2);
});

test('Reject uses latest committed counter after a real version conflict', async t => {
  const value = fixture(t, 'reject');
  const challenges = [0, 1].map(() => value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' }));
  const results = await race(t, value, [assertionBody({ ...challenges[0], credentialId: value.credentialId }, 9),
    assertionBody({ ...challenges[1], credentialId: value.credentialId }, 3)], { ordered: true });
  assert.deepEqual(results[1].observed, [1, 9]);
  assert.equal(results[1].result.status, 'FAIL');
  assert.equal(results[1].result.report.error.kind, 'CounterNonIncreasing');
  assert.equal(value.store.challenge(value.session, binding(value, challenges[1])).consumed_at, null);
  assert.equal(value.store.getCredential(value.session.userId, value.credentialId).signCount, 9);
});

test('backup eligibility mismatch never updates state or consumes challenge', async t => {
  const value = fixture(t);
  const issued = value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  const coordinator = new CeremonyCoordinator(value.store, storeTestCore(), value.config);
  const result = await coordinator.assert(value.session,
    assertionBody({ ...issued, credentialId: value.credentialId }, 7, false, false));
  assert.equal(result.report.error.kind, 'BackupEligibilityMismatch');
  assert.equal(value.store.getCredential(value.session.userId, value.credentialId).version, 0);
  assert.equal(value.store.challenge(value.session, binding(value, issued)).consumed_at, null);
});
