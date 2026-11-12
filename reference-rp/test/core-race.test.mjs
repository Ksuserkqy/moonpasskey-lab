import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { loadCore } from '../core.mjs';
import { CeremonyCoordinator } from '../coordinator.mjs';
import { fixture } from './helpers.mjs';
import { ephemeralAuthenticator } from './signed-fixtures.mjs';
import { race } from './race.mjs';

const corePath = fileURLToPath(new URL('../../_build/js/debug/build/analysis/analysis.js', import.meta.url));

async function realFixture(t, policy) {
  const value = fixture(t, policy);
  const core = await loadCore(corePath);
  const authenticator = ephemeralAuthenticator();
  const coordinator = new CeremonyCoordinator(value.store, core, value.config);
  const issued = value.store.issueChallenge(value.session, { ...value.config, purpose: 'registration' });
  const registered = await coordinator.register(value.session, authenticator.register(issued, value.config));
  assert.equal(registered.status, 'PASS');
  value.credentialId = authenticator.credentialId;
  return { value, authenticator };
}

test('actual Core and two independent workers reject a replay after competing signed assertions', async t => {
  const { value, authenticator } = await realFixture(t, 'report-only');
  const issued = value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' });
  const signed = authenticator.assertion(issued, value.config, 4);
  const results = await race(t, value, [signed, signed], { corePath });
  assert.equal(results.filter(result => result.result?.status === 'PASS').length, 1);
  assert.equal(results.filter(result => result.error === 'ChallengeConsumed').length, 1);
  assert.equal(value.store.getCredential(value.session.userId, value.credentialId).version, 1);
});

test('actual Core re-verifies signed lower counter after CAS and reports risk with current BS', async t => {
  const { value, authenticator } = await realFixture(t, 'report-only');
  const challenges = [0, 1].map(() => value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' }));
  const results = await race(t, value, [authenticator.assertion(challenges[0], value.config, 9),
    authenticator.assertion(challenges[1], value.config, 3, { bs: true })], { corePath, ordered: true });
  assert.deepEqual(results[1].observed, [1, 9]);
  assert.equal(results[1].result.status, 'PASS');
  assert.equal(results[1].result.report.counter.status, 'WARNING');
  assert.equal(results[1].result.report.counter.stored, 9);
  assert.equal(results[1].result.report.checks.signature, 'PASS');
  const record = value.store.getCredential(value.session.userId, value.credentialId);
  assert.equal(record.signCount, 9);
  assert.equal(record.backupState, true);
  assert.equal(record.version, 2);
});

test('actual Core Reject policy re-evaluates the latest signed counter after a true CAS conflict', async t => {
  const { value, authenticator } = await realFixture(t, 'reject');
  const challenges = [0, 1].map(() => value.store.issueChallenge(value.session, { ...value.config, purpose: 'assertion' }));
  const results = await race(t, value, [authenticator.assertion(challenges[0], value.config, 9),
    authenticator.assertion(challenges[1], value.config, 3)], { corePath, ordered: true });
  assert.deepEqual(results[1].observed, [1, 9]);
  assert.equal(results[1].result.status, 'FAIL');
  assert.equal(results[1].result.report.error.kind, 'CounterNonIncreasing');
  assert.equal(value.store.getCredential(value.session.userId, value.credentialId).signCount, 9);
  assert.equal(value.store.challenge(value.session, { ...challenges[1], ...value.config, purpose: 'assertion' }).consumed_at, null);
});
