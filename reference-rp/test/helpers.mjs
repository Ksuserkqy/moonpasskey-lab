import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RpStore } from '../store.mjs';

export function fixture(t, policy = 'report-only') {
  const directory = mkdtempSync(join(tmpdir(), 'moonpasskey-rp-'));
  const path = join(directory, 'test.sqlite');
  const store = new RpStore(path);
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  const created = store.createSession();
  const session = store.session(created.token);
  const config = { rpId: 'localhost', origin: 'http://localhost:8787', userVerification: 'preferred', counterPolicy: policy };
  const issued = store.issueChallenge(session, { ...config, purpose: 'registration' });
  const binding = { ...issued, ...config, purpose: 'registration' };
  const credentialId = Buffer.from('project-test-credential').toString('base64url');
  store.commitRegistration(session, binding, { credentialId,
    publicKey: Buffer.from('fake-public-key-for-store-tests').toString('base64url'),
    signCount: 1, backupEligible: true, backupState: false }, { status: 'PASS', testOnly: true });
  return { path, store, created, session, config, credentialId };
}

export function assertionBody(value, count = 2, bs = false, be = true) {
  return { ...value, type: 'public-key', rawId: value.credentialId,
    clientDataJSON: Buffer.from('{}').toString('base64url'),
    authenticatorData: Buffer.from(JSON.stringify({ count, bs, be })).toString('base64url'),
    signature: Buffer.alloc(8, 1).toString('base64url'), userHandle: null };
}

// This isolated test double exercises transaction orchestration only. Separate
// integration tests call the compiled MoonBit verifier with signed assertions.
export function storeTestCore(observed = []) {
  return { host: async input => {
    const received = JSON.parse(Buffer.from(input.authenticatorData, 'base64url'));
    const old = input.credential;
    observed.push(old.signCount);
    if (received.be !== old.backupEligible) return { status: 'FAIL', error: { kind: 'BackupEligibilityMismatch' } };
    const risk = received.count <= old.signCount && (received.count !== 0 || old.signCount !== 0);
    if (risk && input.policy.counterPolicy === 'reject') return { status: 'FAIL', error: { kind: 'CounterNonIncreasing' } };
    return { status: 'PASS', counter: { status: risk ? 'WARNING' : 'ADVANCED', stored: old.signCount, received: received.count },
      credentialUpdate: { signCount: Math.max(old.signCount, received.count), previousSignCount: old.signCount,
        backupEligible: old.backupEligible, backupState: received.bs } };
  } };
}
