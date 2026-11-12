import { RpError, transportBytes } from './security.mjs';

const PRIVATE_KEYS = new Set([
  'record', 'credentialUpdate', 'raw', 'clientDataJSON', 'authenticatorData',
  'attestationObject', 'signature', 'credentialId', 'userHandle', 'publicKey',
  'expectedChallenge', 'challenge', 'challengeId', 'allowedCredentialIds', 'internal',
]);

// Internal bridge records are used for the database commit only. Reports retain
// statuses, public policy descriptions, flags, counts and typed error locations.
function redactReport(value, parent = '') {
  if (Array.isArray(value)) return value.map(item => redactReport(item, parent));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([key, item]) => !PRIVATE_KEYS.has(key)
        || (parent === 'checks' && ['PASS', 'FAIL', 'WARNING', 'NOT_PERFORMED', 'ADVANCED', 'NOT_SUPPORTED'].includes(item))
        || (['challenge', 'publicKey', 'authenticatorData', 'signature'].includes(key)
          && item !== null && typeof item === 'object' && !Array.isArray(item)))
      .map(([key, item]) => [key, redactReport(item, key)]));
  }
  return value;
}

export function publicReport(value) {
  const report = redactReport(value);
  if (report && typeof report === 'object' && ('redacted' in report || value.internal)) report.redacted = true;
  return report;
}

function coreRecord(record) {
  return {
    credentialId: record.credentialId, userHandle: record.userHandle,
    publicKey: record.publicKey, signCount: record.signCount,
    backupEligible: record.backupEligible,
  };
}

function checkCounter(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff;
}

export class CeremonyCoordinator {
  constructor(store, core, config, { beforeCommit = async () => {}, maxAttempts = 4 } = {}) {
    this.store = store;
    this.core = core;
    this.config = config;
    this.beforeCommit = beforeCommit;
    this.maxAttempts = maxAttempts;
  }

  binding(body, purpose) {
    return {
      challengeId: body.challengeId, challenge: body.challenge,
      purpose, rpId: this.config.rpId, origin: this.config.origin,
    };
  }

  policy(challenge, credentials = []) {
    return {
      rpId: challenge.rp_id, allowedOrigins: [challenge.origin],
      uv: challenge.user_verification, counterPolicy: challenge.counter_policy,
      allowCrossOrigin: false, allowedTopOrigins: [], allowedCredentialIds: credentials,
    };
  }

  checkEnvelope(body, registration = false) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new RpError('InvalidRequest');
    if (body.type !== 'public-key') throw new RpError('InvalidCredentialType');
    const id = transportBytes(body.rawId, 1023);
    if (id.length === 0) throw new RpError('InvalidCredentialId');
    transportBytes(body.clientDataJSON);
    if (registration) transportBytes(body.attestationObject);
    else {
      transportBytes(body.authenticatorData);
      transportBytes(body.signature, 72);
      if (body.userHandle !== null && body.userHandle !== undefined) transportBytes(body.userHandle, 64);
    }
  }

  async register(session, body) {
    this.checkEnvelope(body, true);
    const binding = this.binding(body, 'registration');
    const challenge = this.store.challenge(session, binding);
    const result = await this.core.host({
      command: 'register-test', clientDataJSON: body.clientDataJSON,
      attestationObject: body.attestationObject, credentialId: body.rawId,
      userHandle: session.userHandle, expectedChallenge: body.challenge,
      policy: this.policy(challenge),
    });
    const report = publicReport(result);
    if (result.status !== 'PASS') return { status: 'FAIL', report };
    const record = result.record;
    if (!record || record.credentialId !== body.rawId || record.userHandle !== session.userHandle
        || typeof record.publicKey !== 'string' || !checkCounter(record.signCount)
        || typeof record.backupEligible !== 'boolean') throw new RpError('InvalidCoreResponse', 500);
    const backupState = result.authenticatorData?.flags?.bs;
    if (typeof backupState !== 'boolean') throw new RpError('InvalidCoreResponse', 500);
    const committed = this.store.commitRegistration(session, binding,
      { ...record, backupState }, report);
    return { status: 'PASS', report, reportId: committed.reportId,
      databaseTransaction: { status: 'COMMITTED', previousVersion: null, version: 0 },
      credential: publicCredential(committed.credential) };
  }

  async assert(session, body) {
    this.checkEnvelope(body);
    const binding = this.binding(body, 'assertion');
    for (let attempt = 0; attempt < this.maxAttempts; attempt += 1) {
      const challenge = this.store.challenge(session, binding);
      const snapshot = this.store.getCredential(session.userId, body.rawId);
      if (!snapshot) throw new RpError('CredentialNotFound', 404);
      const result = await this.core.host({
        command: 'verify-assertion', clientDataJSON: body.clientDataJSON,
        authenticatorData: body.authenticatorData, signature: body.signature,
        credentialId: body.rawId, userHandle: body.userHandle ?? null,
        expectedChallenge: body.challenge, userIdentification: 'identified',
        policy: this.policy(challenge, [snapshot.credentialId]), credential: coreRecord(snapshot),
      });
      const report = publicReport(result);
      if (result.status !== 'PASS') return { status: 'FAIL', report, attempts: attempt + 1 };
      const update = result.credentialUpdate;
      if (!update || !checkCounter(update.signCount) || update.signCount < snapshot.signCount
          || update.previousSignCount !== snapshot.signCount
          || update.backupEligible !== snapshot.backupEligible
          || typeof update.backupState !== 'boolean') throw new RpError('InvalidCoreResponse', 500);
      await this.beforeCommit({ attempt, snapshot, result });
      const committed = this.store.commitAssertion(session, binding, snapshot, update, report);
      if (!committed.conflict) return {
        status: 'PASS', report, reportId: committed.reportId, attempts: attempt + 1,
        databaseTransaction: { status: 'COMMITTED', previousVersion: snapshot.version, version: snapshot.version + 1 },
        credential: publicCredential(this.store.getCredential(session.userId, body.rawId)),
      };
      // The next iteration loads the latest version and asks Core to evaluate
      // the original signature and counter against that latest trusted record.
    }
    throw new RpError('CredentialVersionConflict', 409);
  }
}

export function publicCredential(record) {
  return {
    id: record.credentialId, credentialId: record.credentialId,
    version: record.version, signCount: record.signCount,
    backupEligible: record.backupEligible, backupState: record.backupState,
  };
}
