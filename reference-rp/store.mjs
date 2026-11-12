import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { digest, randomToken, RpError, sameBytes, transportBytes } from './security.mjs';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, user_handle BLOB NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
  csrf_hash BLOB NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY, challenge_hash BLOB NOT NULL,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  user_id TEXT NOT NULL REFERENCES users(id), rp_id TEXT NOT NULL, origin TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER,
  purpose TEXT NOT NULL CHECK(purpose IN ('registration','assertion')),
  user_verification TEXT NOT NULL CHECK(user_verification IN ('required','preferred','discouraged')),
  counter_policy TEXT NOT NULL CHECK(counter_policy IN ('report-only','reject'))
) STRICT;
CREATE TABLE IF NOT EXISTS credentials (
  credential_id BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
  public_key BLOB NOT NULL, sign_count INTEGER NOT NULL CHECK(sign_count BETWEEN 0 AND 4294967295),
  backup_eligible INTEGER CHECK(backup_eligible IN (0,1)),
  backup_state INTEGER NOT NULL CHECK(backup_state IN (0,1)),
  version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL, report_json TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS challenges_session ON challenges(session_id, created_at);
CREATE INDEX IF NOT EXISTS credentials_user ON credentials(user_id);
CREATE INDEX IF NOT EXISTS reports_user ON reports(user_id, created_at);
`;

function credential(row) {
  if (!row) return null;
  return {
    credentialId: Buffer.from(row.credential_id).toString('base64url'),
    userId: row.user_id,
    userHandle: Buffer.from(row.user_handle).toString('base64url'),
    publicKey: Buffer.from(row.public_key).toString('base64url'),
    signCount: row.sign_count,
    backupEligible: row.backup_eligible === null ? null : Boolean(row.backup_eligible),
    backupState: Boolean(row.backup_state),
    version: row.version,
  };
}

export class RpStore {
  constructor(path, { now = Date.now, initialize = true } = {}) {
    this.now = now;
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path, { timeout: 5000, allowExtension: false });
    // SQLite derives WAL/SHM permissions from the database file. Set its mode
    // before schema writes can create either sidecar, including library use.
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
    if (initialize) {
      this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
      this.db.exec(SCHEMA);
    }
  }

  close() { this.db.close(); }

  createSession({ lifetimeMs = 8 * 60 * 60 * 1000 } = {}) {
    const now = this.now();
    const token = randomToken();
    const csrfToken = randomToken();
    const userId = randomToken(16);
    const userHandle = transportBytes(randomToken());
    const sessionId = digest(token).toString('hex');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const active = this.db.prepare('SELECT count(*) AS n FROM sessions WHERE expires_at > ?').get(now).n;
      if (active >= 128) throw new RpError('SessionCapacity', 429);
      this.db.prepare('INSERT INTO users VALUES (?,?,?)').run(userId, userHandle, now);
      this.db.prepare('INSERT INTO sessions VALUES (?,?,?,?,?)')
        .run(sessionId, userId, digest(csrfToken), now, now + lifetimeMs);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    return { token, csrfToken, sessionId, userId, userHandle: userHandle.toString('base64url') };
  }

  session(token) {
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
    const row = this.db.prepare(`SELECT s.*, u.user_handle FROM sessions s
      JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?`)
      .get(digest(token).toString('hex'), this.now());
    if (!row) return null;
    return { sessionId: row.id, userId: row.user_id,
      userHandle: Buffer.from(row.user_handle).toString('base64url'), csrfHash: row.csrf_hash };
  }

  rotateCsrf(session) {
    const token = randomToken();
    this.db.prepare('UPDATE sessions SET csrf_hash=? WHERE id=? AND expires_at>?')
      .run(digest(token), session.sessionId, this.now());
    return token;
  }

  checkCsrf(session, token) {
    if (typeof token !== 'string' || token.length > 128
        || !sameBytes(session.csrfHash, digest(token))) throw new RpError('CsrfMismatch', 403);
  }

  issueChallenge(session, { rpId, origin, purpose, userVerification = 'preferred',
    counterPolicy = 'report-only', ttlMs = 5 * 60 * 1000 }) {
    if (!['registration', 'assertion'].includes(purpose)) throw new RpError('InvalidPurpose');
    if (!['required', 'preferred', 'discouraged'].includes(userVerification)) throw new RpError('InvalidUvPolicy');
    if (!['report-only', 'reject'].includes(counterPolicy)) throw new RpError('InvalidCounterPolicy');
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 15 * 60 * 1000) throw new RpError('InvalidChallengeLifetime');
    const now = this.now();
    const id = randomToken(16);
    const challenge = randomToken(32);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const active = this.db.prepare(`SELECT count(*) AS n FROM challenges
        WHERE session_id=? AND consumed_at IS NULL AND expires_at>?`).get(session.sessionId, now).n;
      if (active >= 32) throw new RpError('ChallengeCapacity', 429);
      this.db.prepare(`INSERT INTO challenges VALUES (?,?,?,?,?,?,?,?,NULL,?,?,?)`)
        .run(id, digest(transportBytes(challenge)), session.sessionId, session.userId,
          rpId, origin, now, now + ttlMs, purpose, userVerification, counterPolicy);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    return { challengeId: id, challenge, expiresAt: now + ttlMs };
  }

  challenge(session, { challengeId, challenge, purpose, rpId, origin }) {
    const currentSession = this.db.prepare('SELECT user_id FROM sessions WHERE id=? AND expires_at>?')
      .get(session.sessionId, this.now());
    if (!currentSession || currentSession.user_id !== session.userId) throw new RpError('SessionExpired', 401);
    const raw = transportBytes(challenge, 32);
    if (raw.length !== 32) throw new RpError('ChallengeMismatch');
    if (typeof challengeId !== 'string' || challengeId.length > 64) throw new RpError('ChallengeNotFound');
    const row = this.db.prepare('SELECT * FROM challenges WHERE id=?').get(challengeId);
    if (!row) throw new RpError('ChallengeNotFound');
    if (row.session_id !== session.sessionId || row.user_id !== session.userId) throw new RpError('ChallengeSessionMismatch', 403);
    if (row.purpose !== purpose) throw new RpError('ChallengePurposeMismatch');
    if (row.rp_id !== rpId) throw new RpError('ChallengeRpIdMismatch');
    if (row.origin !== origin) throw new RpError('ChallengeOriginMismatch');
    if (!sameBytes(row.challenge_hash, digest(raw))) throw new RpError('ChallengeMismatch');
    if (row.consumed_at !== null) throw new RpError('ChallengeConsumed', 409);
    if (row.expires_at <= this.now()) throw new RpError('ChallengeExpired', 409);
    return row;
  }

  getCredential(userId, credentialId) {
    const raw = transportBytes(credentialId, 1023);
    return credential(this.db.prepare(`SELECT c.*,u.user_handle FROM credentials c
      JOIN users u ON u.id=c.user_id WHERE c.credential_id=? AND c.user_id=?`).get(raw, userId));
  }

  credentials(userId) {
    return this.db.prepare(`SELECT c.*,u.user_handle FROM credentials c JOIN users u ON u.id=c.user_id
      WHERE c.user_id=? ORDER BY c.created_at`).all(userId).map(credential);
  }

  // Challenge consumption, credential insert and sanitized report share a commit.
  commitRegistration(session, binding, value, report) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.challenge(session, binding);
      const now = this.now();
      const id = transportBytes(value.credentialId, 1023);
      if (this.db.prepare('SELECT count(*) AS n FROM credentials WHERE user_id=?').get(session.userId).n >= 16) {
        throw new RpError('CredentialCapacity', 429);
      }
      if (id.length === 0 || this.db.prepare('SELECT 1 FROM credentials WHERE credential_id=?').get(id)) {
        throw new RpError('CredentialAlreadyRegistered', 409);
      }
      this.db.prepare(`INSERT INTO credentials VALUES (?,?,?,?,?,?,0,?,?)`)
        .run(id, session.userId, transportBytes(value.publicKey), value.signCount,
          value.backupEligible === null ? null : Number(value.backupEligible), Number(value.backupState), now, now);
      this.consume(binding.challengeId, now);
      const reportId = this.insertReport(session.userId, report, now);
      this.db.exec('COMMIT');
      return { reportId, credential: this.getCredential(session.userId, value.credentialId) };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  // Core verification runs outside the write lock. A changed version causes a
  // complete re-read and re-verification by the caller before another attempt.
  commitAssertion(session, binding, snapshot, update, report) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.challenge(session, binding);
      const now = this.now();
      const result = this.db.prepare(`UPDATE credentials SET sign_count=?,backup_eligible=?,backup_state=?,
        version=version+1,updated_at=? WHERE credential_id=? AND user_id=? AND version=?`)
        .run(update.signCount, update.backupEligible === null ? null : Number(update.backupEligible),
          Number(update.backupState), now, transportBytes(snapshot.credentialId, 1023), session.userId, snapshot.version);
      if (result.changes !== 1) {
        this.db.exec('ROLLBACK');
        return { conflict: true };
      }
      this.consume(binding.challengeId, now);
      const reportId = this.insertReport(session.userId, report, now);
      this.db.exec('COMMIT');
      return { conflict: false, reportId };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  consume(id, now) {
    const changed = this.db.prepare(`UPDATE challenges SET consumed_at=?
      WHERE id=? AND consumed_at IS NULL AND expires_at>?`).run(now, id, now).changes;
    if (changed !== 1) throw new RpError('ChallengeConsumeConflict', 409);
  }

  insertReport(userId, report, now = this.now()) {
    const id = randomToken(16);
    this.db.prepare('INSERT INTO reports VALUES (?,?,?,?)').run(id, userId, now, JSON.stringify(report));
    this.db.prepare(`DELETE FROM reports WHERE user_id=? AND id NOT IN
      (SELECT id FROM reports WHERE user_id=? ORDER BY created_at DESC,rowid DESC LIMIT 100)`).run(userId, userId);
    return id;
  }

  reports(userId) {
    return this.db.prepare('SELECT id,created_at,report_json FROM reports WHERE user_id=? ORDER BY created_at DESC,rowid DESC LIMIT 100')
      .all(userId).map(row => ({ id: row.id, createdAt: row.created_at, report: JSON.parse(row.report_json) }));
  }
}
