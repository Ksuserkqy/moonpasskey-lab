import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const target = process.env.CLI_TARGET ?? 'js';
const directory = mkdtempSync(join(tmpdir(), 'moonpasskey-cli-'));
after(() => rmSync(directory, { recursive: true, force: true }));

function run(args) {
  return spawnSync('moon', ['run', 'cmd/main', '--target', target, '--deny-warn', '--', ...args], {
    encoding: 'utf8', timeout: 60_000,
  });
}

function request(value) {
  const path = join(directory, 'request.json');
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  return path;
}

test('CLI displays help through the existing entry point', () => {
  const result = run([]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /MoonPasskey Lab analysis CLI/);
});

test('CLI analyzes original ClientDataJSON bytes with redacted JSON output', () => {
  const clientDataJSON = Buffer.from('{ "type": "webauthn.get", "challenge":"AQ", "origin":"https://example.com" }').toString('base64url');
  const result = run(['--input', request({ command: 'client-data', clientDataJSON }), '--json']);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'PASS');
  assert.equal(report.clientData.type, 'webauthn.get');
  assert.equal(report.clientData.challenge.redacted, true);
  assert.equal(report.clientData.origin, 'https://example.com');
  assert.equal(result.stdout.includes(clientDataJSON), false);
});

test('CLI independently analyzes AuthenticatorData with readable text output', () => {
  const bytes = Buffer.alloc(37);
  bytes[32] = 1;
  const result = run(['--input', request({ command: 'authenticator-data', authenticatorData: bytes.toString('base64url') })]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PASS/);
  assert.match(result.stdout, /signCount/);
  assert.match(result.stdout, /"up":true/);
});

test('CLI returns a typed failure and exit 2 for protocol input errors', () => {
  const result = run(['--input', request({ command: 'verify-assertion' }), '--json']);
  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'FAIL');
  assert.equal(typeof report.error.kind, 'string');
  assert.equal(typeof report.error.context, 'string');
});

test('CLI rejects unknown arguments with exit 64', () => {
  const result = run(['--unknown', '--json']);
  assert.equal(result.status, 64, result.stderr);
  assert.equal(JSON.parse(result.stdout).error.kind, 'InvalidArguments');
});

test('CLI rejects malformed UTF-8 without replacing original input bytes', () => {
  const path = join(directory, 'invalid-utf8.json');
  writeFileSync(path, Buffer.concat([Buffer.from('{"command":"client-data","'), Buffer.from([0xff]), Buffer.from('":0}')]), { mode: 0o600 });
  const result = run(['--input', path, '--json']);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).error.kind, 'InvalidInputUtf8');
});

test('CLI distinguishes missing input and filesystem failures', () => {
  const missing = run(['--json']);
  assert.equal(missing.status, 64, missing.stderr);
  assert.equal(JSON.parse(missing.stdout).error.kind, 'MissingInputFile');
  const unreadable = run(['--input', join(directory, 'absent.json'), '--json']);
  assert.equal(unreadable.status, 74, unreadable.stderr);
  assert.equal(JSON.parse(unreadable.stdout).error.kind, 'InputReadError');
});
