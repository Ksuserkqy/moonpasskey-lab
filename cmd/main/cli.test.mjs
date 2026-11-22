import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const target = process.env.CLI_TARGET ?? 'js';
const maxInputBytes = 12_582_912;
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

test('CLI reads a valid request from a path with spaces and Unicode', () => {
  const nested = join(directory, '测试 folder 😀');
  mkdirSync(nested);
  const path = join(nested, '请求 file 😀.json');
  const clientDataJSON = Buffer.from('{"type":"webauthn.get","challenge":"AQ","origin":"https://example.com"}').toString('base64url');
  writeFileSync(path, JSON.stringify({ command: 'client-data', clientDataJSON }), { mode: 0o600 });
  const result = run(['--input', path, '--json']);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'PASS');
  assert.equal(report.clientData.type, 'webauthn.get');
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
  const directoryInput = run(['--input', directory, '--json']);
  assert.equal(directoryInput.status, 74, directoryInput.stderr);
  assert.equal(JSON.parse(directoryInput.stdout).error.kind, 'InputReadError');
});

test('CLI enforces the byte limit at the exact boundary in JSON and text modes', () => {
  const path = join(directory, 'boundary.json');
  // These inputs exceed the Core's UTF-16 envelope limit, so a successful
  // bounded read must reach the Core and report ResourceLimit, not InputTooLarge.
  writeFileSync(path, Buffer.alloc(maxInputBytes - 1, 0x20), { mode: 0o600 });
  for (const size of [maxInputBytes - 1, maxInputBytes]) {
    if (size === maxInputBytes) appendFileSync(path, ' ');
    const result = run(['--input', path, '--json']);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stdout).error.kind, 'ResourceLimit');
  }
  appendFileSync(path, ' ');
  const json = run(['--input', path, '--json']);
  assert.equal(json.status, 2, json.stderr);
  assert.equal(JSON.parse(json.stdout).error.kind, 'InputTooLarge');
  const text = run(['--input', path]);
  assert.equal(text.status, 2, text.stderr);
  assert.match(text.stdout, /^FAIL InputTooLarge\s*$/);
});

test('CLI accepts a near-limit multibyte UTF-8 envelope within the Core character budget', () => {
  const path = join(directory, '多字节-😀.json');
  const prefix = '{"command":"unknown","padding":"';
  const suffix = '"}';
  const units = 4_194_304;
  const input = Buffer.from(prefix + '中'.repeat(units - prefix.length - suffix.length) + suffix);
  assert.ok(input.length < maxInputBytes);
  writeFileSync(path, input, { mode: 0o600 });
  const result = run(['--input', path, '--json']);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).error.kind, 'UnknownCommand');
});

test('CLI passes an empty input to the JSON parser', () => {
  const path = join(directory, 'empty.json');
  writeFileSync(path, '', { mode: 0o600 });
  const result = run(['--input', path, '--json']);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).error.kind, 'InvalidJson');
});

test('CLI bounds a stream that grows while it is being read', { skip: process.platform === 'win32' }, async () => {
  const path = join(directory, 'growing.fifo');
  const mkfifo = spawnSync('mkfifo', [path], { encoding: 'utf8' });
  assert.equal(mkfifo.status, 0, mkfifo.stderr);
  // The writer blocks until the CLI opens the FIFO, then keeps producing data.
  // A stat-based check cannot determine this stream's eventual size.
  const writer = spawn(process.execPath, ['-e', `
    const fs = require('node:fs');
    const fd = fs.openSync(process.argv[1], 'w');
    const chunk = Buffer.alloc(16_384, 0x20);
    try {
      for (let sent = 0; sent < ${maxInputBytes} + chunk.length;) {
        sent += fs.writeSync(fd, chunk);
      }
    } catch (error) {
      if (error.code !== 'EPIPE') throw error;
    } finally {
      fs.closeSync(fd);
    }
  `, path], { stdio: 'ignore' });
  const writerDone = new Promise(resolve => writer.once('close', (code, signal) => resolve({ code, signal })));
  let timer;
  try {
    const result = run(['--input', path, '--json']);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stdout).error.kind, 'InputTooLarge');
    const outcome = await Promise.race([
      writerDone,
      new Promise(resolve => { timer = setTimeout(() => resolve(null), 5_000); }),
    ]);
    assert.deepEqual(outcome, { code: 0, signal: null });
  } finally {
    clearTimeout(timer);
    writer.kill();
  }
});
