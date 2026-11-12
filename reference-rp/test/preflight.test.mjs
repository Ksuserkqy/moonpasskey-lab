import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { inspectInteropEnvironment } from '../interop-preflight.mjs';
import { ephemeralTls } from './tls-fixtures.mjs';

const domain = 'interop.example.test';
const base = {
  REFERENCE_RP_ORIGIN: `https://${domain}`,
  REFERENCE_RP_ID: domain,
  REFERENCE_RP_UV: 'required',
  REFERENCE_RP_COUNTER: 'report-only',
};

function configuration(t) {
  const tls = ephemeralTls(t, domain);
  return { ...base, REFERENCE_RP_TLS_CERT: tls.certPath, REFERENCE_RP_TLS_KEY: tls.keyPath };
}

test('offline preflight validates exact config and key pair without claiming device or trust success', t => {
  const config = configuration(t);
  const result = inspectInteropEnvironment(config);
  assert.equal(result.status, 'PASS');
  assert.equal(result.scope, 'OFFLINE_CONFIGURATION');
  assert.equal(result.configuration.backendAddress, '127.0.0.1');
  assert.equal(result.configuration.backendPort, 8787);
  assert.equal(result.configuration.userVerification, 'required');
  for (const value of Object.values(result.checks)) assert.equal(value, 'PASS');
  for (const value of Object.values(result.manualChecks)) assert.equal(value, 'NOT_PERFORMED');
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(config.REFERENCE_RP_TLS_KEY), false);
  assert.equal(serialized.includes('PRIVATE KEY'), false);
});

for (const [name, override, kind] of [
  ['missing origin', { REFERENCE_RP_ORIGIN: '' }, 'MissingConfiguration'],
  ['placeholder domain', { REFERENCE_RP_ORIGIN: 'https://passkey-test.<owned-test-domain>' }, 'UnresolvedPlaceholder'],
  ['HTTP cross-device origin', { REFERENCE_RP_ORIGIN: `http://${domain}` }, 'InvalidHttpsOrigin'],
  ['origin with a path', { REFERENCE_RP_ORIGIN: `https://${domain}/page` }, 'InvalidHttpsOrigin'],
  ['origin with credentials', { REFERENCE_RP_ORIGIN: `https://private-user:private-token@${domain}` }, 'InvalidHttpsOrigin'],
  ['phone-local localhost', { REFERENCE_RP_ORIGIN: 'https://localhost' }, 'CrossDeviceDomainRequired'],
  ['numeric loopback', { REFERENCE_RP_ORIGIN: 'https://127.0.0.1' }, 'CrossDeviceDomainRequired'],
  ['RP domain mismatch', { REFERENCE_RP_ID: 'other.example.test' }, 'RpIdDomainMismatch'],
  ['invalid backend port', { REFERENCE_RP_PORT: '0' }, 'InvalidBackendPort'],
  ['unknown UV policy', { REFERENCE_RP_UV: 'optional' }, 'InvalidUvPolicy'],
  ['unknown counter policy', { REFERENCE_RP_COUNTER: 'ignore' }, 'InvalidCounterPolicy'],
]) {
  test(`offline preflight rejects ${name} before reading TLS files`, () => {
    const result = inspectInteropEnvironment({ ...base, ...override });
    assert.equal(result.status, 'FAIL');
    assert.equal(result.error.kind, kind);
    assert.equal(JSON.stringify(result).includes('private-token'), false);
  });
}

test('offline preflight distinguishes missing TLS files without disclosing paths', () => {
  const secretPath = '/nonexistent/interop-private-key.pem';
  const result = inspectInteropEnvironment({ ...base,
    REFERENCE_RP_TLS_CERT: secretPath, REFERENCE_RP_TLS_KEY: secretPath });
  assert.equal(result.error.kind, 'TlsFileReadError');
  assert.equal(result.error.context, 'REFERENCE_RP_TLS_CERT');
  assert.equal(JSON.stringify(result).includes(secretPath), false);
});

test('offline preflight rejects a certificate for another hostname', t => {
  const config = configuration(t);
  const result = inspectInteropEnvironment({ ...config,
    REFERENCE_RP_ORIGIN: 'https://other.example.test', REFERENCE_RP_ID: 'other.example.test' });
  assert.equal(result.error.kind, 'CertificateHostnameMismatch');
});

test('offline preflight rejects a mismatched private key', t => {
  const config = configuration(t);
  const other = ephemeralTls(t, domain);
  const result = inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_KEY: other.keyPath });
  assert.equal(result.error.kind, 'TlsKeyMismatch');
});

test('offline preflight rejects DER and malformed fullchain input that the RP cannot load', t => {
  const config = configuration(t);
  const tls = ephemeralTls(t, domain);
  const certificate = new X509Certificate(tls.cert);
  writeFileSync(tls.certPath, certificate.raw);
  assert.equal(inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_CERT: tls.certPath, REFERENCE_RP_TLS_KEY: tls.keyPath }).error.kind,
    'InvalidTlsCertificate');
  writeFileSync(tls.certPath, Buffer.concat([tls.cert, Buffer.from('\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n')]));
  assert.equal(inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_CERT: tls.certPath, REFERENCE_RP_TLS_KEY: tls.keyPath }).error.kind,
    'InvalidTlsCertificate');
});

test('offline preflight rejects DER and malformed CA bundles', t => {
  const config = configuration(t);
  const tls = ephemeralTls(t, domain);
  writeFileSync(tls.certPath, new X509Certificate(tls.cert).raw);
  assert.equal(inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_CA: tls.certPath }).error.kind,
    'InvalidOriginCaCertificate');
  writeFileSync(tls.certPath, Buffer.concat([tls.cert, Buffer.from('\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n')]));
  assert.equal(inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_CA: tls.certPath }).error.kind,
    'InvalidOriginCaCertificate');
});

test('offline preflight reports a nondefault edge port and leaves matching proxy headers for manual verification', t => {
  const config = configuration(t);
  const result = inspectInteropEnvironment({ ...config, REFERENCE_RP_ORIGIN: `https://${domain}:8443` });
  assert.equal(result.status, 'PASS');
  assert.equal(result.configuration.externalPort, 8443);
  assert.equal(result.manualChecks.proxyHostAndOriginMatch, 'NOT_PERFORMED');
});

test('offline preflight checks both certificate validity boundaries', t => {
  const config = configuration(t);
  const tls = ephemeralTls(t, domain);
  const certificate = new X509Certificate(tls.cert);
  const environment = { ...config, REFERENCE_RP_TLS_CERT: tls.certPath, REFERENCE_RP_TLS_KEY: tls.keyPath };
  assert.equal(inspectInteropEnvironment(environment, certificate.validFromDate.getTime() - 1).error.kind,
    'CertificateOutsideValidity');
  assert.equal(inspectInteropEnvironment(environment, certificate.validToDate.getTime()).error.kind,
    'CertificateOutsideValidity');
});

test('offline preflight accepts an explicit CA PEM while leaving chain trust unverified', t => {
  const config = configuration(t);
  const result = inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_CA: config.REFERENCE_RP_TLS_CERT });
  assert.equal(result.status, 'PASS');
  assert.equal(result.checks.originCaPem, 'PASS');
  assert.equal(result.configuration.originTrustSource, 'EXPLICIT_CA_POOL');
  assert.equal(result.manualChecks.originTlsChainVerification, 'NOT_PERFORMED');
});

test('offline preflight distinguishes malformed certificate, key and CA material', t => {
  const config = configuration(t);
  const tls = ephemeralTls(t, domain);
  writeFileSync(tls.certPath, 'not a certificate');
  assert.equal(inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_CERT: tls.certPath }).error.kind,
    'InvalidTlsCertificate');
  writeFileSync(tls.keyPath, 'not a private key');
  assert.equal(inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_KEY: tls.keyPath }).error.kind,
    'InvalidTlsPrivateKey');
  assert.equal(inspectInteropEnvironment({ ...config, REFERENCE_RP_TLS_CA: tls.certPath }).error.kind,
    'InvalidOriginCaCertificate');
});

test('preflight CLI returns a typed redacted failure and meaningful exit code', () => {
  const executable = fileURLToPath(new URL('../interop-preflight.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [executable], {
    env: { ...process.env, REFERENCE_RP_ORIGIN: '' }, encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.status, 2, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.error.kind, 'MissingConfiguration');
  assert.equal(output.error.context, 'REFERENCE_RP_ORIGIN');
  assert.equal(output.manualChecks.iphoneHttpsReachability, 'NOT_PERFORMED');
});
