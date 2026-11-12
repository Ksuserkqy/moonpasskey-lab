import { createPrivateKey, X509Certificate } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { createSecureContext } from 'node:tls';
import { pathToFileURL } from 'node:url';

class PreflightError extends Error {
  constructor(kind, context) {
    super(kind);
    this.kind = kind;
    this.context = context;
  }
}

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== 'string' || !value.trim() || value.length > 4096) {
    throw new PreflightError('MissingConfiguration', name);
  }
  if (/[<>]/.test(value)) throw new PreflightError('UnresolvedPlaceholder', name);
  return value;
}

function material(path, context) {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size === 0 || stat.size > 1_048_576) {
      throw new PreflightError('InvalidTlsFileSize', context);
    }
    return readFileSync(path);
  } catch (error) {
    if (error instanceof PreflightError) throw error;
    throw new PreflightError('TlsFileReadError', context);
  }
}

// Offline preparation only. This function reads only the TLS paths explicitly
// supplied by the operator and makes no network requests or trust-store edits.
export function inspectInteropEnvironment(environment, now = Date.now()) {
  const result = {
    scope: 'OFFLINE_CONFIGURATION',
    status: 'FAIL',
    checks: {},
    manualChecks: {
      domainOwnership: 'NOT_PERFORMED',
      browserCertificateTrust: 'NOT_PERFORMED',
      originTlsChainVerification: 'NOT_PERFORMED',
      accessPolicyAndConnectorJwt: 'NOT_PERFORMED',
      proxyHostAndOriginMatch: 'NOT_PERFORMED',
      iphoneHttpsReachability: 'NOT_PERFORMED',
      realDeviceCeremony: 'NOT_PERFORMED',
    },
  };
  try {
    const origin = required(environment, 'REFERENCE_RP_ORIGIN');
    let url;
    try { url = new URL(origin); }
    catch { throw new PreflightError('InvalidHttpsOrigin', 'REFERENCE_RP_ORIGIN'); }
    if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) {
      throw new PreflightError('InvalidHttpsOrigin', 'REFERENCE_RP_ORIGIN');
    }
    if (isIP(url.hostname) || url.hostname === 'localhost' || url.hostname.endsWith('.localhost')
        || !url.hostname.includes('.') || url.hostname.startsWith('[')) {
      throw new PreflightError('CrossDeviceDomainRequired', 'REFERENCE_RP_ORIGIN');
    }
    result.checks.httpsOrigin = 'PASS';
    const rpId = required(environment, 'REFERENCE_RP_ID');
    if (rpId !== url.hostname) throw new PreflightError('RpIdDomainMismatch', 'REFERENCE_RP_ID');
    result.checks.rpIdDomain = 'PASS';
    const port = Number(environment.REFERENCE_RP_PORT ?? 8787);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new PreflightError('InvalidBackendPort', 'REFERENCE_RP_PORT');
    }
    const uv = environment.REFERENCE_RP_UV ?? 'preferred';
    const counter = environment.REFERENCE_RP_COUNTER ?? 'report-only';
    if (!['required', 'preferred', 'discouraged'].includes(uv)) {
      throw new PreflightError('InvalidUvPolicy', 'REFERENCE_RP_UV');
    }
    if (!['report-only', 'reject'].includes(counter)) {
      throw new PreflightError('InvalidCounterPolicy', 'REFERENCE_RP_COUNTER');
    }
    result.checks.policies = 'PASS';
    const certificateBytes = material(required(environment, 'REFERENCE_RP_TLS_CERT'), 'REFERENCE_RP_TLS_CERT');
    const keyBytes = material(required(environment, 'REFERENCE_RP_TLS_KEY'), 'REFERENCE_RP_TLS_KEY');
    let certificate;
    let key;
    try { certificate = new X509Certificate(certificateBytes); }
    catch { throw new PreflightError('InvalidTlsCertificate', 'REFERENCE_RP_TLS_CERT'); }
    try { key = createPrivateKey(keyBytes); }
    catch { throw new PreflightError('InvalidTlsPrivateKey', 'REFERENCE_RP_TLS_KEY'); }
    if (!certificate.checkPrivateKey(key)) {
      throw new PreflightError('TlsKeyMismatch', 'REFERENCE_RP_TLS_KEY');
    }
    result.checks.certificateKeyPair = 'PASS';
    try { createSecureContext({ cert: certificateBytes, key: keyBytes }); }
    catch { throw new PreflightError('InvalidTlsCertificate', 'REFERENCE_RP_TLS_CERT'); }
    result.checks.completeTlsContext = 'PASS';
    if (!certificate.checkHost(rpId, { subject: 'never' })) {
      throw new PreflightError('CertificateHostnameMismatch', 'REFERENCE_RP_TLS_CERT');
    }
    result.checks.certificateHostname = 'PASS';
    if (!Number.isFinite(now) || now < certificate.validFromDate.getTime()
        || now >= certificate.validToDate.getTime()) {
      throw new PreflightError('CertificateOutsideValidity', 'REFERENCE_RP_TLS_CERT');
    }
    result.checks.certificateValidity = 'PASS';
    if (environment.REFERENCE_RP_TLS_CA) {
      const caBytes = material(required(environment, 'REFERENCE_RP_TLS_CA'), 'REFERENCE_RP_TLS_CA');
      try {
        const text = caBytes.toString('utf8').replace(/^\s*#.*$/gm, '').trim();
        const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
        const remainder = text.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim();
        if (blocks.length === 0 || remainder) throw new Error();
        for (const block of blocks) new X509Certificate(block);
      }
      catch { throw new PreflightError('InvalidOriginCaCertificate', 'REFERENCE_RP_TLS_CA'); }
      result.checks.originCaPem = 'PASS';
    }
    result.configuration = {
      origin, rpId, userVerification: uv, counterPolicy: counter,
      backendAddress: '127.0.0.1', backendPort: port, externalPort: Number(url.port || 443),
      originTrustSource: environment.REFERENCE_RP_TLS_CA ? 'EXPLICIT_CA_POOL' : 'SYSTEM_TRUST',
      certificateExpiresAt: certificate.validToDate.toISOString(),
    };
    result.status = 'PASS';
  } catch (error) {
    result.error = error instanceof PreflightError
      ? { kind: error.kind, context: error.context }
      : { kind: 'InvalidPreflightInput', context: 'configuration' };
  }
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = inspectInteropEnvironment(process.env);
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.status === 'PASS' ? 0 : 2;
}
