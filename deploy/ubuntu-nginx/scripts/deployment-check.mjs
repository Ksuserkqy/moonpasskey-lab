import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { arch } from 'node:os';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inspectInteropEnvironment } from '../../../reference-rp/interop-preflight.mjs';

const DOMAIN = 'passkey-test.ksuser.cn';
const ORIGIN = `https://${DOMAIN}`;
const REQUIRED_KEYS = ['REFERENCE_RP_PORT', 'REFERENCE_RP_ORIGIN', 'REFERENCE_RP_ID',
  'REFERENCE_RP_UV', 'REFERENCE_RP_COUNTER', 'REFERENCE_RP_TLS_CERT',
  'REFERENCE_RP_TLS_KEY', 'REFERENCE_RP_TLS_CA', 'REFERENCE_RP_DB'];
const ALLOWED_KEYS = new Set([...REQUIRED_KEYS, 'REFERENCE_RP_CORE']);

class CheckError extends Error {
  constructor(kind) { super(kind); this.kind = kind; }
}

// Deliberately a small subset of systemd EnvironmentFile syntax: literal,
// unquoted KEY=VALUE lines only. Shell syntax is rejected, never interpreted.
export function parseEnvironmentText(text) {
  if (Buffer.byteLength(text) > 65_536 || text.includes('\0')) throw new CheckError('InvalidEnvironmentFile');
  const result = Object.create(null);
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=([^\s'"`$\\;#<>]+)$/.exec(line);
    if (!match || !ALLOWED_KEYS.has(match[1])) throw new CheckError('InvalidEnvironmentAssignment');
    if (Object.hasOwn(result, match[1])) throw new CheckError('DuplicateEnvironmentKey');
    result[match[1]] = match[2];
  }
  for (const key of REQUIRED_KEYS) {
    if (!result[key]) throw new CheckError(`MissingConfiguration:${key}`);
  }
  if (result.REFERENCE_RP_PORT !== '8787' || result.REFERENCE_RP_ORIGIN !== ORIGIN
      || result.REFERENCE_RP_ID !== DOMAIN || result.REFERENCE_RP_UV !== 'required'
      || result.REFERENCE_RP_COUNTER !== 'report-only') throw new CheckError('DeploymentPolicyMismatch');
  for (const key of ['REFERENCE_RP_TLS_CERT', 'REFERENCE_RP_TLS_KEY', 'REFERENCE_RP_TLS_CA',
    'REFERENCE_RP_DB', ...(result.REFERENCE_RP_CORE ? ['REFERENCE_RP_CORE'] : [])]) {
    if (!isAbsolute(result[key]) || result[key].split('/').includes('..')) {
      throw new CheckError(`AbsolutePathRequired:${key}`);
    }
  }
  return result;
}

function command(path, args) {
  const result = spawnSync(path, args, { encoding: 'utf8', timeout: 15_000,
    maxBuffer: 1_048_576, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' } });
  return { ok: !result.error && result.status === 0, output: `${result.stdout ?? ''}\n${result.stderr ?? ''}` };
}

function file(path, max = 1_048_576) {
  const info = statSync(path);
  if (!info.isFile() || info.size <= 0 || info.size > max) throw new CheckError('InvalidFile');
  return { info, bytes: readFileSync(path) };
}

// Check the effective service identity using Unix owner/group/other bits on the
// real target and every ancestor. ACLs, AppArmor, mounts and systemd sandboxing
// still need live verification; no probe file or SQLite database is created.
export function canAccessAs(path, identity, permission) {
  const permits = (info, requested) => {
    const shift = info.uid === identity.uid ? 6 : identity.groups.includes(info.gid) ? 3 : 0;
    return ((info.mode >> shift) & requested) === requested;
  };
  try {
    const actual = realpathSync(path);
    if (!permits(statSync(actual), permission)) return false;
    // Both the lexical and resolved path matter when a parent is a symlink.
    for (const target of new Set([resolve(path), actual])) {
      for (let ancestor = dirname(target); ; ancestor = dirname(ancestor)) {
        if (!permits(statSync(ancestor), 1)) return false;
        if (ancestor === dirname(ancestor)) break;
      }
    }
    return true;
  } catch (error) {
    if (['EACCES', 'ENOENT', 'ENOTDIR'].includes(error.code)) return false;
    throw error;
  }
}

export function inspectApplicationCore(path, identity) {
  let info;
  try { info = statSync(path); }
  catch (error) {
    if (error.code === 'ENOENT') throw new CheckError('ApplicationCoreMissing');
    if (['EACCES', 'ENOTDIR'].includes(error.code)) throw new CheckError('ApplicationCoreNotReadableByService');
    throw error;
  }
  if (!info.isFile() || info.size <= 0 || info.size > 67_108_864) throw new CheckError('InvalidApplicationCoreArtifact');
  if (!identity) throw new CheckError('ServiceIdentityRequired');
  if (!canAccessAs(path, identity, 4)) throw new CheckError('ApplicationCoreNotReadableByService');
  if (info.uid !== 0 || (info.mode & 0o022)) throw new CheckError('UnsafeApplicationCorePermissions');
  for (const target of new Set([resolve(path), realpathSync(path)])) {
    for (let parent = dirname(target); ; parent = dirname(parent)) {
      const directory = statSync(parent);
      if (!directory.isDirectory() || directory.uid !== 0 || (directory.mode & 0o022)) {
        throw new CheckError('UnsafeApplicationCoreParentPermissions');
      }
      if (parent === dirname(parent)) break;
    }
  }
  file(path, 67_108_864);
  return 'Compiled Core exists, is readable by the service and has root-controlled artifact/parents; no code executed';
}

export function inspectTls(environment, openssl = '/usr/bin/openssl') {
  const result = inspectInteropEnvironment(environment);
  if (result.status !== 'PASS') throw new CheckError(result.error.kind);
  const leaf = new X509Certificate(file(environment.REFERENCE_RP_TLS_CERT).bytes);
  const caBytes = file(environment.REFERENCE_RP_TLS_CA).bytes;
  const caBlocks = caBytes.toString('utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (caBlocks.length !== 1) throw new CheckError('SingleBackendCaRequired');
  const ca = new X509Certificate(caBlocks[0]);
  if (leaf.ca || !ca.ca || leaf.fingerprint256 === ca.fingerprint256) throw new CheckError('IndependentBackendCaAndLeafRequired');
  const verification = command(openssl, ['verify', '-check_ss_sig', '-x509_strict', '-purpose', 'sslserver', '-verify_hostname', DOMAIN,
    '-no-CApath', '-no-CAstore', '-CAfile', environment.REFERENCE_RP_TLS_CA, '-untrusted', environment.REFERENCE_RP_TLS_CERT,
    environment.REFERENCE_RP_TLS_CERT]);
  if (!verification.ok) throw new CheckError('BackendCertificateChainUntrusted');
  return 'Certificate/key, SAN, dates and explicit backend CA chain verified offline';
}

function identityFor(user) {
  if (!/^[a-z_][a-z0-9_-]*[$]?$/.test(user)) throw new CheckError('InvalidServiceUser');
  const uid = command('/usr/bin/id', ['-u', user]);
  const groups = command('/usr/bin/id', ['-G', user]);
  if (!uid.ok || !groups.ok || !/^\d+\s*$/.test(uid.output)) throw new CheckError('ServiceUserUnavailable');
  const groupIds = groups.output.trim().split(/\s+/).map(Number);
  if (!groupIds.length || groupIds.some(value => !Number.isSafeInteger(value))) throw new CheckError('InvalidServiceGroups');
  const result = { uid: Number(uid.output.trim()), groups: groupIds };
  if (result.uid === 0) throw new CheckError('ServiceUserMustNotBeRoot');
  return result;
}

function privateFile(path, { owner = 0, serviceIdentity, groupReadable = false } = {}) {
  const { info } = file(path);
  if (info.uid !== owner || !(info.mode & 0o400) || (info.mode & 0o137) !== 0
      || (!groupReadable && (info.mode & 0o070) !== 0)) {
    throw new CheckError('UnsafePrivateFilePermissions');
  }
  if (serviceIdentity && !canAccessAs(path, serviceIdentity, 4)) throw new CheckError('ServiceCannotReadPrivateFile');
}

function portListeners(text) {
  const values = [];
  for (const line of text.trim().split('\n')) {
    const columns = line.trim().split(/\s+/);
    const match = /^(.*):(80|443|8787)$/.exec(columns[3] ?? '');
    if (match) values.push({ address: match[1], port: Number(match[2]), nginx: /"nginx"/.test(line), node: /"node"/.test(line) });
  }
  return values;
}

export function requestHttps(options) {
  return new Promise((resolveRequest, reject) => {
    const req = httpsRequest({ method: 'GET', port: 443, ...options,
      rejectUnauthorized: true, agent: false }, response => {
      let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 1_048_576) req.destroy(new Error('ResponseTooLarge')); });
      response.on('end', () => resolveRequest(response.statusCode));
      response.on('error', reject);
    });
    // Socket timeout alone does not bound DNS. The total deadline does.
    const deadline = setTimeout(() => req.destroy(new Error('RequestDeadlineExceeded')), 10_000);
    req.on('close', () => clearTimeout(deadline));
    req.on('error', reject);
    req.end();
  });
}

export async function inspectLiveHttps(add, options, environment, send = requestHttps) {
  let authorization;
  await add('verificationCredentials', () => {
    if (!options.credentialsFile) throw new CheckError('CredentialsFileRequired');
    privateFile(options.credentialsFile, { owner: process.getuid() });
    const credentials = new TextDecoder('utf-8', { fatal: true })
      .decode(file(options.credentialsFile, 4096).bytes).replace(/\r?\n$/, '');
    if (!/^[^:\s\x00-\x1f\x7f]+:[^\x00-\x1f\x7f]+$/.test(credentials)) throw new CheckError('InvalidCredentialsFile');
    authorization = `Basic ${Buffer.from(credentials).toString('base64')}`;
    return 'Private credentials file accepted; credentials omitted from diagnostics';
  });
  if (!authorization) return;
  const ca = file(environment.REFERENCE_RP_TLS_CA).bytes;
  const backend = { hostname: '127.0.0.1', port: 8787, servername: DOMAIN, ca,
    path: '/', headers: { Host: DOMAIN } };
  const expect = async (name, requestOptions, status) => add(name, async () => {
    if (await send(requestOptions) !== status) throw new CheckError('UnexpectedHttpStatus');
    return `HTTPS response ${status}; certificate verification enabled`;
  });
  await expect('backendHttps', backend, 200);
  await expect('backendRejectsHost', { ...backend, headers: { Host: 'invalid.example.test' } }, 403);
  await expect('backendRejectsOrigin', { ...backend, headers: { Host: DOMAIN, Origin: 'https://invalid.example.test' } }, 403);
  const edge = { hostname: DOMAIN, servername: DOMAIN, path: '/' };
  await expect('publicRequiresBasicAuth', edge, 401);
  await expect('publicAuthenticatedHttps', { ...edge, headers: { Authorization: authorization } }, 200);
  await expect('publicRejectsOrigin', { ...edge,
    headers: { Authorization: authorization, Origin: 'https://invalid.example.test' } }, 403);
}

export async function runChecks(options) {
  const report = { scope: options.network ? 'LIVE_HTTPS_VERIFICATION' : 'OFFLINE_READINESS',
    status: 'PASS', checks: {}, limitations: [
      'This script does not write local files/databases or change services, firewall rules, DNS records or trust stores.',
      'Unix access-bit checks do not prove ACL, AppArmor, mount or systemd sandbox access.',
      'No real-device WebAuthn ceremony, browser trust or iPhone reachability is proven.',
    ] };
  const add = async (name, inspect) => {
    try { report.checks[name] = { status: 'PASS', detail: await inspect() }; }
    catch (error) {
      report.checks[name] = { status: 'FAIL', detail: error instanceof CheckError ? error.kind : 'CheckUnavailableOrInvalid' };
      report.status = 'FAIL';
    }
  };
  await add('operatingSystem', () => {
    const release = readFileSync('/etc/os-release', 'utf8');
    if (!/^ID=(?:ubuntu|"ubuntu")$/m.test(release) || !/^VERSION_ID=(?:22\.04|"22\.04")$/m.test(release)) {
      throw new CheckError('Ubuntu2204Required');
    }
    return 'Ubuntu 22.04';
  });
  await add('cpuArchitecture', () => {
    if (!['x64', 'arm64'].includes(arch())) throw new CheckError('UnsupportedCpuArchitecture');
    return arch() === 'x64' ? 'x64 (Node linux-x64)' : 'arm64 (Node linux-arm64)';
  });
  await add('nodeVersion', () => {
    if (process.versions.node !== '24.18.0') throw new CheckError('Node24180Required');
    return 'Node v24.18.0';
  });
  await add('moonbitVersion', () => {
    const result = command(options.moon, ['version', '--all']);
    if (!result.ok || !/\bmoonc v0\.10\.20\+65efd5b93(?:\s|$)/m.test(result.output)) throw new CheckError('Moonc01020Build65efd5b93Required');
    return 'moonc v0.10.20+65efd5b93';
  });
  await add('openssl', () => {
    const result = command(options.openssl, ['version']);
    const version = /^OpenSSL\s+[0-9A-Za-z.+-]+/.exec(result.output);
    if (!result.ok || !version) throw new CheckError('OpenSslUnavailable');
    return version[0];
  });
  await add('nginxInstalled', () => {
    const result = command('/usr/sbin/nginx', ['-v']);
    const version = /nginx\/[0-9.]+/.exec(result.output);
    if (!result.ok || !version) throw new CheckError('NginxUnavailable');
    return version[0];
  });
  await add('nginxService', () => {
    const state = command('/bin/systemctl', ['is-active', 'nginx.service']);
    const active = state.ok && state.output.trim() === 'active';
    if (options.mode === 'verify' && !active) throw new CheckError('NginxNotActive');
    if (!active && state.output.trim() === 'failed') throw new CheckError('NginxServiceFailed');
    if (!active && !/^inactive\s*$/.test(state.output)) throw new CheckError('NginxServiceStateUnavailable');
    return active ? 'active (no service change requested)' : 'stopped; acceptable before first deployment';
  });
  await add('ports', () => {
    const result = command('/usr/bin/ss', ['-H', '-ltnp']);
    if (!result.ok) throw new CheckError('ListenerInspectionUnavailable');
    const listeners = portListeners(result.output);
    if (listeners.some(value => value.port === 8787 && (value.address !== '127.0.0.1' || !value.node))) {
      throw new CheckError('BackendPortExposedOrOccupied');
    }
    if (listeners.some(value => [80, 443].includes(value.port) && !value.nginx)) {
      throw new CheckError('EdgePortOccupiedByOtherProcess');
    }
    if (options.mode === 'verify' && [80, 443, 8787].some(port => !listeners.some(value => value.port === port))) {
      throw new CheckError('DeploymentListenerMissing');
    }
    return [80, 443, 8787].map(port => `${port}: ${listeners.some(value => value.port === port) ? 'listening as expected' : 'free'}`).join('; ');
  });
  let environment;
  await add('environment', () => {
    const { bytes } = file(options.envFile, 65_536);
    environment = parseEnvironmentText(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return 'All required literal values match the fixed RP, origin and policies';
  });
  let identity;
  await add('serviceIdentity', () => {
    identity = identityFor(options.serviceUser);
    return 'Dedicated non-root service user and supplementary groups resolved';
  });
  await add('environmentPermissions', () => {
    privateFile(options.envFile, { groupReadable: true });
    const info = statSync(options.envFile);
    if ((info.mode & 0o040) && (!identity || !identity.groups.includes(info.gid))) throw new CheckError('EnvironmentGroupIsNotServiceGroup');
    return 'Root-owned private environment; systemd PID1 loads it before changing the service user';
  });
  if (environment) {
    if (environment.REFERENCE_RP_CORE) {
      await add('applicationCore', () => inspectApplicationCore(environment.REFERENCE_RP_CORE, identity));
    }
    await add('backendTls', () => inspectTls(environment, options.openssl));
    await add('backendCaPermissions', () => {
      const { info } = file(environment.REFERENCE_RP_TLS_CA);
      if (info.uid !== 0 || (info.mode & 0o022)) throw new CheckError('UnsafeBackendCaPermissions');
      return 'Public backend CA is root-owned and not writable by group or others';
    });
    await add('backendTlsPermissions', () => {
      if (!identity) throw new CheckError('ServiceIdentityRequired');
      privateFile(environment.REFERENCE_RP_TLS_KEY, { serviceIdentity: identity, groupReadable: true });
      if (!canAccessAs(environment.REFERENCE_RP_TLS_CERT, identity, 4)
          || !canAccessAs(environment.REFERENCE_RP_TLS_CA, identity, 4)) throw new CheckError('ServiceCannotReadTlsCertificate');
      return 'Root-owned backend key is private; service can traverse and read TLS inputs';
    });
    await add('sqliteAccess', () => {
      if (!identity) throw new CheckError('ServiceIdentityRequired');
      const parent = dirname(environment.REFERENCE_RP_DB);
      const info = statSync(parent);
      if (!info.isDirectory() || !canAccessAs(parent, identity, 3)) throw new CheckError('SqliteDirectoryNotWritable');
      if (info.mode & 0o022) throw new CheckError('SqliteDirectoryTooBroad');
      try {
        const database = statSync(environment.REFERENCE_RP_DB);
        if (!database.isFile() || !canAccessAs(environment.REFERENCE_RP_DB, identity, 6)
            || (database.mode & 0o077)) throw new CheckError('SqliteFileNotPrivateOrWritable');
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
      return 'Service has directory write/traversal and existing database read/write permission; no write probe performed';
    });
  }
  await add('edgeTls', () => {
    const result = inspectInteropEnvironment({ REFERENCE_RP_ORIGIN: ORIGIN, REFERENCE_RP_ID: DOMAIN,
      REFERENCE_RP_TLS_CERT: options.edgeCert, REFERENCE_RP_TLS_KEY: options.edgeKey });
    if (result.status !== 'PASS') throw new CheckError(result.error.kind);
    privateFile(options.edgeKey);
    const chain = command(options.openssl, ['verify', '-purpose', 'sslserver', '-verify_hostname', DOMAIN,
      '-untrusted', options.edgeCert, options.edgeCert]);
    if (!chain.ok) throw new CheckError('EdgeCertificateSystemChainUntrusted');
    return 'Edge certificate/key, SAN, dates, root-only key and system CA chain verified offline';
  });
  if (options.checkDns || options.network) {
    await add('dns', () => {
      const result = command('/usr/bin/getent', ['ahosts', DOMAIN]);
      if (!result.ok || !result.output.trim()) throw new CheckError('DnsResolutionFailed');
      return 'System resolver returned addresses; ownership and intended server address require operator comparison';
    });
  } else report.checks.dns = { status: 'NOT_PERFORMED', detail: 'Use --check-dns for a system resolver lookup' };
  if (options.network && environment) {
    await add('networkVerification', async () => {
      await inspectLiveHttps(add, options, environment);
      return 'Authorized HTTPS checks completed; inspect individual response checks';
    });
  }
  else report.checks.liveHttps = { status: 'NOT_PERFORMED', detail: 'Use verify-deployment.sh --network --credentials-file PATH after deployment' };
  return report;
}

function optionsFrom(args) {
  const options = { mode: 'preflight', envFile: '/etc/moonpasskey/reference-rp.env', serviceUser: 'moonpasskey',
    moon: '/opt/moonbit-0.10.20/bin/moon', openssl: '/usr/bin/openssl',
    edgeCert: `/etc/letsencrypt/live/${DOMAIN}/fullchain.pem`,
    edgeKey: `/etc/letsencrypt/live/${DOMAIN}/privkey.pem`, network: false, checkDns: false, json: false };
  const fields = { '--mode': 'mode', '--env-file': 'envFile', '--service-user': 'serviceUser',
    '--moon': 'moon', '--openssl': 'openssl', '--edge-cert': 'edgeCert', '--edge-key': 'edgeKey',
    '--credentials-file': 'credentialsFile' };
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--json') options.json = true;
    else if (argument === '--network') options.network = true;
    else if (argument === '--check-dns') options.checkDns = true;
    else if (fields[argument] && args[index + 1] && !args[index + 1].startsWith('--')) options[fields[argument]] = args[++index];
    else throw new CheckError('UnknownOrIncompleteArgument');
  }
  if (!['preflight', 'verify'].includes(options.mode) || (options.network && options.mode !== 'verify')) throw new CheckError('NetworkRequiresVerifyMode');
  for (const key of ['envFile', 'moon', 'openssl', 'edgeCert', 'edgeKey', ...(options.credentialsFile ? ['credentialsFile'] : [])]) {
    if (!isAbsolute(options[key])) throw new CheckError('AbsoluteOptionPathRequired');
  }
  if (options.network && !options.credentialsFile) throw new CheckError('CredentialsFileRequired');
  return options;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.includes('--help')) {
      console.log('Usage: preflight.sh [--node ABSOLUTE_PATH] [--env-file ABSOLUTE_PATH] [--json] [--check-dns]');
      console.log('       verify-deployment.sh [same options] [--network --credentials-file ABSOLUTE_PATH]');
      console.log('Defaults: offline/read-only; --network is accepted only by verify-deployment.sh.');
      console.log('Additional absolute-path overrides: --moon, --openssl, --edge-cert, --edge-key; --service-user NAME.');
      process.exit(0);
    }
    const options = optionsFrom(process.argv.slice(2));
    const report = await runChecks(options);
    if (options.json) console.log(JSON.stringify(report, null, 2));
    else {
      console.log(`${report.status}: ${report.scope}`);
      for (const [name, check] of Object.entries(report.checks)) console.log(`${check.status} ${name}: ${check.detail}`);
      for (const limitation of report.limitations) console.log(limitation);
    }
    process.exitCode = report.status === 'PASS' ? 0 : 2;
  } catch (error) {
    console.error(error instanceof CheckError ? error.kind : 'DeploymentCheckFailed');
    process.exitCode = 2;
  }
}
