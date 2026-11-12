import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';

// This executes the checked-in vhosts against a synthetic HTTPS transport stub.
// It tests Nginx behavior, not WebAuthn ceremony or real-device acceptance.
// Install Nginx on the test host, or set MOONPASSKEY_NGINX_BIN to its absolute path.
// CI can set MOONPASSKEY_REQUIRE_NGINX=1 so a missing runtime is a failure.
const domain = 'passkey-test.ksuser.cn';
const nginx = process.env.MOONPASSKEY_NGINX_BIN || 'nginx';
const detection = spawnSync(nginx, ['-v'], { encoding: 'utf8' });
const missingRuntime = detection.error?.code === 'ENOENT';
const required = process.env.MOONPASSKEY_REQUIRE_NGINX === '1' || Boolean(process.env.MOONPASSKEY_NGINX_BIN);
const templateRoot = new URL('../nginx/', import.meta.url);
const readTemplate = name => readFileSync(new URL(name, templateRoot), 'utf8');

function command(executable, args) {
  const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 30_000 });
  assert.equal(result.error, undefined, `${executable}: ${result.error?.message}`);
  assert.equal(result.status, 0, `${executable} failed: ${result.stderr}`);
  return result.stdout;
}
const quote = value => `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;

function certificates(directory) {
  function ca(name) {
    const key = join(directory, `${name}.key`);
    const cert = join(directory, `${name}.crt`);
    command('openssl', ['req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '2',
      '-keyout', key, '-out', cert, '-subj', `/CN=MoonPasskey synthetic ${name}`,
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    return { key, cert };
  }
  function leaf(name, authority, hostname, expired = false) {
    const key = join(directory, `${name}.key`);
    const cert = join(directory, `${name}.crt`);
    const csr = join(directory, `${name}.csr`);
    const extensions = join(directory, `${name}.ext`);
    writeFileSync(extensions, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${hostname}\n`);
    command('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-keyout', key,
      '-out', csr, '-subj', `/CN=${hostname}`]);
    if (expired) {
      const database = join(directory, 'expired-index');
      const serial = join(directory, 'expired-serial');
      const configuration = join(directory, 'expired-ca.cnf');
      writeFileSync(database, '');
      writeFileSync(serial, '1000\n');
      writeFileSync(configuration, `[ca]\ndefault_ca=synthetic\n[synthetic]\ndatabase=${database}\nserial=${serial}\nnew_certs_dir=${directory}\ncertificate=${authority.cert}\nprivate_key=${authority.key}\ndefault_md=sha256\npolicy=synthetic_policy\n[synthetic_policy]\ncommonName=supplied\n`);
      command('openssl', ['ca', '-batch', '-notext', '-config', configuration, '-in', csr, '-out', cert,
        '-startdate', '200101000000Z', '-enddate', '210101000000Z', '-extfile', extensions]);
    } else {
      command('openssl', ['x509', '-req', '-sha256', '-days', '1', '-in', csr, '-CA', authority.cert,
        '-CAkey', authority.key, '-set_serial', `0x${randomBytes(12).toString('hex')}`, '-extfile', extensions, '-out', cert]);
    }
    return { key: readFileSync(key), cert: readFileSync(cert), keyPath: key, certPath: cert };
  }
  const trusted = ca('trusted-ca');
  const foreign = ca('foreign-ca');
  return { trusted, valid: leaf('valid', trusted, domain), wrongSan: leaf('wrong-san', trusted, 'unexpected.example.test'),
    untrusted: leaf('untrusted', foreign, domain), expired: leaf('expired', trusted, domain, true) };
}

async function availablePort() {
  const server = createNetServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function request(port, path, { tls = true, headers = {}, method = 'GET', body } = {}, ca) {
  return new Promise((resolve, reject) => {
    const outgoing = (tls ? httpsRequest : httpRequest)({ hostname: '127.0.0.1', port, path, method,
      ...(tls ? { servername: domain, ca } : {}), headers: { host: domain, ...headers } }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    outgoing.on('error', reject);
    outgoing.setTimeout(3_000, () => outgoing.destroy(new Error('Synthetic Nginx request timed out')));
    outgoing.end(body);
  });
}

test('actual Nginx enforces deployment transport boundaries', {
  skip: missingRuntime && !required ? 'Nginx is not installed; template assertions still run. Set MOONPASSKEY_REQUIRE_NGINX=1 to require runtime checks.' : false,
  timeout: 60_000,
}, async t => {
  assert.equal(missingRuntime, false, 'Nginx is required but its executable is missing');
  assert.equal(detection.status, 0, `Nginx detection failed: ${detection.stderr}`);
  const directory = mkdtempSync(join(tmpdir(), 'moonpasskey-nginx-'));
  let backend;
  let child;
  let exited;
  t.after(async () => {
    if (child) {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
      await exited;
    }
    if (backend) {
      const closed = new Promise(resolve => backend.close(resolve));
      backend.closeAllConnections();
      await closed;
    }
    rmSync(directory, { recursive: true, force: true });
  });
  const tls = certificates(directory);
  const trustedCa = readFileSync(tls.trusted.cert);
  const httpPort = await availablePort();
  const httpsPort = await availablePort();
  const acmeRoot = join(directory, 'acme');
  mkdirSync(join(acmeRoot, '.well-known/acme-challenge'), { recursive: true });
  writeFileSync(join(acmeRoot, '.well-known/acme-challenge/synthetic-token'), 'synthetic-acme-response');
  const authFile = join(directory, 'htpasswd');
  const password = randomBytes(24).toString('hex');
  const username = 'synthetic-runtime-test';
  const hash = command('openssl', ['passwd', '-apr1', password]).trim();
  writeFileSync(authFile, `${username}:${hash}\n`, { mode: 0o600 });
  const authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  const observed = [];
  let backendPort;
  async function replaceBackend(credentials) {
    if (backend) {
      const closed = new Promise(resolve => backend.close(resolve));
      backend.closeAllConnections();
      await closed;
    }
    backend = createHttpsServer(credentials, async (incoming, response) => {
      const chunks = [];
      for await (const chunk of incoming) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString('utf8');
      observed.push({ headers: incoming.headers, body, servername: incoming.socket.servername });
      // These minimal stub checks prove that Nginx does not fabricate Origin or
      // CSRF and that Sec-Fetch-Site survives. The reference RP has its own tests.
      const denied = incoming.method === 'POST' && (incoming.headers.origin !== `https://${domain}`
        || incoming.headers['x-csrf-token'] !== 'synthetic-csrf' || incoming.headers['sec-fetch-site'] === 'cross-site');
      response.writeHead(denied ? 403 : 200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
        'Set-Cookie': 'synthetic-session=value; Path=/; HttpOnly; Secure; SameSite=Strict' });
      response.end(JSON.stringify({ headers: incoming.headers, body }));
    });
    await new Promise((resolve, reject) => backend.once('error', reject).listen(backendPort ?? 0, '127.0.0.1', resolve));
    backendPort = backend.address().port;
  }
  await replaceBackend(tls.valid);
  const http = readTemplate('moonpasskey-http.conf').replaceAll('listen 80;', `listen 127.0.0.1:${httpPort};`)
    .replace('    listen [::]:80;\n', '').replace('/var/www/moonpasskey-acme', quote(acmeRoot));
  const https = readTemplate('moonpasskey-https.conf').replace('listen 443 ssl;', `listen 127.0.0.1:${httpsPort} ssl;`)
    .replace('    listen [::]:443 ssl;\n', '')
    .replace(`/etc/letsencrypt/live/${domain}/fullchain.pem`, quote(tls.valid.certPath))
    .replace(`/etc/letsencrypt/live/${domain}/privkey.pem`, quote(tls.valid.keyPath))
    .replace('/etc/nginx/moonpasskey.htpasswd', quote(authFile))
    .replace('/etc/moonpasskey/tls/backend-ca.crt', quote(tls.trusted.cert))
    .replace('https://127.0.0.1:8787', `https://127.0.0.1:${backendPort}`);
  const configuration = join(directory, 'nginx.conf');
  writeFileSync(configuration, `worker_processes 1;\nmaster_process off;\ndaemon off;\npid ${quote(join(directory, 'nginx.pid'))};\nerror_log ${quote(join(directory, 'error.log'))} info;\nevents { worker_connections 64; }\nhttp {\naccess_log off;\nclient_body_temp_path ${quote(join(directory, 'body'))};\nproxy_temp_path ${quote(join(directory, 'proxy'))};\n${http}\n${https}\n}\n`);
  command(nginx, ['-p', directory, '-c', configuration, '-t']);
  child = spawn(nginx, ['-p', directory, '-c', configuration], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
  exited = once(child, 'exit');
  let ready = false;
  for (let attempt = 0; attempt < 80; attempt++) {
    assert.equal(child.exitCode, null, `Nginx exited during startup: ${stderr}`);
    try { ready = (await request(httpPort, '/', { tls: false })).status === 308; }
    catch { /* Listener may not be ready yet. */ }
    if (ready) break;
    await delay(25);
  }
  assert.ok(ready, `Nginx did not become ready: ${stderr}`);
  const get = (path, options = {}) => request(httpsPort, path, options, trustedCa);

  await t.test('HTTP ACME is unauthenticated and other requests redirect to the fixed HTTPS origin', async () => {
    const acme = await request(httpPort, '/.well-known/acme-challenge/synthetic-token', { tls: false });
    assert.equal(acme.status, 200);
    assert.equal(acme.body, 'synthetic-acme-response');
    assert.equal(acme.headers['www-authenticate'], undefined);
    const redirect = await request(httpPort, '/api/session?synthetic=1', { tls: false });
    assert.equal(redirect.status, 308);
    assert.equal(redirect.headers.location, `https://${domain}/api/session?synthetic=1`);
    await assert.rejects(request(httpPort, '/.well-known/acme-challenge/synthetic-token',
      { tls: false, headers: { host: 'unexpected.example.test' } }), /socket hang up|ECONNRESET/);
  });

  await t.test('all HTTPS application paths require valid Basic Auth before reaching the backend', async () => {
    for (const path of ['/', '/api/session', '/api/challenges', '/api/reports', '/assets/synthetic.js', '/health']) {
      const response = await get(path);
      assert.equal(response.status, 401, path);
      assert.match(response.headers['www-authenticate'], /^Basic /);
    }
    assert.equal((await get('/api/session', { headers: { authorization: 'Basic c3ludGhldGljOndyb25n' } })).status, 401);
    assert.equal(observed.length, 0, 'unauthenticated requests never reach the RP');
  });

  await t.test('authenticated requests preserve application headers, body and responses but strip proxy identity', async () => {
    const body = JSON.stringify({ purpose: 'registration', synthetic: true });
    const response = await get('/api/challenges', { method: 'POST', body, headers: { authorization,
      origin: `https://${domain}`, cookie: 'synthetic-session=value', 'x-csrf-token': 'synthetic-csrf',
      'content-type': 'application/json', 'sec-fetch-site': 'same-origin', forwarded: 'host=unexpected.example.test;proto=http',
      'x-forwarded-for': '203.0.113.77', 'x-forwarded-host': 'unexpected.example.test', 'x-forwarded-proto': 'http',
      'x-forwarded-arbitrary': 'must-not-pass', 'x-real-ip': '203.0.113.88' } });
    assert.equal(response.status, 200);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.match(response.headers['set-cookie'][0], /HttpOnly; Secure; SameSite=Strict/);
    const upstream = observed.at(-1);
    assert.equal(upstream.servername, domain);
    assert.equal(upstream.body, body);
    assert.equal(upstream.headers.host, domain);
    assert.equal(upstream.headers.origin, `https://${domain}`);
    assert.equal(upstream.headers.cookie, 'synthetic-session=value');
    assert.equal(upstream.headers['x-csrf-token'], 'synthetic-csrf');
    assert.equal(upstream.headers['sec-fetch-site'], 'same-origin');
    assert.equal(upstream.headers['content-type'], 'application/json');
    assert.equal(upstream.headers.authorization, undefined);
    assert.ok(Object.keys(upstream.headers).every(name => !/^(?:forwarded$|x-forwarded-|x-real-ip$)/i.test(name)));
  });

  await t.test('unexpected Host is rejected and Origin, CSRF and cross-site failures are not repaired', async () => {
    const count = observed.length;
    await assert.rejects(get('/api/session', { headers: { authorization, host: 'unexpected.example.test' } }), /socket hang up|ECONNRESET/);
    assert.equal(observed.length, count);
    const valid = { authorization, origin: `https://${domain}`, 'x-csrf-token': 'synthetic-csrf', 'sec-fetch-site': 'same-origin' };
    for (const headers of [{ ...valid, origin: 'https://unexpected.example.test' }, { ...valid, origin: '' },
      { ...valid, 'x-csrf-token': '' }, { ...valid, 'sec-fetch-site': 'cross-site' }]) {
      assert.equal((await get('/api/challenges', { method: 'POST', headers, body: '{}' })).status, 403);
    }
  });

  for (const name of ['wrongSan', 'untrusted', 'expired']) {
    await t.test(`upstream ${name} certificate fails closed with 502`, async () => {
      await replaceBackend(tls[name]);
      const count = observed.length;
      assert.equal((await get('/api/session', { headers: { authorization } })).status, 502);
      assert.equal(observed.length, count, 'unverified upstream receives no HTTP request');
      assert.equal((await get('/api/session')).status, 401, 'Basic Auth remains required during upstream TLS failure');
    });
  }
});
