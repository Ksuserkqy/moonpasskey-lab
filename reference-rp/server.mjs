import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, extname, sep } from 'node:path';
import { RpStore } from './store.mjs';
import { CeremonyCoordinator, publicCredential } from './coordinator.mjs';
import { RpError } from './security.mjs';

export const MAX_BODY_BYTES = 2_097_152;
const COOKIE = 'moonpasskey_session';
const DASHBOARD = fileURLToPath(new URL('../dashboard/dist/', import.meta.url));

function json(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(body));
}

async function body(request) {
  if (!request.headers['content-type']?.startsWith('application/json')) throw new RpError('JsonContentTypeRequired', 415);
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new RpError('BodyTooLarge', 413);
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch { throw new RpError('InvalidJsonBody'); }
}

function cookieToken(request) {
  return (request.headers.cookie ?? '').split(';').map(value => value.trim())
    .find(value => value.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
}

export function createReferenceRp({ store, core, rpId = 'localhost', origin = 'http://localhost:8787',
  host = '127.0.0.1', port = 8787, tls, dashboard = DASHBOARD,
  userVerification = 'preferred', counterPolicy = 'report-only', challengeTtlMs = 300_000,
  coordinatorOptions } = {}) {
  const configured = new URL(origin);
  if (!['http:', 'https:'].includes(configured.protocol) || configured.origin !== origin
      || configured.username || configured.password) throw new Error('Origin must be an exact HTTP(S) origin.');
  if (host !== '127.0.0.1' && host !== '::1') throw new Error('Reference RP must bind to a loopback address. Use a protected local HTTPS tunnel for another device.');
  if (configured.protocol === 'https:' && !tls) throw new Error('HTTPS requires a certificate and key.');
  if (tls && configured.protocol !== 'https:') throw new Error('A TLS server requires an HTTPS origin.');
  if (configured.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(configured.hostname)) {
    throw new Error('HTTP is supported only for a loopback origin.');
  }
  if (!['required', 'preferred', 'discouraged'].includes(userVerification)
      || !['report-only', 'reject'].includes(counterPolicy)) throw new Error('Invalid server policy.');
  if (!store || !core) throw new Error('A store and MoonBit Core bridge are required.');
  const config = { rpId, origin, userVerification, counterPolicy };
  const coordinator = new CeremonyCoordinator(store, core, config, coordinatorOptions);
  const handler = async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      const allowed = new URL(config.origin);
      if (request.headers.host !== allowed.host) throw new RpError('HostMismatch', 403);
      if (request.headers.origin && request.headers.origin !== config.origin) throw new RpError('OriginMismatch', 403);
      if (request.headers['sec-fetch-site'] === 'cross-site') throw new RpError('CrossSiteRequest', 403);
      const url = new URL(request.url, config.origin);
      if (url.pathname === '/api/session' && request.method === 'GET') {
        let session = store.session(cookieToken(request));
        let csrfToken;
        if (!session) {
          const created = store.createSession();
          response.setHeader('Set-Cookie', `${COOKIE}=${created.token}; Path=/; HttpOnly; SameSite=Strict${allowed.protocol === 'https:' ? '; Secure' : ''}`);
          session = store.session(created.token);
          csrfToken = created.csrfToken;
        } else csrfToken = store.rotateCsrf(session);
        json(response, 200, { csrfToken, config,
          user: { id: session.userId, name: 'local-test-account', displayName: 'Local test account', userHandle: session.userHandle },
          developmentOnly: true });
        return;
      }
      if (url.pathname.startsWith('/api/')) {
        const session = store.session(cookieToken(request));
        if (!session) throw new RpError('SessionRequired', 401);
        if (request.method === 'POST') {
          if (request.headers.origin !== config.origin) throw new RpError('OriginRequired', 403);
          store.checkCsrf(session, request.headers['x-csrf-token']);
        }
        if (url.pathname === '/api/state' && request.method === 'GET') {
          json(response, 200, { credentials: store.credentials(session.userId).map(publicCredential), developmentOnly: true });
        } else if (url.pathname === '/api/reports' && request.method === 'GET') {
          json(response, 200, { reports: store.reports(session.userId), developmentOnly: true });
        } else if (url.pathname === '/api/challenges' && request.method === 'POST') {
          const input = await body(request);
          const credentials = store.credentials(session.userId);
          if (input.purpose === 'assertion' && credentials.length === 0) throw new RpError('CredentialNotFound', 404);
          const issued = store.issueChallenge(session, { ...config, purpose: input.purpose, ttlMs: challengeTtlMs });
          const publicKey = input.purpose === 'registration' ? {
            challenge: issued.challenge, rp: { id: config.rpId, name: 'MoonPasskey Lab TEST ONLY' },
            user: { id: session.userHandle, name: 'local-test-account', displayName: 'Local test account' },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'none',
            authenticatorSelection: { userVerification }, timeout: challengeTtlMs,
            excludeCredentials: credentials.map(value => ({ type: 'public-key', id: value.credentialId })),
          } : {
            challenge: issued.challenge, rpId: config.rpId, userVerification, timeout: challengeTtlMs,
            allowCredentials: credentials.map(value => ({ type: 'public-key', id: value.credentialId })),
          };
          json(response, 200, { ...issued, publicKey, developmentOnly: true });
        } else if (url.pathname === '/api/register' && request.method === 'POST') {
          const result = await coordinator.register(session, await body(request));
          json(response, result.status === 'PASS' ? 200 : 400, result);
        } else if (url.pathname === '/api/assertions' && request.method === 'POST') {
          const result = await coordinator.assert(session, await body(request));
          json(response, result.status === 'PASS' ? 200 : 400, result);
        } else if (url.pathname === '/api/analyze' && request.method === 'POST') {
          json(response, 200, await core.analyze(await body(request)));
        } else throw new RpError('EndpointNotFound', 404);
        return;
      }
      if (request.method !== 'GET') throw new RpError('MethodNotAllowed', 405);
      const relative = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
      const path = resolve(dashboard, `.${relative}`);
      if (!path.startsWith(resolve(dashboard) + sep)) throw new RpError('AssetNotFound', 404);
      const content = await readFile(path).catch(() => { throw new RpError('DashboardNotBuilt', 404); });
      const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };
      response.writeHead(200, { 'Content-Type': types[extname(path)] ?? 'application/octet-stream' });
      response.end(content);
    } catch (error) {
      const safe = error instanceof RpError ? error : new RpError('InternalError', 500);
      if (!response.headersSent) json(response, safe.status, { status: 'FAIL', error: { kind: safe.kind } });
      else response.end();
    }
  };
  const server = tls ? httpsServer(tls, handler) : httpServer(handler);
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.maxHeadersCount = 100;
  return {
    server, store, config, coordinator,
    async listen() {
      await new Promise((resolveListen, reject) => {
        server.once('error', reject);
        server.listen(port, host, resolveListen);
      });
      if (configured.port === '0') {
        config.origin = `${configured.protocol}//${configured.hostname}:${server.address().port}`;
      }
      return config.origin;
    },
    async close() { await new Promise(resolveClose => server.close(resolveClose)); },
  };
}

export function openReferenceStore(path) { return new RpStore(path); }
