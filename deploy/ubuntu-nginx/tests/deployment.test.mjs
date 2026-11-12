import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const read = path => readFileSync(new URL(path, root), 'utf8');
const domain = 'passkey-test.ksuser.cn';

// Parse the template's directive tree so checks apply to the effective scope,
// rather than succeeding because a security directive appears in a comment.
function nginxTree(text) {
  const tokens = text.match(/#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};"']+/g)
    .filter(token => !token.startsWith('#'));
  let index = 0;
  function scope(nested = false) {
    const nodes = [];
    while (index < tokens.length) {
      if (tokens[index] === '}') {
        assert.ok(nested, 'unexpected closing brace');
        index++;
        return nodes;
      }
      const words = [];
      while (index < tokens.length && ![';', '{', '}'].includes(tokens[index])) {
        const token = tokens[index++];
        words.push(/^['"]/.test(token) ? token.slice(1, -1) : token);
      }
      assert.ok(words.length, 'directive must have a name');
      const end = tokens[index++];
      assert.ok([';', '{'].includes(end), 'directive must end with ; or {');
      nodes.push({ name: words[0], args: words.slice(1), ...(end === '{' ? { children: scope(true) } : {}) });
    }
    assert.equal(nested, false, 'unclosed block');
    return nodes;
  }
  return scope();
}
const directive = (nodes, name) => nodes.filter(node => node.name === name);
const args = (nodes, name) => directive(nodes, name).map(node => node.args.join(' '));
const only = (nodes, name) => {
  const matches = directive(nodes, name);
  assert.equal(matches.length, 1, `exactly one ${name}`);
  return matches[0];
};
const server = source => {
  const nodes = nginxTree(source);
  assert.deepEqual(nodes.map(node => node.name), ['server'], 'installable site fragment only');
  return nodes[0].children;
};
const http = server(read('nginx/moonpasskey-http.conf'));
const https = server(read('nginx/moonpasskey-https.conf'));
const proxy = only(https, 'location').children;

function checkHostGuard(nodes) {
  assert.deepEqual(args(nodes, 'server_name'), [domain]);
  const guard = only(nodes, 'if');
  assert.equal(guard.args.join(' ').replaceAll(' ', ''), `($http_host!=${domain})`);
  assert.deepEqual(args(guard.children, 'return'), ['444']);
}

test('HTTP bootstrap exposes only ACME files and a fixed-domain HTTPS redirect', () => {
  checkHostGuard(http);
  assert.deepEqual(args(http, 'listen'), ['80', '[::]:80']);
  const locations = directive(http, 'location');
  assert.equal(locations.length, 2);
  const acme = locations.find(node => node.args.join(' ') === '^~ /.well-known/acme-challenge/');
  assert.ok(acme);
  assert.deepEqual(args(acme.children, 'auth_basic'), ['off']);
  assert.deepEqual(args(acme.children, 'root'), ['/var/www/moonpasskey-acme']);
  assert.deepEqual(args(acme.children, 'try_files'), ['$uri =404']);
  const application = locations.find(node => node.args.join(' ') === '/');
  assert.deepEqual(application.children, [{ name: 'return', args: ['308', `https://${domain}$request_uri`] }]);
  assert.equal(directive(http, 'ssl_certificate').length, 0, 'HTTP starts before certificate issuance');
});

test('HTTPS requires Basic Auth for every application path without a health or static bypass', () => {
  checkHostGuard(https);
  assert.deepEqual(args(https, 'listen'), ['443 ssl', '[::]:443 ssl']);
  assert.deepEqual(args(https, 'auth_basic'), ['MoonPasskey Lab TEST ONLY']);
  assert.deepEqual(args(https, 'satisfy'), ['all']);
  assert.deepEqual(args(https, 'auth_basic_user_file'), ['/etc/nginx/moonpasskey.htpasswd']);
  assert.deepEqual(directive(https, 'location').map(node => node.args.join(' ')), ['/']);
  assert.equal(directive(proxy, 'auth_basic').length, 0, 'application inherits server authentication');
  assert.equal(directive(proxy, 'satisfy').length, 0, 'no alternative auth bypass');
  assert.equal(directive(proxy, 'return').length, 0, 'content is reached through the access phase');
  assert.deepEqual(args(https, 'ssl_certificate'), [`/etc/letsencrypt/live/${domain}/fullchain.pem`]);
  assert.deepEqual(args(https, 'ssl_certificate_key'), [`/etc/letsencrypt/live/${domain}/privkey.pem`]);
  assert.deepEqual(args(https, 'ssl_protocols'), ['TLSv1.2 TLSv1.3']);
  assert.deepEqual(args(https, 'client_max_body_size'), ['2m']);
});

test('Nginx verifies the HTTPS loopback upstream using its exact SAN name and isolated CA', () => {
  assert.deepEqual(args(proxy, 'proxy_pass'), ['https://127.0.0.1:8787']);
  assert.deepEqual(args(proxy, 'proxy_ssl_verify'), ['on']);
  assert.deepEqual(args(proxy, 'proxy_ssl_verify_depth'), ['1']);
  assert.deepEqual(args(proxy, 'proxy_ssl_server_name'), ['on']);
  assert.deepEqual(args(proxy, 'proxy_ssl_name'), [domain]);
  assert.deepEqual(args(proxy, 'proxy_ssl_trusted_certificate'), ['/etc/moonpasskey/tls/backend-ca.crt']);
  assert.deepEqual(args(proxy, 'proxy_ssl_protocols'), ['TLSv1.2 TLSv1.3']);
  assert.deepEqual(args(proxy, 'proxy_intercept_errors'), ['off']);
  assert.deepEqual(args(proxy, 'proxy_redirect'), ['off']);
});

test('the proxy preserves Origin, cookies and CSRF but strips credentials and untrusted proxy metadata', () => {
  assert.deepEqual(args(proxy, 'proxy_pass_request_headers'), ['off']);
  const headers = Object.fromEntries(directive(proxy, 'proxy_set_header').map(node => node.args));
  assert.equal(Object.keys(headers).length, directive(proxy, 'proxy_set_header').length, 'no header overrides');
  assert.equal(headers.Host, domain);
  assert.equal(headers.Authorization, '');
  assert.equal(headers.Origin, '$http_origin');
  assert.equal(headers.Cookie, '$http_cookie');
  assert.equal(headers['X-CSRF-Token'], '$http_x_csrf_token');
  assert.equal(headers['Sec-Fetch-Site'], '$http_sec_fetch_site');
  assert.equal(headers['Content-Type'], '$http_content_type');
  assert.ok(Object.keys(headers).every(name => !/^(?:forwarded$|x-forwarded-|x-real-ip$)/i.test(name)));
  assert.deepEqual(Object.keys(headers).sort(), ['Accept', 'Accept-Language', 'Authorization', 'Connection', 'Content-Type',
    'Cookie', 'Host', 'Origin', 'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'User-Agent', 'X-CSRF-Token'].sort());
});

function ini(text) {
  let section;
  const result = {};
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('[')) { section = line.slice(1, -1); result[section] = {}; }
    else {
      const index = line.indexOf('=');
      assert.ok(section && index > 0, 'valid systemd assignment');
      const key = line.slice(0, index);
      assert.equal(Object.hasOwn(result[section], key), false, `duplicate ${key}`);
      result[section][key] = line.slice(index + 1);
    }
  }
  return result;
}

test('systemd runs the pinned Node binary as an unprivileged account with persistent-data-only writes', () => {
  const unit = ini(read('systemd/moonpasskey-rp.service'));
  const service = unit.Service;
  assert.equal(service.User, 'moonpasskey');
  assert.equal(service.Group, 'moonpasskey');
  assert.equal(service.WorkingDirectory, '/opt/moonpasskey/current');
  assert.equal(service.ExecStart, '/opt/node-v24.18.0/bin/node /opt/moonpasskey/current/reference-rp/start.mjs');
  assert.equal(service.EnvironmentFile, '/etc/moonpasskey/reference-rp.env');
  assert.equal(service.UMask, '0077');
  assert.equal(service.Restart, 'on-failure');
  for (const name of ['NoNewPrivileges', 'PrivateTmp', 'ProtectHome']) assert.equal(service[name], 'true');
  assert.equal(service.ProtectSystem, 'strict');
  assert.equal(service.ReadWritePaths, '/var/lib/moonpasskey');
  assert.deepEqual(service.InaccessiblePaths.split(' ').sort(),
    ['/etc/moonpasskey/tls/ca', '/etc/letsencrypt', '/etc/nginx/moonpasskey.htpasswd'].sort());
  assert.equal(service.StandardOutput, 'journal');
  assert.equal(service.StandardError, 'journal');
  assert.equal(unit.Install.WantedBy, 'multi-user.target');
});

test('the root-controlled EnvironmentFile pins RP security policy, leaf TLS and persistent SQLite', () => {
  const entries = read('config/reference-rp.env.example').split('\n').filter(line => line && !line.startsWith('#'));
  const values = {};
  for (const line of entries) {
    assert.match(line, /^[A-Z_]+=\S+$/, 'systemd assignment without export, shell expansion, quotes or spaces');
    const [name, value] = line.split('=');
    assert.equal(Object.hasOwn(values, name), false, `duplicate ${name}`);
    assert.doesNotMatch(value, /[$`<>]/);
    values[name] = value;
  }
  assert.deepEqual(values, {
    REFERENCE_RP_PORT: '8787', REFERENCE_RP_ORIGIN: `https://${domain}`, REFERENCE_RP_ID: domain,
    REFERENCE_RP_UV: 'required', REFERENCE_RP_COUNTER: 'report-only',
    REFERENCE_RP_CORE: '/opt/moonpasskey/current/_build/js/release/build/analysis/analysis.js',
    REFERENCE_RP_DB: '/var/lib/moonpasskey/reference-rp.sqlite',
    REFERENCE_RP_TLS_CERT: '/etc/moonpasskey/tls/backend/backend.crt',
    REFERENCE_RP_TLS_KEY: '/etc/moonpasskey/tls/backend/backend.key',
    REFERENCE_RP_TLS_CA: '/etc/moonpasskey/tls/backend-ca.crt',
  });
  assert.doesNotMatch(values.REFERENCE_RP_TLS_CA, /\/ca\//, 'only public CA material enters preflight configuration');
});
