import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

const b64 = bytes => Buffer.from(bytes).toString('base64url');
const sha = bytes => createHash('sha256').update(bytes).digest();

// Test-only binary construction. Every generated value is parsed and verified
// by the actual compiled MoonBit Core during integration tests.
export function ephemeralAuthenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = Buffer.concat([Buffer.from('a5010203262001215820', 'hex'),
    Buffer.from(jwk.x, 'base64url'), Buffer.from('225820', 'hex'), Buffer.from(jwk.y, 'base64url')]);
  const id = randomBytes(32);
  function authData(rpId, count, { registration = false, uv = true, be = true, bs = false } = {}) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(count);
    const flag = 1 | (uv ? 4 : 0) | (be ? 8 : 0) | (bs ? 16 : 0) | (registration ? 64 : 0);
    const base = Buffer.concat([sha(Buffer.from(rpId)), Buffer.from([flag]), counter]);
    if (!registration) return base;
    const length = Buffer.alloc(2);
    length.writeUInt16BE(id.length);
    return Buffer.concat([base, Buffer.alloc(16), length, id, cose]);
  }
  function client(type, challenge, origin) {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }
  return {
    credentialId: b64(id), publicKey: b64(cose),
    register(issued, config, count = 1, flags = {}) {
      const auth = authData(config.rpId, count, { ...flags, registration: true });
      assertShort(auth.length);
      const outer = Buffer.concat([Buffer.from('a363666d74646e6f6e656761747453746d74a068617574684461746158', 'hex'), Buffer.from([auth.length]), auth]);
      return { ...issued, type: 'public-key', rawId: b64(id),
        clientDataJSON: b64(client('webauthn.create', issued.challenge, config.origin)), attestationObject: b64(outer) };
    },
    assertion(issued, config, count = 2, flags = {}) {
      const auth = authData(config.rpId, count, flags);
      const json = client('webauthn.get', issued.challenge, config.origin);
      const signature = sign('sha256', Buffer.concat([auth, sha(json)]), privateKey);
      return { ...issued, type: 'public-key', rawId: b64(id), clientDataJSON: b64(json),
        authenticatorData: b64(auth), signature: b64(signature), userHandle: null };
    },
  };
}

function assertShort(length) {
  if (length < 24 || length > 255) throw new Error('Test fixture requires one-byte CBOR length.');
}
