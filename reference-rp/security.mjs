import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export class RpError extends Error {
  constructor(kind, status = 400) {
    super(kind);
    this.name = 'RpError';
    this.kind = kind;
    this.status = status;
  }
}

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function digest(value) {
  return createHash('sha256').update(value).digest();
}

export function sameBytes(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Transport validation only. WebAuthn parsing and all ceremony verification
// remain in the MoonBit Core bridge.
export function transportBytes(value, maximum = 1_048_576) {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum * 4 / 3)
      || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new RpError('InvalidTransportEncoding');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maximum || bytes.toString('base64url') !== value) {
    throw new RpError('InvalidTransportEncoding');
  }
  return bytes;
}
