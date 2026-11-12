import assert from "node:assert/strict";
import test from "node:test";
import {
  creationOptions,
  fromBase64Url,
  requestOptions,
  safeReportExport,
  toBase64Url,
} from "../src/transport.ts";

test("browser transport preserves original zero and high bytes without padding", () => {
  const original = Uint8Array.from([0, 1, 127, 128, 254, 255]);
  const encoded = toBase64Url(original.buffer);
  assert.equal(encoded, "AAF_gP7_");
  assert.deepEqual(new Uint8Array(fromBase64Url(encoded)), original);
  assert.equal(toBase64Url(new ArrayBuffer(0)), "");
});

test("creation options decode only transport byte fields", () => {
  const input = {
    challenge: "AAH_",
    rp: { id: "localhost", name: "Test" },
    user: { id: "gP8", name: "temporary", displayName: "Temporary test" },
    pubKeyCredParams: [{ type: "public-key" as const, alg: -7 }],
    excludeCredentials: [{ type: "public-key" as const, id: "AP8" }],
    attestation: "none" as const,
  };
  const decoded = creationOptions(input);
  assert.deepEqual(
    new Uint8Array(decoded.challenge as ArrayBuffer),
    Uint8Array.from([0, 1, 255]),
  );
  assert.deepEqual(
    new Uint8Array(decoded.user.id as ArrayBuffer),
    Uint8Array.from([128, 255]),
  );
  assert.deepEqual(
    new Uint8Array(decoded.excludeCredentials![0].id as ArrayBuffer),
    Uint8Array.from([0, 255]),
  );
  assert.equal(input.challenge, "AAH_");
  assert.equal(input.user.id, "gP8");
  assert.equal(decoded.attestation, "none");
});

test("request options retain the trusted RP and UV settings", () => {
  const decoded = requestOptions({
    challenge: "AQ",
    rpId: "localhost",
    userVerification: "required",
    allowCredentials: [
      { type: "public-key", id: "AAI", transports: ["internal"] },
    ],
  });
  assert.deepEqual(
    new Uint8Array(decoded.challenge as ArrayBuffer),
    Uint8Array.from([1]),
  );
  assert.deepEqual(
    new Uint8Array(decoded.allowCredentials![0].id as ArrayBuffer),
    Uint8Array.from([0, 2]),
  );
  assert.equal(decoded.rpId, "localhost");
  assert.equal(decoded.userVerification, "required");
  assert.deepEqual(decoded.allowCredentials![0].transports, ["internal"]);
});

test("safe export excludes raw authentication material and unknown nested fields", () => {
  const entry = {
    id: "private report identifier",
    source: "assertion" as const,
    createdAt: "2026-11-12T00:00:00.000Z",
    credentialId: "secret credential",
    userHandle: "secret account",
    report: {
      status: "PASS" as const,
      algorithm: "ES256",
      credentialId: "secret credential",
      signature: "secret signature",
      publicKey: "secret coordinates",
      clientData: {
        type: "webauthn.get",
        challenge: {
          redacted: false,
          encodedLength: 43,
          raw: "secret challenge",
        },
        origin: "http://localhost:8080",
        crossOrigin: false,
        topOrigin: null,
      },
      authenticatorData: {
        rpIdHash: "omitted hash",
        length: 37,
        signCount: 1,
        raw: "secret authenticator bytes",
        flags: {
          up: true,
          uv: true,
          be: true,
          bs: false,
          at: false,
          ed: false,
          rfu: 0,
          userHandle: "secret nested handle",
        },
      },
      crypto: {
        format: "DER",
        signatureValid: true,
        signature: "secret signature",
      },
      counter: {
        status: "ADVANCED" as const,
        stored: 0,
        received: 1,
        credentialId: "secret counter identifier",
      },
    },
  };
  const exported = safeReportExport(entry, {
    device: "Test device",
    operatingSystem: "Test OS",
    browser: "Test browser",
    provider: "Test provider",
  });
  const json = JSON.stringify(exported);
  assert.equal(json.includes("secret"), false);
  assert.equal(json.includes("omitted hash"), false);
  assert.equal(json.includes("private report identifier"), false);
  assert.equal(exported.clientData?.challenge.redacted, true);
  assert.equal(exported.crypto?.signatureValid, true);
  assert.equal(exported.counter?.received, 1);
});

test("failed and partial Core reports export without inventing verification results", () => {
  const exported = safeReportExport(
    {
      id: "failure",
      source: "import",
      createdAt: "2026-11-12T00:00:00.000Z",
      report: {
        status: "FAIL",
        checks: { json: "PASS", signature: "NOT_PERFORMED" },
        error: { kind: "Parse", context: "authData", offset: 12 },
      },
    },
    { device: "", operatingSystem: "", browser: "", provider: "" },
  );
  assert.equal(exported.status, "FAIL");
  assert.equal(exported.checks?.signature, "NOT_PERFORMED");
  assert.equal(exported.crypto, undefined);
  assert.deepEqual(exported.error, {
    kind: "Parse",
    context: "authData",
    offset: 12,
  });
});
