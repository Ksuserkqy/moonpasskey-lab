import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import schema from "../../docs/interop/report.schema.json" with { type: "json" };
import {
  normalizeLegacyReport,
  validateInteropReport,
} from "../src/interop-report.ts";
import {
  captureLocalReport,
  safeReportExport,
  type DeviceMetadata,
  type LocalReport,
  type Session,
} from "../src/transport.ts";

const device: DeviceMetadata = {
  device: "Synthetic test device",
  operatingSystem: "Synthetic OS 1",
  browser: "Synthetic browser 1",
  provider: "Unknown",
  providerSource: "UNKNOWN",
};
const config: Session["config"] = {
  rpId: "localhost",
  origin: "http://localhost:8787",
  userVerification: "required",
  counterPolicy: "report-only",
};

function entry(): LocalReport {
  return {
    id: "private-local-report-id",
    source: "assertion",
    createdAt: "2026-11-12T05:02:59.977Z",
    configuration: { ...config },
    databaseTransaction: { status: "COMMITTED", previousVersion: 2, version: 3 },
    report: {
      status: "PASS",
      algorithm: "ES256",
      checks: { challenge: "PASS", user_verification: "PASS", signature: "PASS" },
      clientData: {
        type: "webauthn.get",
        challenge: { redacted: true, encodedLength: 43 },
        origin: config.origin,
        crossOrigin: false,
        topOrigin: null,
      },
      authenticatorData: {
        rpIdHash: "private-rp-id-hash",
        length: 37,
        flags: { up: true, uv: true, be: true, bs: false, at: false, ed: false, rfu: 0 },
        signCount: 0,
      },
      crypto: { format: "DER", signatureValid: true },
      counter: { status: "NOT_SUPPORTED", stored: 0, received: 0 },
    },
  };
}

function validReport() {
  return safeReportExport(entry(), device);
}

test("schema v1 exports preserve Core results and explicit transaction evidence", () => {
  const report = validReport();
  assert.deepEqual(validateInteropReport(report), []);
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.outcome, "PASS");
  assert.equal(report.status, "PASS");
  assert.equal(report.configuration?.userVerification, "required");
  assert.equal(report.authenticatorData?.flags.uv, true);
  assert.deepEqual(report.databaseTransaction, { status: "COMMITTED", previousVersion: 2, version: 3 });
  assert.equal(JSON.stringify(report).includes("private-"), false);
});

test("capture snapshots configuration, Core results and transaction versions", () => {
  const configuration = { ...config };
  const envelope = {
    status: "PASS" as const,
    reportId: "local-report",
    report: entry().report,
    databaseTransaction: { status: "COMMITTED" as const, previousVersion: 2, version: 3 },
  };
  const captured = captureLocalReport(envelope, "assertion", configuration);
  configuration.userVerification = "discouraged";
  envelope.report.authenticatorData!.flags.uv = false;
  envelope.databaseTransaction.version = 99;
  const exported = safeReportExport(captured, device, configuration);
  assert.equal(exported.configuration?.userVerification, "required");
  assert.equal(exported.authenticatorData?.flags.uv, true);
  assert.deepEqual(exported.databaseTransaction, { status: "COMMITTED", previousVersion: 2, version: 3 });
});

test("imports retain their Core evidence without borrowing the live RP configuration or transaction", () => {
  const envelope = {
    status: "PASS" as const,
    report: entry().report,
    databaseTransaction: { status: "COMMITTED" as const, previousVersion: 2, version: 3 },
  };
  const exported = safeReportExport(
    captureLocalReport(envelope, "import", config),
    device,
    config,
  );
  assert.equal(exported.source, "import");
  assert.equal(exported.status, "PASS");
  assert.equal(exported.configuration, null);
  assert.deepEqual(exported.databaseTransaction, { status: "NOT_PERFORMED" });
});

test("Core PASS and a report ID alone do not establish database commit evidence", () => {
  const captured = captureLocalReport(
    { status: "PASS", report: entry().report, reportId: "opaque-id" },
    "assertion",
    config,
  );
  assert.deepEqual(safeReportExport(captured, device).databaseTransaction, { status: "NOT_OBSERVED" });
  const failed = captureLocalReport({ status: "FAIL", report: { status: "FAIL" } }, "assertion", config);
  const exported = safeReportExport(failed, device);
  assert.equal(exported.outcome, "FAILED");
  assert.deepEqual(exported.databaseTransaction, { status: "NOT_OBSERVED" });
});

test("report exports require complete environment metadata and an explicit provider source", () => {
  for (const key of ["device", "operatingSystem", "browser", "provider", "providerSource"]) {
    const incomplete = { ...device, [key]: "" };
    assert.throws(() => safeReportExport(entry(), incomplete as DeviceMetadata), /validation failed/);
    const report = validReport() as unknown as Record<string, any>;
    delete report.device[key];
    assert.ok(validateInteropReport(report).length, key);
  }
  assert.throws(() => safeReportExport(entry(), { ...device, browser: "   " }), /invalid format/);
  const withoutPolicy = entry();
  delete withoutPolicy.configuration;
  assert.throws(() => safeReportExport(withoutPolicy, device), /configuration is required/);
});

test("report timestamps reject invalid calendar dates and missing UTC precision", () => {
  for (const capturedAt of [
    "", "2026-02-30T00:00:00.000Z", "2026-11-12",
    "2026-11-12T00:00:00", "2026-11-12T00:00:00Z",
  ]) {
    const report = { ...validReport(), capturedAt };
    assert.ok(validateInteropReport(report).length, capturedAt);
  }
});

test("provider attribution remains explicit and never derives from browser or OS names", () => {
  const report = safeReportExport(entry(), {
    ...device,
    browser: "Safari 27.2",
    operatingSystem: "macOS 27.2.1",
    provider: "iCloud Keychain",
  });
  assert.equal(report.device.providerSource, "UNKNOWN");
  for (const providerSource of ["BROWSER_INFERRED", "", null]) {
    assert.ok(validateInteropReport({ ...report, device: { ...report.device, providerSource } }).length);
  }
});

test("every report object rejects unknown and raw-sensitive fields by allowlist", () => {
  const sensitive = [
    "credentialId", "userHandle", "clientDataJSON", "authenticatorDataBytes",
    "attestationObject", "signature", "publicKey", "x", "y", "privateKey",
    "cookie", "csrfToken", "tlsKey", "raw", "challengeId",
  ];
  const paths = [
    [], ["device"], ["configuration"], ["checks"], ["clientData"],
    ["clientData", "challenge"], ["authenticatorData"],
    ["authenticatorData", "flags"], ["crypto"], ["counter"], ["databaseTransaction"],
  ];
  for (const path of paths) {
    for (const field of sensitive) {
      const report = validReport() as unknown as Record<string, any>;
      let target = report;
      for (const key of path) target = target[key];
      if (Object.hasOwn(target, field)) continue;
      target[field] = "sensitive-value";
      assert.ok(validateInteropReport(report).length, `${path.join(".")}.${field}`);
    }
  }
  const withError = { ...validReport(), error: { kind: "Parse", signature: "private" } };
  assert.ok(validateInteropReport(withError).some(error => error.includes("unapproved field")));
});

test("export filters unknown check names and nested material while preserving allowed results", () => {
  const input = entry() as LocalReport & Record<string, any>;
  input.report.checks = { ...input.report.checks, credentialId: "private-check-credential" } as any;
  Object.assign(input.report.clientData!.challenge, { raw: "private-challenge" });
  Object.assign(input.report.crypto!, { signature: "private-DER-signature" });
  Object.assign(input.databaseTransaction!, { cookie: "private-cookie" });
  const report = safeReportExport(input, device);
  assert.equal(JSON.stringify(report).includes("private-"), false);
  assert.equal(report.checks?.signature, "PASS");
  assert.equal(report.clientData?.challenge.encodedLength, 43);
});

test("statuses, counters, flags and redaction markers have bounded validated types", () => {
  const mutations = [
    (report: any) => { report.status = "SUCCESS"; },
    (report: any) => { report.outcome = "FAIL"; },
    (report: any) => { report.checks.signature = "TRUE"; },
    (report: any) => { report.clientData.challenge.redacted = false; },
    (report: any) => { report.clientData.challenge.encodedLength = -1; },
    (report: any) => { report.authenticatorData.flags.uv = "true"; },
    (report: any) => { report.authenticatorData.signCount = 4294967296; },
    (report: any) => { report.authenticatorData.length = 36; },
    (report: any) => { report.counter.received = 1.5; },
    (report: any) => { report.configuration.userVerification = "optional"; },
  ];
  for (const mutate of mutations) {
    const report = validReport();
    mutate(report);
    assert.ok(validateInteropReport(report).length);
  }
});

test("typed outcomes retain missing evidence and reject contradictory Core success", () => {
  for (const outcome of ["BLOCKED", "NOT_PERFORMED"]) {
    const report = {
      ...validReport(),
      outcome,
      status: null,
      checks: undefined,
      clientData: undefined,
      authenticatorData: undefined,
      crypto: undefined,
      counter: undefined,
      databaseTransaction: { status: "NOT_OBSERVED" },
    };
    const serialized = JSON.parse(JSON.stringify(report));
    assert.deepEqual(validateInteropReport(serialized), []);
    serialized.status = "PASS";
    assert.ok(validateInteropReport(serialized).length);
    serialized.status = null;
    serialized.crypto = { format: "DER", signatureValid: true };
    assert.ok(validateInteropReport(serialized).length);
  }
  assert.ok(validateInteropReport({ ...validReport(), outcome: "FAILED" }).length);
});

test("committed database evidence validates the operation and credential version transition", () => {
  const original = validReport();
  for (const transaction of [
    { status: "COMMITTED", version: 3 },
    { status: "COMMITTED", previousVersion: 2, version: 4 },
    { status: "NOT_OBSERVED", previousVersion: 2, version: 3 },
  ]) assert.ok(validateInteropReport({ ...original, databaseTransaction: transaction }).length);
  assert.deepEqual(validateInteropReport({
    ...original,
    source: "registration",
    databaseTransaction: { status: "COMMITTED", previousVersion: null, version: 0 },
  }), []);
  assert.ok(validateInteropReport({ ...original, source: "registration" }).length);
  assert.ok(validateInteropReport({ ...original, status: "FAIL", outcome: "FAILED" }).length);
  assert.ok(validateInteropReport({ ...original, source: "import" }).length);
});

test("origin metadata accepts only exact HTTP and HTTPS origins without credentials or payloads", () => {
  for (const origin of [
    "https://test.example/path", "https://user:secret@test.example",
    "https://test.example?token=secret", "https://test.example/#secret",
    "file:///tmp/report", "https://test.example/",
  ]) {
    const report = validReport();
    report.configuration!.origin = origin;
    assert.ok(validateInteropReport(report).length, origin);
  }
});

test("typed partial Core failures preserve the existing CBOR trailing-data error location", () => {
  const report = safeReportExport({
    id: "partial",
    source: "import",
    createdAt: "2026-11-12T05:02:59.977Z",
    report: {
      status: "FAIL",
      error: { kind: "Cbor.TrailingData", context: "attestationObject.trailing data", offset: 37 },
    },
  }, device);
  assert.equal(report.outcome, "FAILED");
  assert.equal(report.error?.context, "attestationObject.trailing data");
  assert.equal(report.authenticatorData, undefined);
  assert.equal(report.crypto, undefined);
});

test("bounded Core parser depth-limit paths remain exportable in partial failure reports", () => {
  const context = `clientDataJSON${".member[0].value".repeat(32)}`;
  assert.ok(context.length > 256);
  const exported = safeReportExport({
    id: "depth-limit",
    source: "import",
    createdAt: "2026-11-12T05:02:59.977Z",
    report: {
      status: "FAIL",
      error: { kind: "ResourceLimit", context, offset: 352 },
    },
  }, device);
  assert.equal(exported.error?.context, context);
  assert.equal(exported.outcome, "FAILED");
  assert.deepEqual(exported.databaseTransaction, { status: "NOT_PERFORMED" });
});

test("structural client-data imports preserve Core-parsed type and origin strings", () => {
  const parsed = {
    status: "PASS" as const,
    clientData: {
      type: "custom.operation",
      challenge: { redacted: true, encodedLength: 0 },
      origin: "custom-origin",
      crossOrigin: true,
      topOrigin: "custom-parent-origin",
    },
  };
  const exported = safeReportExport(captureLocalReport(parsed, "import", config), device);
  assert.equal(exported.status, "PASS");
  assert.deepEqual(exported.clientData, parsed.clientData);
  assert.equal(exported.source, "import");
  assert.equal(exported.configuration, null);
  assert.deepEqual(exported.databaseTransaction, { status: "NOT_PERFORMED" });
  assert.equal(exported.crypto, undefined);
});

const legacyPath = new URL("../../docs/interop/safari-macos-2026-11-12.redacted.json", import.meta.url);
const legacyBytes = readFileSync(legacyPath);
const legacy = JSON.parse(legacyBytes.toString("utf8"));
const provenance = JSON.parse(readFileSync(
  new URL("../../docs/interop/safari-macos-2026-11-12.provenance.json", import.meta.url),
  "utf8",
));
const originalDigest = "0f27841c5fcf6d84927a7b53b66a9f6b24aa2fa0feb84f7caa711cd13311c9af";

test("the preserved Safari report is byte-identical and normalizes with separate attribution only", () => {
  assert.equal(createHash("sha256").update(legacyBytes).digest("hex"), originalDigest);
  const before = JSON.stringify(legacy);
  const report = normalizeLegacyReport(legacy, provenance, provenance.sourceFile, originalDigest);
  assert.equal(JSON.stringify(legacy), before);
  assert.equal(report.status, "PASS");
  assert.equal(report.capturedAt, legacy.capturedAt);
  assert.equal(report.device.provider, legacy.device.provider);
  assert.equal(report.device.providerSource, "MAINTAINER_SELECTED");
  assert.deepEqual(report.databaseTransaction, { status: "UNKNOWN" });
  assert.equal(report.provenance?.sourceSha256, originalDigest);
  assert.deepEqual(validateInteropReport(report), []);
});

test("legacy provenance is hash-bound and rejects unknown metadata or unsupported attribution", () => {
  for (const changed of [
    { ...provenance, sourceSha256: "0".repeat(64) },
    { ...provenance, sourceFile: "other.redacted.json" },
    { ...provenance, providerSource: "BROWSER_INFERRED" },
    { ...provenance, providerSource: "INDEPENDENTLY_VERIFIED" },
    { ...provenance, providerSource: "UNKNOWN" },
    { ...provenance, privateKey: "private" },
  ]) assert.throws(
    () => normalizeLegacyReport(legacy, changed, provenance.sourceFile, originalDigest),
    /provenance/i,
  );
});

test("legacy adaptation applies the same nested allowlist before normalization", () => {
  const injected = structuredClone(legacy);
  injected.clientData.challenge.raw = "secret";
  assert.throws(
    () => normalizeLegacyReport(injected, provenance, provenance.sourceFile, originalDigest),
    /unapproved field/,
  );
});

test("the report checker validates preserved evidence and rejects a leaking exported file", () => {
  const checker = new URL("../../scripts/check-interop-reports.mjs", import.meta.url);
  const result = execFileSync(
    process.execPath, ["--experimental-strip-types", checker.pathname],
    { encoding: "utf8" },
  );
  assert.match(result, /PASS safari-macos-2026-11-12.redacted.json/);
  assert.match(result, /transaction evidence UNKNOWN/);
  const temporary = mkdtempSync(join(tmpdir(), "moonpasskey-report-"));
  try {
    const validPath = join(temporary, "valid.redacted.json");
    const punctuation = validReport();
    punctuation.device.provider = 'Test "provider" { [ ] }';
    writeFileSync(validPath, JSON.stringify(punctuation));
    const valid = execFileSync(
      process.execPath, ["--experimental-strip-types", checker.pathname, validPath],
      { encoding: "utf8" },
    );
    assert.match(valid, /PASS valid.redacted.json \(schema v1\)/);
    const path = join(temporary, "leaking.redacted.json");
    writeFileSync(path, JSON.stringify({ ...validReport(), privateKey: "private" }));
    const invalid = spawnSync(
      process.execPath, ["--experimental-strip-types", checker.pathname, path],
      { encoding: "utf8" },
    );
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /unapproved field/);
    assert.equal(invalid.stdout.includes("PASS"), false);
    writeFileSync(path, '{"signature":"secret-signature"');
    const malformed = spawnSync(
      process.execPath, ["--experimental-strip-types", checker.pathname, path],
      { encoding: "utf8" },
    );
    assert.equal(malformed.status, 1);
    assert.match(malformed.stderr, /invalid JSON/);
    assert.equal(malformed.stderr.includes("secret-signature"), false);

    const invalidUtf8 = Buffer.from(JSON.stringify(validReport()));
    invalidUtf8[invalidUtf8.indexOf("Synthetic test device")] = 0xff;
    writeFileSync(path, invalidUtf8);
    const encoding = spawnSync(
      process.execPath, ["--experimental-strip-types", checker.pathname, path],
      { encoding: "utf8" },
    );
    assert.equal(encoding.status, 1);
    assert.match(encoding.stderr, /valid UTF-8/);

    const serialized = JSON.stringify(validReport());
    const duplicates = [
      `{"device":{"userHandle":"secret-handle"},${serialized.slice(1)}`,
      serialized.replace('"providerSource":"UNKNOWN"', '"providerSource":"UNKNOWN","provider\\u0053ource":"UNKNOWN"'),
      serialized.replace('"redacted":true', '"raw":"secret-challenge","redacted":false,"redacted":true'),
    ];
    for (const duplicate of duplicates) {
      writeFileSync(path, duplicate);
      const result = spawnSync(
        process.execPath, ["--experimental-strip-types", checker.pathname, path],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 1);
      assert.match(result.stderr, /duplicate JSON object keys/);
      assert.equal(result.stderr.includes("secret-"), false);
      assert.equal(result.stdout.includes("PASS"), false);
    }

    const historicalPath = join(temporary, provenance.sourceFile);
    const sidecarPath = historicalPath.replace(".redacted.json", ".provenance.json");
    writeFileSync(historicalPath, legacyBytes);
    const invalidSidecar = Buffer.from(JSON.stringify(provenance));
    invalidSidecar[invalidSidecar.indexOf("ORIGINAL_PROVIDER_LABEL")] = 0xff;
    writeFileSync(sidecarPath, invalidSidecar);
    const sidecarEncoding = spawnSync(
      process.execPath, ["--experimental-strip-types", checker.pathname, historicalPath],
      { encoding: "utf8" },
    );
    assert.equal(sidecarEncoding.status, 1);
    assert.match(sidecarEncoding.stderr, /valid UTF-8/);

    writeFileSync(sidecarPath, Buffer.alloc(2_097_153, 32));
    const sidecarSize = spawnSync(
      process.execPath, ["--experimental-strip-types", checker.pathname, historicalPath],
      { encoding: "utf8" },
    );
    assert.equal(sidecarSize.status, 1);
    assert.match(sidecarSize.stderr, /two-MiB input limit/);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("every bundled object schema explicitly closes its property allowlist", () => {
  function inspect(rule: any): void {
    if (rule.properties) {
      assert.equal(rule.additionalProperties, false);
      for (const child of Object.values(rule.properties)) inspect(child);
    }
  }
  inspect(schema);
});
