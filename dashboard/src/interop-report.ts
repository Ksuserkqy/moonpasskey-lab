import schema from "../../docs/interop/report.schema.json" with { type: "json" };
import type {
  CoreReport,
  DeviceMetadata,
  LocalReport,
  Session,
} from "./transport.ts";

export type InteropOutcome = "PASS" | "FAILED" | "BLOCKED" | "NOT_PERFORMED";
export type ProviderSource =
  | "MAINTAINER_SELECTED"
  | "INDEPENDENTLY_VERIFIED"
  | "UNKNOWN";

export type DatabaseTransaction =
  | { status: "COMMITTED"; previousVersion: number | null; version: number }
  | { status: "NOT_PERFORMED" | "NOT_OBSERVED" | "UNKNOWN" };

export interface InteropReport {
  schemaVersion: 1;
  application: "MoonPasskey Lab";
  developmentOnly: true;
  source: LocalReport["source"];
  capturedAt: string;
  device: DeviceMetadata;
  configuration: Session["config"] | null;
  outcome: InteropOutcome;
  status: CoreReport["status"] | null;
  databaseTransaction: DatabaseTransaction;
  algorithm?: string;
  checks?: CoreReport["checks"];
  error?: CoreReport["error"];
  clientData?: CoreReport["clientData"];
  authenticatorData?: Omit<
    NonNullable<CoreReport["authenticatorData"]>,
    "rpIdHash"
  >;
  crypto?: CoreReport["crypto"];
  counter?: CoreReport["counter"];
  provenance?: {
    kind: "LEGACY_NORMALIZATION";
    sourceFile: string;
    sourceSha256: string;
  };
}

interface Schema {
  type?: string | string[];
  const?: unknown;
  enum?: unknown[];
  required?: string[];
  properties?: Record<string, Schema>;
  additionalProperties?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  format?: string;
  minimum?: number;
  maximum?: number;
}

const reportSchema: Schema = schema;
export const CHECK_NAMES = Object.keys(schema.properties.checks.properties);

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function matchesType(value: unknown, type: string): boolean {
  if (type === "null") return value === null;
  if (type === "object") return isObject(value);
  if (type === "integer") return Number.isSafeInteger(value);
  return typeof value === type;
}

function validOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && url.origin === value;
  } catch {
    return false;
  }
}

// This checks the small JSON Schema vocabulary used by our bundled schema.
// Every object in that schema has additionalProperties=false.
function validateSchema(
  value: unknown,
  rule: Schema,
  path: string,
  errors: string[],
): void {
  const types = Array.isArray(rule.type) ? rule.type : [rule.type];
  if (rule.type && !types.some((type) => matchesType(value, type!))) {
    errors.push(`${path} has an invalid type`);
    return;
  }
  if ("const" in rule && value !== rule.const)
    errors.push(`${path} has an invalid value`);
  if (rule.enum && !rule.enum.includes(value))
    errors.push(`${path} has an invalid value`);
  if (typeof value === "string") {
    if (rule.minLength !== undefined && value.length < rule.minLength)
      errors.push(`${path} is too short`);
    if (rule.maxLength !== undefined && value.length > rule.maxLength)
      errors.push(`${path} is too long`);
    if (rule.pattern && !new RegExp(rule.pattern).test(value))
      errors.push(`${path} has an invalid format`);
    if (rule.format === "date-time") {
      const timestamp = Date.parse(value);
      if (
        !Number.isFinite(timestamp) ||
        new Date(timestamp).toISOString() !== value
      )
        errors.push(`${path} must be an ISO UTC timestamp with milliseconds`);
    }
    if (rule.format === "uri" && !validOrigin(value))
      errors.push(`${path} must be an exact HTTP or HTTPS origin`);
  }
  if (typeof value === "number") {
    if (rule.minimum !== undefined && value < rule.minimum)
      errors.push(`${path} is too small`);
    if (rule.maximum !== undefined && value > rule.maximum)
      errors.push(`${path} is too large`);
  }
  if (isObject(value)) {
    for (const key of rule.required ?? []) {
      if (!Object.hasOwn(value, key)) errors.push(`${path}.${key} is required`);
    }
    for (const [key, item] of Object.entries(value)) {
      const child = Object.hasOwn(rule.properties ?? {}, key)
        ? rule.properties![key]
        : undefined;
      if (child) validateSchema(item, child, `${path}.${key}`, errors);
      else if (rule.additionalProperties === false)
        errors.push(`${path} contains an unapproved field`);
    }
  }
}

export function validateInteropReport(value: unknown): string[] {
  const errors: string[] = [];
  validateSchema(value, reportSchema, "report", errors);
  if (errors.length || !isObject(value)) return errors;
  const report = value as unknown as InteropReport;
  if (report.source !== "import" && report.configuration === null)
    errors.push("report.configuration is required for browser ceremonies");
  if (report.outcome === "PASS" && report.status !== "PASS")
    errors.push("report.outcome PASS requires Core status PASS");
  if (report.outcome === "FAILED" && report.status !== "FAIL")
    errors.push("report.outcome FAILED requires Core status FAIL");
  if (["BLOCKED", "NOT_PERFORMED"].includes(report.outcome)) {
    if (report.status !== null)
      errors.push("an unperformed or blocked report cannot claim a Core result");
    if (
      report.clientData || report.authenticatorData || report.crypto || report.counter ||
      Object.values(report.checks ?? {}).some(status => status !== "NOT_PERFORMED")
    )
      errors.push("an unperformed or blocked report cannot claim observed Core evidence");
  }
  const transaction = report.databaseTransaction;
  if (transaction.status === "COMMITTED") {
    if (report.source === "import" || report.outcome !== "PASS")
      errors.push("a committed transaction requires a successful browser ceremony");
    if (
      transaction.version === undefined ||
      transaction.previousVersion === undefined
    )
      errors.push("a committed transaction requires credential versions");
    else if (
      report.source === "registration" &&
      (transaction.previousVersion !== null || transaction.version !== 0)
    )
      errors.push("registration must record the initial credential version");
    else if (
      report.source === "assertion" &&
      (transaction.previousVersion === null ||
        transaction.version !== transaction.previousVersion + 1)
    )
      errors.push(
        "assertion must record the committed credential version increment",
      );
  } else if ("previousVersion" in transaction || "version" in transaction) {
    errors.push("unobserved transactions cannot claim credential versions");
  }
  if (report.source === "import" && transaction.status !== "NOT_PERFORMED")
    errors.push("imported Core analysis does not perform a database transaction");
  return errors;
}

export function assertValidInteropReport(value: unknown): asserts value is InteropReport {
  const errors = validateInteropReport(value);
  if (errors.length)
    throw new Error(`Redacted report validation failed. ${errors.join(". ")}`);
}

interface LegacyProvenance {
  schemaVersion: 1;
  sourceFile: string;
  sourceSha256: string;
  providerSource: ProviderSource;
  providerSourceBasis: "ORIGINAL_PROVIDER_LABEL";
}

const provenanceSchema: Schema = {
  type: "object",
  additionalProperties: false,
  required: [
    "schemaVersion",
    "sourceFile",
    "sourceSha256",
    "providerSource",
    "providerSourceBasis",
  ],
  properties: {
    schemaVersion: { const: 1 },
    sourceFile: { type: "string", pattern: "^[a-z0-9-]+\\.redacted\\.json$" },
    sourceSha256: { type: "string", pattern: "^[a-f0-9]{64}$" },
    providerSource: { enum: ["MAINTAINER_SELECTED", "UNKNOWN"] },
    providerSourceBasis: { const: "ORIGINAL_PROVIDER_LABEL" },
  },
};

// The caller hashes the original file bytes before decoding JSON. Normalization
// adds separately recorded attribution and leaves missing historic evidence unknown.
export function normalizeLegacyReport(
  value: unknown,
  provenance: unknown,
  sourceFile: string,
  sourceSha256: string,
): InteropReport {
  const errors: string[] = [];
  validateSchema(provenance, provenanceSchema, "provenance", errors);
  if (errors.length)
    throw new Error(`Legacy provenance validation failed. ${errors.join(". ")}`);
  const metadata = provenance as LegacyProvenance;
  if (metadata.sourceFile !== sourceFile || metadata.sourceSha256 !== sourceSha256)
    throw new Error("Legacy provenance does not match the original report bytes");
  const legacySchema = structuredClone(reportSchema);
  for (const key of ["schemaVersion", "outcome", "databaseTransaction", "provenance"])
    delete legacySchema.properties![key];
  legacySchema.required = legacySchema.required!.filter(
    (key) => Object.hasOwn(legacySchema.properties!, key),
  );
  const legacyDevice = legacySchema.properties!.device;
  delete legacyDevice.properties!.providerSource;
  legacyDevice.required = legacyDevice.required!.filter((key) => key !== "providerSource");
  validateSchema(value, legacySchema, "legacyReport", errors);
  if (errors.length)
    throw new Error(`Legacy report validation failed. ${errors.join(". ")}`);
  const legacy = structuredClone(value) as Omit<
    InteropReport,
    "schemaVersion" | "outcome" | "databaseTransaction" | "device"
  > & { device: Omit<DeviceMetadata, "providerSource"> };
  const labelSource = legacy.device.provider.endsWith("(maintainer-selected)")
    ? "MAINTAINER_SELECTED"
    : "UNKNOWN";
  if (metadata.providerSource !== labelSource)
    throw new Error("Legacy provenance does not match the original provider label");
  const normalized: InteropReport = {
    ...legacy,
    schemaVersion: 1,
    outcome: legacy.status === "PASS" ? "PASS" : "FAILED",
    device: { ...legacy.device, providerSource: metadata.providerSource },
    databaseTransaction: { status: "UNKNOWN" },
    provenance: { kind: "LEGACY_NORMALIZATION", sourceFile, sourceSha256 },
  };
  assertValidInteropReport(normalized);
  return normalized;
}
