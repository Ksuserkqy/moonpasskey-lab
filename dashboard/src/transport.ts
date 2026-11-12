import {
  CHECK_NAMES,
  assertValidInteropReport,
  type DatabaseTransaction,
  type InteropReport,
  type ProviderSource,
} from "./interop-report.ts";

export type CheckStatus =
  | "PASS"
  | "FAIL"
  | "WARNING"
  | "NOT_PERFORMED"
  | "ADVANCED"
  | "NOT_SUPPORTED";

export interface CoreReport {
  status: "PASS" | "FAIL";
  algorithm?: string;
  command?: string;
  checks?: Record<string, CheckStatus>;
  error?: { kind: string; context?: string; offset?: number };
  clientData?: {
    type: string;
    challenge: { redacted: boolean; encodedLength: number };
    origin: string;
    crossOrigin: boolean | null;
    topOrigin: string | null;
  };
  authenticatorData?: {
    rpIdHash: string;
    length: number;
    flags: {
      up: boolean;
      uv: boolean;
      be: boolean;
      bs: boolean;
      at: boolean;
      ed: boolean;
      rfu: number;
    };
    signCount: number;
  };
  crypto?: { format: string; signatureValid?: boolean };
  counter?: { status: CheckStatus; stored: number; received: number };
}

export interface ReportEnvelope {
  status: "PASS" | "FAIL";
  report?: CoreReport;
  reportId?: string;
  error?: { kind: string; context?: string };
  databaseTransaction?: Extract<DatabaseTransaction, { status: "COMMITTED" }>;
}

export interface Session {
  csrfToken: string;
  developmentOnly: boolean;
  config: {
    rpId: string;
    origin: string;
    userVerification: UserVerificationRequirement;
    counterPolicy: "report-only" | "reject";
  };
  user: { id: string; name: string; displayName: string; userHandle: string };
}

export interface StoredCredential {
  id: string;
  credentialId: string;
  version: number;
  signCount: number;
  backupEligible: boolean;
  backupState: boolean;
}

export interface DeviceMetadata {
  device: string;
  operatingSystem: string;
  browser: string;
  provider: string;
  providerSource: ProviderSource;
}

export interface LocalReport {
  id: string;
  source: "registration" | "assertion" | "import";
  createdAt: string;
  report: CoreReport;
  configuration?: Session["config"];
  databaseTransaction?: DatabaseTransaction;
  inputProvenance?: "SYNTHETIC" | "UNVERIFIED";
}

export function captureLocalReport(
  envelope: ReportEnvelope | CoreReport,
  source: LocalReport["source"],
  config?: Session["config"],
): LocalReport {
  const report =
    "report" in envelope && envelope.report
      ? envelope.report
      : envelope as CoreReport;
  const committed =
    "databaseTransaction" in envelope ? envelope.databaseTransaction : undefined;
  return {
    id:
      "reportId" in envelope && envelope.reportId
        ? envelope.reportId
        : crypto.randomUUID(),
    source,
    createdAt: new Date().toISOString(),
    report: structuredClone(report),
    configuration: source !== "import" && config ? { ...config } : undefined,
    databaseTransaction:
      source === "import"
        ? { status: "NOT_PERFORMED" }
        : committed
          ? {
              status: committed.status,
              previousVersion: committed.previousVersion,
              version: committed.version,
            }
          : { status: "NOT_OBSERVED" },
  };
}

export const MAX_IMPORT_BYTES = 2_097_152;

// Browser transport encoding preserves ArrayBuffer bytes. Protocol checks run in Core.
export function toBase64Url(buffer: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(buffer))
    binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(value: string): ArrayBuffer {
  const standard = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(standard + "=".repeat((4 - (standard.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

interface EncodedDescriptor {
  type: PublicKeyCredentialType;
  id: string;
  transports?: AuthenticatorTransport[];
}

export interface EncodedCreationOptions
  extends Omit<
    PublicKeyCredentialCreationOptions,
    "challenge" | "user" | "excludeCredentials"
  > {
  challenge: string;
  user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
  excludeCredentials?: EncodedDescriptor[];
}

export interface EncodedRequestOptions
  extends Omit<
    PublicKeyCredentialRequestOptions,
    "challenge" | "allowCredentials"
  > {
  challenge: string;
  allowCredentials?: EncodedDescriptor[];
}

export interface Challenge {
  challengeId: string;
  challenge: string;
  publicKey: EncodedCreationOptions | EncodedRequestOptions;
}

export function creationOptions(
  options: EncodedCreationOptions,
): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: fromBase64Url(options.challenge),
    user: { ...options.user, id: fromBase64Url(options.user.id) },
    excludeCredentials: options.excludeCredentials?.map((item) => ({
      ...item,
      id: fromBase64Url(item.id),
    })),
  };
}

export function requestOptions(
  options: EncodedRequestOptions,
): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: fromBase64Url(options.challenge),
    allowCredentials: options.allowCredentials?.map((item) => ({
      ...item,
      id: fromBase64Url(item.id),
    })),
  };
}

// Export an explicit field allowlist. Raw input, credential IDs, handles,
// signatures, public coordinates and challenges never enter this object.
export function safeReportExport(
  entry: LocalReport,
  device: DeviceMetadata,
  config?: Session["config"],
): InteropReport {
  const report = entry.report;
  const client = report.clientData;
  const auth = report.authenticatorData;
  const configuration = entry.source === "import"
    ? undefined
    : entry.configuration ?? config;
  const transaction = entry.databaseTransaction;
  const exported = {
    schemaVersion: 1,
    application: "MoonPasskey Lab",
    developmentOnly: true,
    source: entry.source,
    capturedAt: entry.createdAt,
    device: {
      device: device.device,
      operatingSystem: device.operatingSystem,
      browser: device.browser,
      provider: device.provider,
      providerSource: device.providerSource,
    },
    configuration: configuration
      ? {
          rpId: configuration.rpId,
          origin: configuration.origin,
          userVerification: configuration.userVerification,
          counterPolicy: configuration.counterPolicy,
        }
      : null,
    outcome: report.status === "PASS" ? "PASS" : "FAILED",
    status: report.status,
    databaseTransaction:
      transaction?.status === "COMMITTED"
        ? {
            status: transaction.status,
            previousVersion: transaction.previousVersion,
            version: transaction.version,
          }
        : {
            status:
              transaction?.status ??
              (entry.source === "import" ? "NOT_PERFORMED" : "NOT_OBSERVED"),
          },
    algorithm: report.algorithm,
    checks: report.checks
      ? Object.fromEntries(
          CHECK_NAMES.filter((key) => Object.hasOwn(report.checks!, key))
            .map((key) => [key, report.checks![key]]),
        )
      : undefined,
    error: report.error
      ? {
          kind: report.error.kind,
          context: report.error.context,
          offset: report.error.offset,
        }
      : undefined,
    clientData: client
      ? {
          type: client.type,
          challenge: {
            redacted: true,
            encodedLength: client.challenge?.encodedLength,
          },
          origin: client.origin,
          crossOrigin: client.crossOrigin,
          topOrigin: client.topOrigin,
        }
      : undefined,
    authenticatorData: auth
      ? {
          length: auth.length,
          flags: {
            up: auth.flags.up,
            uv: auth.flags.uv,
            be: auth.flags.be,
            bs: auth.flags.bs,
            at: auth.flags.at,
            ed: auth.flags.ed,
            rfu: auth.flags.rfu,
          },
          signCount: auth.signCount,
        }
      : undefined,
    crypto: report.crypto
      ? {
          format: report.crypto.format,
          signatureValid: report.crypto.signatureValid,
        }
      : undefined,
    counter: report.counter
      ? {
          status: report.counter.status,
          stored: report.counter.stored,
          received: report.counter.received,
        }
      : undefined,
  };
  // Match the actual JSON download and remove absent optional values before validation.
  const serialized: unknown = JSON.parse(JSON.stringify(exported));
  assertValidInteropReport(serialized);
  return serialized;
}
