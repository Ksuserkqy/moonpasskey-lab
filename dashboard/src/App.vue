<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import {
  MAX_IMPORT_BYTES,
  creationOptions,
  requestOptions,
  safeReportExport,
  toBase64Url,
  type Challenge,
  type CoreReport,
  type DeviceMetadata,
  type EncodedCreationOptions,
  type EncodedRequestOptions,
  type LocalReport,
  type ReportEnvelope,
  type Session,
  type StoredCredential,
} from "./transport";

const tab = ref<"browser" | "import" | "reports">("browser");
const session = ref<Session>();
const credentials = ref<StoredCredential[]>([]);
const reports = ref<LocalReport[]>([]);
const selectedReport = ref<LocalReport>();
const busy = ref("");
const notice = ref("");
const connected = ref(false);
const importedText = ref("");
const importCommand = ref("verify-assertion");
const fileInput = ref<HTMLInputElement>();
const device = reactive<DeviceMetadata>({
  device: "",
  operatingSystem: "",
  browser: "",
  provider: "",
});
const browserOrigin = window.location.origin;

const browserReady =
  window.isSecureContext &&
  typeof PublicKeyCredential !== "undefined" &&
  !!navigator.credentials;
const report = computed(() => selectedReport.value?.report);
const flags = computed(() => report.value?.authenticatorData?.flags);
const available = computed(
  () => connected.value && browserReady && !busy.value,
);
const successfulChecks = computed(
  () =>
    Object.values(report.value?.checks ?? {}).filter(
      (value) => value === "PASS",
    ).length,
);
const checkEntries = [
  ["json", "Client data JSON"],
  ["authenticator_data", "Authenticator data"],
  ["identity", "Credential & account"],
  ["challenge", "Challenge"],
  ["origin", "Origin"],
  ["cross_origin", "Cross-origin policy"],
  ["rp_id_hash", "RP ID hash"],
  ["user_presence", "User presence"],
  ["user_verification", "User verification"],
  ["backup", "Backup eligibility & state"],
  ["public_key", "ES256 public key"],
  ["signature", "ECDSA signature"],
  ["counter", "Signature counter"],
];
const flagEntries = [
  ["up", "UP", "User present"],
  ["uv", "UV", "User verified"],
  ["be", "BE", "Backup eligible"],
  ["bs", "BS", "Backed up"],
  ["at", "AT", "Attested data"],
  ["ed", "ED", "Extensions"],
  ["rfu", "RFU", "Reserved bits"],
] as const;

const resultTitle = computed(() => {
  if (!report.value) return "Ready for an assertion";
  if (report.value.status === "FAIL") return "Core verification failed";
  if (selectedReport.value?.source === "registration")
    return "Test credential registered";
  if (selectedReport.value?.source === "assertion") return "Assertion verified";
  return "Core request completed";
});

function statusClass(status?: string): string {
  if (status === "PASS" || status === "ADVANCED") return "pass";
  if (status === "FAIL") return "fail";
  if (status === "WARNING") return "warning";
  return "pending";
}

function statusLabel(status?: string): string {
  return (status ?? "NOT_PERFORMED").replaceAll("_", " ");
}

function flagValue(key: (typeof flagEntries)[number][0]): string {
  if (!flags.value) return "—";
  return key === "rfu" ? String(flags.value.rfu) : flags.value[key] ? "1" : "0";
}

function flagActive(key: (typeof flagEntries)[number][0]): boolean {
  if (!flags.value) return false;
  return key === "rfu" ? flags.value.rfu !== 0 : flags.value[key];
}

async function api<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    credentials: "same-origin",
    headers:
      body === undefined
        ? {}
        : {
            "Content-Type": "application/json",
            "X-CSRF-Token": session.value?.csrfToken ?? "",
          },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  const payload = await response.json();
  if (!response.ok && !payload.report) {
    const error = payload.error;
    throw new Error(
      error?.kind
        ? `${error.kind}${error.context ? ` · ${error.context}` : ""}`
        : `Local service returned HTTP ${response.status}`,
    );
  }
  return payload as T;
}

async function refreshCredentials() {
  const state = await api<{ credentials: StoredCredential[] }>("/api/state");
  credentials.value = state.credentials;
}

async function connect() {
  busy.value = "Connecting to local RP";
  notice.value = "";
  try {
    session.value = await api<Session>("/api/session");
    await refreshCredentials();
    connected.value = true;
  } catch {
    connected.value = false;
    notice.value =
      "The local reference RP is unavailable. Start the reference-rp server, then reconnect.";
  } finally {
    busy.value = "";
  }
}

function remember(
  envelope: ReportEnvelope | CoreReport,
  source: LocalReport["source"],
) {
  const value =
    "report" in envelope && envelope.report
      ? envelope.report
      : (envelope as CoreReport);
  const entry: LocalReport = {
    id:
      "reportId" in envelope && envelope.reportId
        ? envelope.reportId
        : crypto.randomUUID(),
    source,
    createdAt: new Date().toISOString(),
    report: value,
  };
  reports.value = [entry, ...reports.value].slice(0, 30);
  selectedReport.value = entry;
}

function describeError(error: unknown): string {
  if (error instanceof DOMException && error.name === "NotAllowedError") {
    return "The browser did not complete the passkey request. You can retry after checking its prompt or authenticator.";
  }
  return error instanceof Error
    ? error.message
    : "The local request could not be completed.";
}

async function registerPasskey() {
  notice.value = "";
  busy.value = "Complete the browser registration prompt";
  try {
    const challenge = await api<Challenge>("/api/challenges", {
      purpose: "registration",
    });
    const credential = await navigator.credentials.create({
      publicKey: creationOptions(challenge.publicKey as EncodedCreationOptions),
    });
    if (
      !(credential instanceof PublicKeyCredential) ||
      !(credential.response instanceof AuthenticatorAttestationResponse)
    ) {
      throw new Error("Expected a public-key registration response.");
    }
    const result = await api<ReportEnvelope>("/api/register", {
      challengeId: challenge.challengeId,
      challenge: challenge.challenge,
      type: credential.type,
      rawId: toBase64Url(credential.rawId),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
      attestationObject: toBase64Url(credential.response.attestationObject),
    });
    remember(result, "registration");
    await refreshCredentials();
  } catch (error) {
    notice.value = describeError(error);
  } finally {
    busy.value = "";
  }
}

async function authenticate() {
  notice.value = "";
  busy.value = "Complete the browser authentication prompt";
  try {
    const challenge = await api<Challenge>("/api/challenges", {
      purpose: "assertion",
    });
    const credential = await navigator.credentials.get({
      publicKey: requestOptions(challenge.publicKey as EncodedRequestOptions),
    });
    if (
      !(credential instanceof PublicKeyCredential) ||
      !(credential.response instanceof AuthenticatorAssertionResponse)
    ) {
      throw new Error("Expected a public-key assertion response.");
    }
    const result = await api<ReportEnvelope>("/api/assertions", {
      challengeId: challenge.challengeId,
      challenge: challenge.challenge,
      type: credential.type,
      rawId: toBase64Url(credential.rawId),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
      authenticatorData: toBase64Url(credential.response.authenticatorData),
      signature: toBase64Url(credential.response.signature),
      userHandle:
        credential.response.userHandle === null
          ? null
          : toBase64Url(credential.response.userHandle),
    });
    remember(result, "assertion");
    await refreshCredentials();
  } catch (error) {
    notice.value = describeError(error);
  } finally {
    busy.value = "";
  }
}

async function importFile(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  notice.value = "";
  if (file.size > MAX_IMPORT_BYTES) {
    notice.value = "The local service accepts JSON requests up to 2 MiB.";
  } else {
    importedText.value = await file.text();
  }
  input.value = "";
}

async function analyzeImport() {
  notice.value = "";
  busy.value = "MoonBit Core is checking the imported request";
  try {
    if (
      new TextEncoder().encode(importedText.value).length > MAX_IMPORT_BYTES
    ) {
      throw new Error("The local service accepts JSON requests up to 2 MiB.");
    }
    const input = JSON.parse(importedText.value);
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new Error("Import a JSON request object.");
    }
    const result = await api<ReportEnvelope | CoreReport>("/api/analyze", {
      ...input,
      command: importCommand.value,
    });
    remember(result, "import");
  } catch (error) {
    notice.value = describeError(error);
  } finally {
    busy.value = "";
  }
}

function downloadReport() {
  if (!selectedReport.value) return;
  const exported = safeReportExport(
    selectedReport.value,
    device,
    session.value?.config,
  );
  const blob = new Blob([JSON.stringify(exported, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `moonpasskey-report-${selectedReport.value.createdAt.replaceAll(":", "-")}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function clearView() {
  importedText.value = "";
  reports.value = [];
  selectedReport.value = undefined;
  notice.value = "";
}

onMounted(connect);
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <a class="brand" href="/" aria-label="MoonPasskey Lab home"
        ><span class="moon-mark" aria-hidden="true"></span
        ><span>MoonPasskey<span class="brand-lab">LAB</span></span></a
      >
      <div class="workspace-label">LOCAL WORKSPACE</div>
      <nav aria-label="Workspace navigation">
        <button
          :class="{ selected: tab === 'browser' }"
          @click="tab = 'browser'"
        >
          <span class="nav-icon">⌘</span> Browser test
        </button>
        <button :class="{ selected: tab === 'import' }" @click="tab = 'import'">
          <span class="nav-icon">↥</span> Import assertion
        </button>
        <button
          :class="{ selected: tab === 'reports' }"
          @click="tab = 'reports'"
        >
          <span class="nav-icon">▤</span> Test reports
          <span v-if="reports.length" class="nav-count">{{
            reports.length
          }}</span>
        </button>
      </nav>
      <div class="sidebar-bottom">
        <span class="local-dot"></span> Local development only
        <p>MoonBit Core<br />ES256 · MoonCrypt 0.4.16</p>
        <span class="test-only-label">TEST ONLY</span>
      </div>
    </aside>

    <div class="main-shell">
      <header class="topbar">
        <div>
          <span class="breadcrumb">Workspace</span
          ><span class="breadcrumb-divider">/</span
          ><span>Assertion verification</span>
        </div>
        <div class="connection" :class="{ online: connected }">
          <span></span
          >{{ connected ? "Local RP connected" : "Local RP offline" }}
        </div>
      </header>
      <main>
        <div class="page-heading">
          <div>
            <div class="eyebrow">WEBAUTHN VERIFICATION</div>
            <h1>
              {{
                tab === "browser"
                  ? "Browser test"
                  : tab === "import"
                    ? "Import assertion"
                    : "Test reports"
              }}
            </h1>
            <p>
              {{
                tab === "browser"
                  ? "Create a temporary passkey and verify a real browser assertion."
                  : tab === "import"
                    ? "Send original protocol bytes to your local MoonBit Core."
                    : "Review the Core results collected in this browser session."
              }}
            </p>
          </div>
          <button
            class="button secondary"
            :disabled="!selectedReport"
            @click="downloadReport"
          >
            <span>↓</span> Export safe report
          </button>
        </div>

        <div v-if="notice" class="notice" role="alert">
          <span class="notice-symbol">!</span><span>{{ notice }}</span
          ><button v-if="!connected" @click="connect">Reconnect</button
          ><button v-else aria-label="Dismiss message" @click="notice = ''">
            ×
          </button>
        </div>
        <div
          v-if="!browserReady && tab === 'browser'"
          class="notice"
          role="status"
        >
          WebAuthn needs a supported browser and a secure context. Open the
          local RP at localhost or use its configured HTTPS origin.
        </div>

        <section class="environment" aria-label="Trusted server configuration">
          <div>
            <span>RP ID</span><strong>{{ session?.config.rpId ?? "—" }}</strong>
          </div>
          <div>
            <span>Origin</span
            ><strong>{{ session?.config.origin ?? browserOrigin }}</strong>
          </div>
          <div>
            <span>User verification</span
            ><strong>{{ session?.config.userVerification ?? "—" }}</strong>
          </div>
          <div>
            <span>Counter policy</span
            ><strong>{{ session?.config.counterPolicy ?? "—" }}</strong>
          </div>
        </section>

        <template v-if="tab === 'browser'">
          <section class="browser-workflow" aria-label="Browser test workflow">
            <div class="workflow-step">
              <div class="step-number">1</div>
              <div class="step-content">
                <h2>Create a test passkey</h2>
                <p>
                  Register an ES256 credential with your browser’s
                  authenticator.
                </p>
                <button
                  class="button secondary"
                  :disabled="!available"
                  @click="registerPasskey"
                >
                  {{
                    busy.includes("registration")
                      ? "Waiting for your browser…"
                      : "Register test passkey"
                  }}<span>↗</span>
                </button>
              </div>
            </div>
            <div class="workflow-step">
              <div class="step-number" :class="{ ready: credentials.length }">
                2
              </div>
              <div class="step-content">
                <h2>Authenticate & verify</h2>
                <p>
                  Submit the original response for Core verification and atomic
                  state commit.
                </p>
                <button
                  class="button primary"
                  :disabled="!available || !credentials.length"
                  @click="authenticate"
                >
                  {{
                    busy.includes("authentication")
                      ? "Waiting for your browser…"
                      : "Verify with passkey"
                  }}<span>→</span>
                </button>
              </div>
            </div>
          </section>
          <div class="credential-strip">
            <span class="credential-icon">⌑</span
            ><span
              ><strong>{{
                credentials.length
                  ? `${credentials.length} test credential${credentials.length > 1 ? "s" : ""} registered`
                  : "No test credential registered"
              }}</strong
              ><small>{{
                credentials.length
                  ? "Credential identifiers and account handles are hidden."
                  : "Complete registration to enable the authentication step."
              }}</small></span
            ><span v-if="credentials.length" class="credential-counter"
              >Counter <strong>{{ credentials[0].signCount }}</strong
              ><span class="divider">/</span> Version
              {{ credentials[0].version }}</span
            >
          </div>
          <p class="registration-boundary">
            Test registration checks the response bindings and public key.
            Attestation trust validation is outside this test adapter.
          </p>
        </template>

        <section v-if="tab === 'import'" class="import-panel panel">
          <div class="panel-heading">
            <div>
              <h2>Original request JSON</h2>
              <p>
                Binary fields use Base64URL. Keep clientDataJSON in its original
                byte encoding.
              </p>
            </div>
            <button class="button secondary small" @click="fileInput?.click()">
              Choose JSON file</button
            ><input
              ref="fileInput"
              class="visually-hidden"
              type="file"
              accept="application/json,.json"
              @change="importFile"
            />
          </div>
          <label class="input-label" for="core-command">Core operation</label
          ><select id="core-command" v-model="importCommand">
            <option value="verify-assertion">Verify assertion</option>
            <option value="analyze-assertion">
              Analyze assertion & signature
            </option>
            <option value="client-data">Analyze ClientDataJSON</option>
            <option value="authenticator-data">
              Analyze AuthenticatorData
            </option>
          </select>
          <label class="input-label" for="request-json">Request body</label
          ><textarea
            id="request-json"
            v-model="importedText"
            spellcheck="false"
            placeholder='{
  "clientDataJSON": "<original bytes, Base64URL>",
  "authenticatorData": "<Base64URL>",
  "signature": "<DER signature, Base64URL>",
  "expectedChallenge": "<Base64URL>",
  "credentialId": "<Base64URL>",
  "credential": { "publicKey": "<COSE key, Base64URL>", "credentialId": "<Base64URL>", "userHandle": "<Base64URL>", "signCount": 0 },
  "policy": { "rpId": "localhost", "allowedOrigins": ["http://localhost:8080"], "uv": "preferred" }
}'
          ></textarea>
          <div class="import-actions">
            <span>Sent only to this local RP · 2 MiB request limit</span
            ><button
              class="button primary"
              :disabled="!connected || !!busy || !importedText.trim()"
              @click="analyzeImport"
            >
              Run MoonBit Core<span>→</span>
            </button>
          </div>
        </section>

        <section v-if="tab === 'reports'" class="reports-layout">
          <div class="panel history-panel">
            <div class="panel-heading">
              <h2>Session reports</h2>
              <button
                class="text-button"
                :disabled="!reports.length"
                @click="clearView"
              >
                Clear view
              </button>
            </div>
            <div v-if="!reports.length" class="empty-history">
              Complete a browser test or import a request to collect Core
              results.
            </div>
            <button
              v-for="entry in reports"
              :key="entry.id"
              class="history-row"
              :class="{ active: selectedReport?.id === entry.id }"
              @click="selectedReport = entry"
            >
              <span
                class="status-dot"
                :class="statusClass(entry.report.status)"
              ></span
              ><span
                ><strong>{{
                  entry.source === "registration"
                    ? "Test registration"
                    : entry.source === "assertion"
                      ? "Browser assertion"
                      : "Imported request"
                }}</strong
                ><small>{{
                  new Date(entry.createdAt).toLocaleTimeString()
                }}</small></span
              ><span
                class="status-text"
                :class="statusClass(entry.report.status)"
                >{{ entry.report.status }}</span
              >
            </button>
          </div>
          <div class="panel device-panel">
            <div class="panel-heading">
              <div>
                <h2>Device evidence</h2>
                <p>Record the environment you actually used.</p>
              </div>
            </div>
            <label for="device-model">Device model</label
            ><input
              id="device-model"
              v-model="device.device"
              placeholder="e.g. MacBook Pro"
            /><label for="device-os">Operating system & version</label
            ><input
              id="device-os"
              v-model="device.operatingSystem"
              placeholder="Enter the actual OS version"
            /><label for="device-browser">Browser & version</label
            ><input
              id="device-browser"
              v-model="device.browser"
              placeholder="Enter the actual browser version"
            /><label for="device-provider"
              >Passkey provider or security key</label
            ><input
              id="device-provider"
              v-model="device.provider"
              placeholder="e.g. iCloud Keychain"
            />
          </div>
        </section>

        <div class="results-layout">
          <section class="panel verification-panel">
            <div class="panel-heading">
              <h2>Verification flow</h2>
              <span class="core-source">MOONBIT CORE</span>
            </div>
            <div class="result-summary" :class="statusClass(report?.status)">
              <div class="result-symbol">
                {{
                  report?.status === "PASS"
                    ? "✓"
                    : report?.status === "FAIL"
                      ? "×"
                      : "◷"
                }}
              </div>
              <div>
                <h3>{{ resultTitle }}</h3>
                <p>
                  {{
                    busy ||
                    (report
                      ? `${successfulChecks} checks passed · ${selectedReport?.source === "import" ? "Imported request" : "Local reference RP"}`
                      : "Each check will show its result from the Core response.")
                  }}
                </p>
              </div>
              <span
                v-if="report"
                class="status-chip"
                :class="statusClass(report.status)"
                >{{ report.status }}</span
              >
            </div>
            <div v-if="report?.error" class="core-error">
              <strong>{{ report.error.kind }}</strong
              ><span
                >{{ report.error.context
                }}{{
                  report.error.offset !== undefined
                    ? ` · byte ${report.error.offset}`
                    : ""
                }}</span
              >
            </div>
            <div class="check-list">
              <div
                v-for="[key, label] in checkEntries"
                :key="key"
                class="check-row"
              >
                <span
                  class="check-indicator"
                  :class="statusClass(report?.checks?.[key])"
                  >{{
                    report?.checks?.[key] === "PASS"
                      ? "✓"
                      : report?.checks?.[key] === "FAIL"
                        ? "×"
                        : "·"
                  }}</span
                ><span>{{ label }}</span
                ><span
                  class="status-text"
                  :class="statusClass(report?.checks?.[key])"
                  >{{ statusLabel(report?.checks?.[key]) }}</span
                >
              </div>
            </div>
          </section>

          <div class="detail-column">
            <section class="panel flags-panel">
              <div class="panel-heading">
                <h2>Authenticator flags</h2>
                <span class="muted">{{
                  report?.authenticatorData
                    ? `${report.authenticatorData.length} bytes`
                    : "No response"
                }}</span>
              </div>
              <div class="flag-grid">
                <div
                  v-for="[key, label, description] in flagEntries"
                  :key="key"
                  class="flag-cell"
                  :class="{ set: flagActive(key) }"
                  :title="description"
                >
                  <span>{{ label }}</span
                  ><strong>{{ flagValue(key) }}</strong
                  ><small>{{ description }}</small>
                </div>
              </div>
            </section>
            <section class="panel crypto-panel">
              <div class="panel-heading">
                <h2>Cryptography</h2>
                <span class="algorithm-tag">ES256</span>
              </div>
              <dl class="data-list">
                <div>
                  <dt>Public key</dt>
                  <dd>
                    {{
                      report?.checks?.public_key === "PASS"
                        ? "P-256 · validated"
                        : "Awaiting Core result"
                    }}
                  </dd>
                </div>
                <div>
                  <dt>Signature format</dt>
                  <dd>{{ report?.crypto?.format ?? "ASN.1 DER" }}</dd>
                </div>
                <div>
                  <dt>Signature verified</dt>
                  <dd
                    :class="
                      report?.crypto?.signatureValid === true
                        ? 'pass'
                        : report?.crypto?.signatureValid === false
                          ? 'fail'
                          : 'muted'
                    "
                  >
                    {{
                      report?.crypto?.signatureValid === true
                        ? "Valid"
                        : report?.crypto?.signatureValid === false
                          ? "Invalid"
                          : "Not performed"
                    }}
                  </dd>
                </div>
                <div>
                  <dt>Counter</dt>
                  <dd :class="statusClass(report?.counter?.status)">
                    {{
                      report?.counter
                        ? statusLabel(report.counter.status)
                        : "Not performed"
                    }}
                  </dd>
                </div>
                <div v-if="report?.counter">
                  <dt>Stored → received</dt>
                  <dd class="mono">
                    {{ report.counter.stored }} → {{ report.counter.received }}
                  </dd>
                </div>
              </dl>
            </section>
            <section class="panel client-panel">
              <div class="panel-heading">
                <h2>Client data</h2>
                <span class="privacy-label">REDACTED</span>
              </div>
              <dl class="data-list">
                <div>
                  <dt>Type</dt>
                  <dd class="mono">{{ report?.clientData?.type ?? "—" }}</dd>
                </div>
                <div>
                  <dt>Challenge</dt>
                  <dd class="muted">
                    {{
                      report?.clientData
                        ? `Hidden · ${report.clientData.challenge.encodedLength} encoded characters`
                        : "—"
                    }}
                  </dd>
                </div>
                <div>
                  <dt>Origin</dt>
                  <dd>{{ report?.clientData?.origin ?? "—" }}</dd>
                </div>
                <div>
                  <dt>Cross origin</dt>
                  <dd>
                    {{
                      report?.clientData
                        ? report.clientData.crossOrigin === null
                          ? "Absent"
                          : String(report.clientData.crossOrigin)
                        : "—"
                    }}
                  </dd>
                </div>
                <div>
                  <dt>Top origin</dt>
                  <dd>
                    {{
                      report?.clientData?.topOrigin ??
                      (report?.clientData ? "Absent" : "—")
                    }}
                  </dd>
                </div>
              </dl>
            </section>
          </div>
        </div>
        <footer>
          <span class="privacy-lock">⌑</span> Original authentication bytes stay
          in local memory. Exports contain a redacted report.<button
            class="text-button"
            @click="clearView"
          >
            Clear browser view
          </button>
        </footer>
      </main>
    </div>
  </div>
</template>
