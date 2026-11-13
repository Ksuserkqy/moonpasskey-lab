#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [ -n "${MOON_HOME:-}" ]; then export PATH="$MOON_HOME/bin:$PATH"; fi

case "${1:-start}" in
  start|cli) mode="${1:-start}" ;;
  -h|--help)
    printf '%s\n' 'Usage: ./scripts/demo.sh [start|cli]' \
      '  start  Build Core, CLI and Dashboard; serve http://localhost:8787 (default).' \
      '         Set DEMO_PORT to use another local port.' \
      '  cli    Run seven SYNTHETIC cases through the normal CLI, human + JSON.'
    exit 0 ;;
  *) printf '%s\n' 'Usage: ./scripts/demo.sh [start|cli]' >&2; exit 64 ;;
esac
if [ "$#" -gt 1 ]; then
  printf '%s\n' 'Expected at most one argument.' >&2
  exit 64
fi

port="${DEMO_PORT:-8787}"
case "$port" in
  ''|*[!0-9]*) printf '%s\n' 'DEMO_PORT must be an integer from 1 to 65535.' >&2; exit 64 ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
  printf '%s\n' 'DEMO_PORT must be an integer from 1 to 65535.' >&2
  exit 64
fi

for tool in node npm moon moonc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Missing %s. Install Node.js 24.18.0 and MoonBit 0.10.20+65efd5b93 first.\n' "$tool" >&2
    exit 1
  fi
done
if [ "$(node --version)" != 'v24.18.0' ]; then
  printf '%s\n' 'This demo requires Node.js v24.18.0 on PATH.' >&2
  exit 1
fi
case "$(moonc -v)" in
  'v0.10.20+65efd5b93 '*) ;;
  *) printf '%s\n' 'This demo requires moonc v0.10.20+65efd5b93 on PATH.' >&2; exit 1 ;;
esac

moon build analysis --target js --deny-warn
moon build cmd/main --target js --deny-warn

if [ "$mode" = cli ]; then
  while IFS='|' read -r name status error check; do
    input="examples/fixtures/$name.json"
    expected_exit=0
    if [ "$status" = FAIL ]; then expected_exit=2; fi
    printf '\n=== SYNTHETIC %s (expected %s) — human ===\n' "$name" "$status"
    if moon run cmd/main --target js --deny-warn -- --input "$input"; then
      actual_exit=0
    else
      actual_exit=$?
    fi
    if [ "$actual_exit" -ne "$expected_exit" ]; then
      printf 'Unexpected human CLI exit: %s (expected %s).\n' "$actual_exit" "$expected_exit" >&2
      exit 1
    fi
    printf '\n=== SYNTHETIC %s — JSON ===\n' "$name"
    if report="$(moon run cmd/main --target js --deny-warn -- --input "$input" --json)"; then
      actual_exit=0
    else
      actual_exit=$?
    fi
    if [ "$actual_exit" -ne "$expected_exit" ]; then
      printf 'Unexpected JSON CLI exit: %s (expected %s).\n' "$actual_exit" "$expected_exit" >&2
      exit 1
    fi
    printf '%s\n' "$report"
    node - "$input" "$status" "$error" "$check" "$report" <<'NODE'
const [path, status, error, check, text] = process.argv.slice(2);
const { readFileSync } = require('node:fs');
const assert = require('node:assert/strict');
const input = JSON.parse(readFileSync(path, 'utf8'));
const report = JSON.parse(text);
assert.equal(input._fixture.classification, 'SYNTHETIC');
assert.equal(typeof report.status, 'string');
assert.equal(report.status, status);
assert.equal(report.command, input.command);
assert.equal(report.redacted, true);
assert.equal(report.checks[check], status);
if (error === '-') {
  assert.equal(report.error, undefined);
  if (input.command === 'verify-assertion') assert.equal(report.crypto.signatureValid, true);
  else assert.equal(report.checks.signature, 'NOT_PERFORMED');
} else {
  assert.equal(typeof report.error.kind, 'string');
  assert.equal(report.error.kind, error);
  assert.equal(typeof report.error.context, 'string');
}
NODE
  done <<'CASES'
client-data|PASS|-|json
authenticator-data|PASS|-|authenticator_data
verify-valid|PASS|-|signature
verify-invalid-signature|FAIL|InvalidSignature|signature
verify-wrong-challenge|FAIL|ChallengeMismatch|challenge
verify-wrong-origin|FAIL|OriginNotAllowed|origin
verify-uv-required|FAIL|UserVerificationRequired|user_verification
CASES
  printf '\n%s\n' 'All 7 SYNTHETIC cases matched their status, error kind, check and exit code.'
  exit 0
fi

if [ ! -x dashboard/node_modules/.bin/vite ]; then
  (cd dashboard && npm ci)
fi
(cd dashboard && npm run build)

# Keep the one-command demo local, ephemeral, and independent of deployment env.
export REFERENCE_RP_PORT="$port" REFERENCE_RP_ORIGIN="http://localhost:$port"
export REFERENCE_RP_ID=localhost REFERENCE_RP_DB=:memory:
export REFERENCE_RP_UV=required REFERENCE_RP_COUNTER=report-only
unset REFERENCE_RP_TLS_CERT REFERENCE_RP_TLS_KEY REFERENCE_RP_CORE
printf '\n%s\n' "Open http://localhost:$port — TEST ONLY, in-memory store, UV required." \
  'Use a second terminal for ./scripts/demo.sh cli. Stop the local server with Ctrl+C.'
exec node reference-rp/start.mjs
