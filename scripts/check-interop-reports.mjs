import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertValidInteropReport, normalizeLegacyReport } from '../dashboard/src/interop-report.ts';

const reportDirectory = fileURLToPath(new URL('../docs/interop/', import.meta.url));

function rejectDuplicateKeys(text) {
  const containers = [];
  const tokens = /"(?:\\.|[^"\\])*"|[{}\[\]]/g;
  for (const token of text.matchAll(tokens)) {
    const value = token[0];
    if (value === '{') containers.push(new Set());
    else if (value === '[') containers.push(null);
    else if (value === '}' || value === ']') containers.pop();
    else if (/^[\t\n\r ]*:/.test(text.slice(token.index + value.length))) {
      const keys = containers.at(-1);
      const key = JSON.parse(value);
      if (keys.has(key)) throw new Error('Report or provenance contains duplicate JSON object keys');
      keys.add(key);
    }
  }
}

function parseJson(bytes) {
  if (bytes.length > 2_097_152)
    throw new Error('Report or provenance exceeds the two-MiB input limit');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error('Report or provenance must use valid UTF-8');
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('Report or provenance contains invalid JSON');
  }
  // Native JSON parsing validates syntax. This lexical pass only detects keys
  // that would otherwise disappear before the strict field allowlist runs.
  rejectDuplicateKeys(text);
  return value;
}

const requested = process.argv.slice(2);
const files = requested.length
  ? requested.map(path => resolve(path))
  : (await readdir(reportDirectory)).filter(name => name.endsWith('.redacted.json'))
    .sort().map(name => resolve(reportDirectory, name));

if (!files.length) {
  console.error('No redacted interoperability reports found');
  process.exitCode = 1;
}

for (const path of files) {
  try {
    const bytes = await readFile(path);
    const report = parseJson(bytes);
    if (report?.schemaVersion === undefined) {
      const sidecar = path.replace(/\.redacted\.json$/, '.provenance.json');
      if (sidecar === path) throw new Error('Legacy reports require a .redacted.json filename and provenance sidecar');
      const provenance = parseJson(await readFile(sidecar));
      const digest = createHash('sha256').update(bytes).digest('hex');
      normalizeLegacyReport(report, provenance, basename(path), digest);
      console.log(`PASS ${basename(path)} (legacy bytes verified, transaction evidence UNKNOWN)`);
    } else {
      assertValidInteropReport(report);
      console.log(`PASS ${basename(path)} (schema v1)`);
    }
  } catch (error) {
    console.error(`FAILED ${basename(path)} — ${error.message}`);
    process.exitCode = 1;
  }
}
