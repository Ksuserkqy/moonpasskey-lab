import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { RpError } from './security.mjs';

export async function loadCore(path = process.env.REFERENCE_RP_CORE) {
  if (!path) throw new Error('Set REFERENCE_RP_CORE to the compiled MoonBit analysis JavaScript module.');
  const module = await import(pathToFileURL(resolve(path)).href);
  const invoke = name => async input => {
    const fn = module[name] ?? module.default?.[name];
    if (typeof fn !== 'function') throw new Error(`MoonBit export ${name} is unavailable.`);
    const output = JSON.parse(fn(JSON.stringify(input)));
    if (!output || !['PASS', 'FAIL'].includes(output.status)) throw new RpError('InvalidCoreResponse', 500);
    return output;
  };
  return { host: invoke('run_host_json'), analyze: invoke('run_json') };
}
