import { Worker } from 'node:worker_threads';

const failure = (error) => ({ redactedJson: '', replacedKeys: [], piiCount: 0, error });

/** Redact using untrusted custom key regexes with an enforceable time budget. */
export function redactJsonWithKeyModes(json, { keyModes, maskChar }) {
  if (keyModes.length > 20 || keyModes.some((p) => typeof p !== 'string' || p.length === 0 || p.length > 200)) {
    return Promise.resolve(failure('invalid keyModes: at most 20 non-empty string patterns, each up to 200 characters'));
  }
  // Compile only for syntax validation here; matching always happens in the worker.
  try {
    new RegExp(keyModes.map((p) => `(?:${p})`).join('|'), 'i');
  } catch {
    return Promise.resolve(failure('invalid keyModes regex'));
  }
  return new Promise((resolve) => {
    let worker;
    let timer;
    let settled = false;
    function finish(result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (worker) void worker.terminate();
      resolve(result);
    }
    try {
      worker = new Worker(new URL('./redact-worker.js', import.meta.url), {
        // The file worker needs no host eval/preload flags (notably
        // --input-type, which is valid for eval but invalid for a file).
        execArgv: [],
        workerData: { json, patterns: keyModes, maskChar },
        resourceLimits: { maxOldGenerationSizeMb: 64 },
      });
      timer = setTimeout(() => finish(failure('custom key matching exceeded its 2000ms budget')), 2_000);
      worker.once('message', finish);
      worker.once('error', () => finish(failure('custom key matching failed')));
      worker.once('exit', () => finish(failure('custom key matching stopped before completion')));
    } catch {
      finish(failure('custom key matching could not start'));
    }
  });
}
