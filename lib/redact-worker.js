import { parentPort, workerData } from 'node:worker_threads';
import { redactJson } from './redact.js';

// Custom regexes come from tool input. Execute them off the host event loop
// so a pathological expression can be terminated without freezing DSH.
const { json, patterns, maskChar } = workerData;
try {
  const keyPattern = new RegExp(patterns.map((p) => `(?:${p})`).join('|'), 'i');
  parentPort.postMessage(redactJson(json, { keyPattern, maskChar }));
} catch {
  parentPort.postMessage({ redactedJson: '', replacedKeys: [], piiCount: 0, error: 'invalid keyModes regex or JSON input' });
}
