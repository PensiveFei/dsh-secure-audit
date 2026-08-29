/**
 * Detection-quality evaluation for the injection rule engine.
 *
 * Runs the adversarial sample library through the scanner and reports
 * precision / recall / F1 over the positive (attack) and negative (benign)
 * classes, treating `block`/`review` as "flagged". A sample whose decision
 * regresses from its pinned expectation fails the run (exit 1) — CI runs
 * this after `npm test` so rule changes are measured, not just tested.
 *
 * Usage: `node scripts/eval.mjs` (CI: `npm run eval`).
 */

import { createInjectionScanner } from '../lib/injection.js';
import { ADVERSARIAL_SAMPLES } from '../tests/fixtures/adversarial-samples.js';

const scanner = createInjectionScanner({ timeoutMs: 2000 });

const rows = [];
let tp = 0;
let fp = 0;
let fn = 0;
let tn = 0;
const failures = [];

for (const sample of ADVERSARIAL_SAMPLES) {
  const result = await scanner.scan(sample.text);
  const flagged = result.decision === 'block' || result.decision === 'review';
  const positive = sample.expect === 'block' || sample.expect === 'review';
  if (positive && flagged) tp += 1;
  else if (!positive && flagged) fp += 1;
  else if (positive && !flagged) fn += 1;
  else tn += 1;
  const ok = result.decision === sample.expect;
  rows.push({ id: sample.id, expect: sample.expect, got: result.decision, ok });
  if (!ok) failures.push(sample.id + ': expected ' + sample.expect + ', got ' + result.decision + ' (' + sample.note + ')');
}

const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
const recall = tp + fn > 0 ? tp / (tp + fn) : 1;
const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
const accuracy = (tp + tn) / Math.max(1, rows.length);

console.log('=== dsh-secure-audit rule-engine eval ===');
console.log('samples: ' + rows.length + ' (positive ' + (tp + fn) + ', negative ' + (tn + fp) + ')');
console.log('TP ' + tp + '  FP ' + fp + '  FN ' + fn + '  TN ' + tn);
console.log('precision ' + precision.toFixed(3) + '  recall ' + recall.toFixed(3) + '  F1 ' + f1.toFixed(3) + '  accuracy ' + accuracy.toFixed(3));
for (const row of rows) {
  console.log('  ' + (row.ok ? 'OK ' : 'BAD') + ' ' + row.id.padEnd(22) + ' expect=' + row.expect.padEnd(6) + ' got=' + row.got.padEnd(6));
}

if (failures.length > 0) {
  console.error('eval: ' + failures.length + ' regression(s):');
  for (const f of failures) console.error('  ' + f);
  process.exit(1);
}
console.log('eval: all pinned expectations hold');
