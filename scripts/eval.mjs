/**
 * Detection-quality evaluation for the injection rule engine.
 *
 * Runs the corpus in tests/fixtures/adversarial-samples.js and reports:
 * - precision / recall / F1 / accuracy over attack vs benign samples;
 * - false-positive rate (benign flagged) and false-negative rate (attack
 *   missed), overall and per language;
 * - p50 / p95 scan latency, plus a long-text cohort.
 *
 * A sample whose decision differs from its pinned expectation fails the run
 * (exit 1). Aggregate FP/FN thresholds are a backstop: CI runs this after
 * `npm test` so rule changes are measured, not just tested.
 *
 * Usage: `node scripts/eval.mjs` (CI: `npm run eval`).
 */

import { createInjectionScanner } from '../lib/injection.js';
import { ADVERSARIAL_SAMPLES } from '../tests/fixtures/adversarial-samples.js';

const MAX_FP_RATE = 0.15;
const MAX_FN_RATE = 0.2;

const scanner = createInjectionScanner({ timeoutMs: 2000 });

const rows = [];
for (const sample of ADVERSARIAL_SAMPLES) {
  const result = await scanner.scan(sample.text);
  rows.push({
    ...sample,
    got: result.decision,
    flagged: result.decision !== 'allow',
    elapsedMs: result.elapsedMs,
    scanComplete: result.scanComplete,
  });
}

function metricsFor(subset) {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  for (const row of subset) {
    if (row.kind === 'attack' && row.flagged) tp += 1;
    else if (row.kind === 'attack') fn += 1;
    else if (row.flagged) fp += 1;
    else tn += 1;
  }
  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  return {
    tp,
    fp,
    fn,
    tn,
    precision,
    recall,
    f1,
    accuracy: (tp + tn) / Math.max(1, subset.length),
    fpRate: fp + tn > 0 ? fp / (fp + tn) : 0,
    fnRate: tp + fn > 0 ? fn / (tp + fn) : 0,
  };
}

/** Nearest-rank percentile. */
function percentile(values, p) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[index];
}

const pct = (value) => `${(value * 100).toFixed(1)}%`;
const failures = [];
const mismatches = rows.filter((row) => row.got !== row.expect);
for (const row of mismatches) {
  failures.push(`${row.id}: expected ${row.expect}, got ${row.got} (${row.note})`);
}
for (const row of rows) {
  if (row.tags?.includes('long') && !row.scanComplete) {
    failures.push(`${row.id}: long sample was not fully scanned (scanComplete=false)`);
  }
}

const overall = metricsFor(rows);
const byLang = {
  en: metricsFor(rows.filter((row) => row.lang === 'en')),
  zh: metricsFor(rows.filter((row) => row.lang === 'zh')),
};
const longRows = rows.filter((row) => row.tags?.includes('long'));
const latencies = rows.map((row) => row.elapsedMs);
const longLatencies = longRows.map((row) => row.elapsedMs);
const attacks = rows.filter((row) => row.kind === 'attack').length;
const benign = rows.length - attacks;
const accepted = rows.filter((row) => row.acceptedFalsePositive);

if (overall.fpRate > MAX_FP_RATE) {
  failures.push(`false-positive rate ${pct(overall.fpRate)} exceeds the ${pct(MAX_FP_RATE)} cap`);
}
if (overall.fnRate > MAX_FN_RATE) {
  failures.push(`false-negative rate ${pct(overall.fnRate)} exceeds the ${pct(MAX_FN_RATE)} cap`);
}

function summaryLine(label, m) {
  return `${label} attack ${m.tp}/${m.tp + m.fn} flagged, benign ${m.fp}/${m.fp + m.tn} flagged, F1 ${m.f1.toFixed(3)}`;
}

console.log('=== dsh-secure-audit rule-engine eval ===');
console.log(`samples: ${rows.length} (attack ${attacks}, benign ${benign}; en ${byLang.en.tp + byLang.en.fp + byLang.en.fn + byLang.en.tn}, zh ${byLang.zh.tp + byLang.zh.fp + byLang.zh.fn + byLang.zh.tn})`);
console.log(`TP ${overall.tp}  FP ${overall.fp}  FN ${overall.fn}  TN ${overall.tn}`);
console.log(`precision ${overall.precision.toFixed(3)}  recall ${overall.recall.toFixed(3)}  F1 ${overall.f1.toFixed(3)}  accuracy ${overall.accuracy.toFixed(3)}`);
console.log(`false-positive rate ${pct(overall.fpRate)} (${overall.fp}/${overall.fp + overall.tn} benign flagged)  false-negative rate ${pct(overall.fnRate)} (${overall.fn}/${overall.fn + overall.tp} attacks missed)`);
console.log(`by language: ${summaryLine('en', byLang.en)} | ${summaryLine('zh', byLang.zh)}`);
console.log(`latency: p50 ${percentile(latencies, 50)}ms  p95 ${percentile(latencies, 95)}ms  (n=${latencies.length})`);
console.log(`long text: p50 ${percentile(longLatencies, 50)}ms  p95 ${percentile(longLatencies, 95)}ms  (n=${longLatencies.length})`);
if (accepted.length > 0) {
  console.log(`accepted false positives (${accepted.length}, counted in the FP rate): ${accepted.map((row) => row.id).join(', ')}`);
}
console.log('--- per sample ---');
for (const row of rows) {
  const ok = row.got === row.expect;
  console.log(`  ${ok ? 'OK ' : 'BAD'} ${row.id.padEnd(38)} ${row.lang} ${row.kind.padEnd(6)} expect=${row.expect.padEnd(6)} got=${row.got.padEnd(6)} ${row.elapsedMs}ms`);
}

if (failures.length > 0) {
  console.error(`eval: ${failures.length} failure(s):`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log('eval: all pinned expectations hold');
