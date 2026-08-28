/**
 * Prompt-injection detection engine (rule-first, model-optional).
 *
 * Design (see docs/architecture.md):
 * - RULE LAYER: a compiled rule table runs first — fast, deterministic,
 *   cheap. Confidence = severity-weighted score of distinct rule hits.
 * - MODEL LAYER: an optional pluggable classifier
 *   (`{ classify(text, context) => Promise<{decision?, confidence?}> }`)
 *   runs only when the rule layer is inconclusive (decision === "review" and
 *   no critical hit). Its failure degrades to the rule decision, never
 *   raises an error to the caller.
 * - PERFORMANCE: an LRU cache keyed by SHA-256(text)+ruleset version avoids
 *   re-scanning identical inputs; a cooperative budget bails out to
 *   "allow" with a warning when the scan exceeds `timeoutMs` (fail-open per
 *   the product spec — security features must never become availability
 *   killers); input length is hard-capped.
 *
 * Pure module apart from `node:crypto`: unit-testable standalone.
 */

import { createHash } from 'node:crypto';
import { INJECTION_RULES, SEVERITY_WEIGHT, RULESET_VERSION } from './rules.js';
import { redactText } from './redact.js';

export const DECISIONS = Object.freeze(['allow', 'review', 'block']);

const DEFAULT_OPTIONS = Object.freeze({
  cacheSize: 512,
  timeoutMs: 100,
  maxLength: 200_000,
  blockThreshold: 0.8,
  reviewThreshold: 0.5,
  classifierTimeoutMs: 2_000,
  allowlist: [],
  maskChar: '*',
  /** Policy when the cooperative budget expires before the rule pass finishes:
   * 'allow' (fail-open, default, backwards compatible), 'review', or 'block'
   * (fail-closed for sensitive flows). The decision is forced and a warning
   * explains why; reasons are dropped because the scan was incomplete. */
  onTimeout: 'allow',
});

/** Per-rule match cap: bounds worst-case output size, not scan cost. */
const MAX_MATCHES_PER_RULE = 20;
/** Snippet window around the first match, before masking + trimming. */
const SNIPPET_RADIUS = 30;
const SNIPPET_MAX = 100;

function clamp(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function cacheKey(text) {
  return createHash('sha256').update(`${RULESET_VERSION}\u0000${text}`).digest('hex');
}

/** Map a rule severity to a risk level (severity-based, conservative). */
const SEV_TO_RISK = Object.freeze({
  critical: 'high',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'low',
});

const RISK_ORDER = Object.freeze({ low: 0, medium: 1, high: 2 });

/**
 * Derive a coarse risk level (low/medium/high) from the rule hits plus the
 * final confidence: the highest rule severity sets a floor, then the decision
 * band escalates it. Consumers (policies, auto-approvers) can route on this
 * instead of interpreting raw confidence.
 * @param {{severity: string}[]} reasons rule hits (post-allowlist)
 * @param {number} confidence final 0..1 confidence
 * @param {number} blockThreshold
 * @param {number} reviewThreshold
 * @returns {'low'|'medium'|'high'}
 */
function riskLevelOf(reasons, confidence, blockThreshold, reviewThreshold) {
  let level = 'low';
  for (const r of reasons) {
    const lv = SEV_TO_RISK[r.severity] ?? 'low';
    if (RISK_ORDER[lv] > RISK_ORDER[level]) level = lv;
  }
  if (confidence >= blockThreshold) level = 'high';
  else if (confidence >= reviewThreshold && RISK_ORDER[level] < RISK_ORDER.medium) level = 'medium';
  return level;
}

function snippetOf(subject, index, matched, maskChar) {
  const start = Math.max(0, index - SNIPPET_RADIUS);
  const end = Math.min(subject.length, index + matched.length + SNIPPET_RADIUS);
  let raw = subject.slice(start, end);
  // collapse control characters and newlines to a single printable line
  raw = raw.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  const redacted = redactText(raw, { maskChar }).redacted;
  return redacted.length > SNIPPET_MAX ? redacted.slice(0, SNIPPET_MAX) + '…' : redacted;
}

/**
 * Create an injection scanner.
 * @param {object} [options]
 * @param {number} [options.cacheSize=512]
 * @param {number} [options.timeoutMs=100] cooperative budget; on expiry the
 *   scan stops and returns "allow" with a warning
 * @param {number} [options.maxLength=200000]
 * @param {number} [options.blockThreshold=0.8]
 * @param {number} [options.reviewThreshold=0.5]
 * @param {string[]} [options.allowlist=[]] rule ids always treated as benign
 *   (documented as the fast appeal channel)
 * @param {object|null} [options.classifier=null] pluggable model classifier
 * @param {number} [options.classifierTimeoutMs=2000]
 * @param {string} [options.maskChar='*']
 * @returns {{scan: Function, clearCache: Function, stats: Function, ruleset: Function}}
 */
export function createInjectionScanner(userOptions = {}) {
  const options = { ...DEFAULT_OPTIONS, ...userOptions };
  options.blockThreshold = clamp(options.blockThreshold, 0, 1, DEFAULT_OPTIONS.blockThreshold);
  options.reviewThreshold = clamp(options.reviewThreshold, 0, 1, DEFAULT_OPTIONS.reviewThreshold);
  if (options.reviewThreshold >= options.blockThreshold) {
    options.reviewThreshold = Math.max(0, options.blockThreshold - 0.001);
  }
  options.cacheSize = Math.trunc(clamp(options.cacheSize, 1, 10_000, DEFAULT_OPTIONS.cacheSize));
  options.timeoutMs = Math.trunc(clamp(options.timeoutMs, 1, 60_000, DEFAULT_OPTIONS.timeoutMs));
  options.maxLength = Math.trunc(clamp(options.maxLength, 100, 10_000_000, DEFAULT_OPTIONS.maxLength));
  options.classifierTimeoutMs = Math.trunc(clamp(options.classifierTimeoutMs, 100, 30_000, DEFAULT_OPTIONS.classifierTimeoutMs));
  options.onTimeout = DECISIONS.includes(options.onTimeout) ? options.onTimeout : DEFAULT_OPTIONS.onTimeout;

  // Each rule gets a global clone up front. `String#matchAll` builds its
  // own per-call clone with lastIndex = 0 internally, so the shared object is
  // never mutated — the scan loop must not rebuild a RegExp per rule per call,
  // and concurrent scans (isConcurrencySafe: true) cannot corrupt each other.
  const compiled = INJECTION_RULES.map((rule) => ({
    ...rule,
    re: new RegExp(rule.pattern, 'i'),
    reG: new RegExp(rule.pattern, 'ig'),
  }));
  const allowlist = new Set(options.allowlist ?? []);

  /** @type {Map<string, object>} simple LRU */
  const cache = new Map();
  let hits = 0;
  let misses = 0;

  function evict() {
    if (cache.size >= options.cacheSize) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
  }

  /**
   * Single cooperative pass over the rule table.
   * @returns {{reasons: object[], allowlistedHits: object[], score: number,
   *            confidence: number, anyCritical: boolean, budgetExceeded: boolean}}
   */
  function ruleScan(subject, scanStart) {
    const reasons = [];
    const allowlistedHits = [];
    let score = 0;
    let anyCritical = false;
    let budgetExceeded = false;

    for (const rule of compiled) {
      let matches = 0;
      let firstIndex = -1;
      let firstMatch = '';
      // matchAll clones the regex per call with a fresh lastIndex and handles
      // zero-width matches internally, so the loop is allocation-light and
      // safe to run concurrently against the shared `reG`.
      for (const m of subject.matchAll(rule.reG)) {
        if (firstIndex === -1) {
          firstIndex = m.index;
          firstMatch = m[0];
        }
        matches += 1;
        if (matches >= MAX_MATCHES_PER_RULE) break;
      }
      if (matches > 0) {
        const hit = {
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          action: rule.action,
          description: rule.description,
          matches,
          snippet: snippetOf(subject, firstIndex, firstMatch, options.maskChar),
        };
        if (allowlist.has(rule.id)) {
          allowlistedHits.push(hit);
          continue;
        }
        score += SEVERITY_WEIGHT[rule.severity] ?? 0.4;
        if (rule.severity === 'critical') anyCritical = true;
        reasons.push(hit);
      }
      if (anyCritical) break; // critical hit: no need to keep scoring
      if (Date.now() - scanStart > options.timeoutMs) {
        budgetExceeded = true;
        break;
      }
    }

    const confidence = anyCritical
      ? Math.min(1, Math.max(score, 0.9))
      : Math.min(1, score);
    return { reasons, allowlistedHits, score, confidence, anyCritical, budgetExceeded };
  }

  async function runClassifier(subject, context, warnings) {
    const classifier = options.classifier;
    if (!classifier || typeof classifier.classify !== 'function') return null;
    let timer;
    try {
      const verdict = await Promise.race([
        Promise.resolve(classifier.classify(subject, context)),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('classifier timeout')), options.classifierTimeoutMs);
        }),
      ]);
      return verdict ?? null;
    } catch (err) {
      warnings.push(`model classifier unavailable (${err?.name ?? 'error'}); using rule decision`);
      return null;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * Scan text for injection attempts.
   * @param {string} text
   * @param {object} [context] optional {requestId, forceClassifier}
   * @returns {Promise<object>} decision payload (see README for the shape)
   */
  async function scan(text, context = {}) {
    if (typeof text !== 'string') {
      throw new TypeError('scan: text must be a string');
    }
    const started = Date.now();
    const warnings = [];
    let truncated = false;
    let subject = text;
    if (text.length > options.maxLength) {
      subject = text.slice(0, options.maxLength);
      truncated = true;
      warnings.push(`input truncated to ${options.maxLength} characters`);
    }

    const key = cacheKey(subject);
    const cached = cache.get(key);
    if (cached !== undefined) {
      hits += 1;
      cache.delete(key);
      cache.set(key, cached);
      return { ...cached, cacheHit: true };
    }
    misses += 1;

    const scanStart = Date.now();
    const { reasons, allowlistedHits, confidence: ruleConfidence, anyCritical, budgetExceeded } =
      ruleScan(subject, scanStart);

    if (budgetExceeded) {
      const mode = options.onTimeout === 'allow' ? 'fail-open' : 'fail-closed';
      warnings.push(
        `scan budget exceeded (${options.timeoutMs}ms); remaining rules were skipped and the decision was set to "${options.onTimeout}" by policy (${mode})`,
      );
    }
    let reasonsOut = reasons;
    let confidence = ruleConfidence;

    let decision = confidence >= options.blockThreshold
      ? 'block'
      : confidence >= options.reviewThreshold
        ? 'review'
        : 'allow';

    let classifierUsed = false;
    if (budgetExceeded) {
      // Incomplete scan: reasons are untrustworthy, so they are dropped. The
      // decision follows the configured timeout policy (default fail-open
      // 'allow'; 'review'/'block' are the fail-closed options). Confidence is
      // 0 because the scan did not finish — the warning carries the meaning.
      decision = options.onTimeout;
      confidence = 0;
      reasonsOut = [];
    } else if (options.classifier && decision === 'review' && !anyCritical) {
      const verdict = await runClassifier(subject, context, warnings);
      if (verdict) {
        classifierUsed = true;
        if (typeof verdict.confidence === 'number' && verdict.confidence >= 0 && verdict.confidence <= 1) {
          confidence = verdict.confidence;
        }
        if (typeof verdict.decision === 'string' && DECISIONS.includes(verdict.decision)) {
          decision = verdict.decision;
        }
      }
    }

    const result = {
      decision,
      confidence: Number(confidence.toFixed(3)),
      riskLevel: budgetExceeded
        ? (options.onTimeout === 'block' ? 'high' : options.onTimeout === 'review' ? 'medium' : 'low')
        : riskLevelOf(reasonsOut, confidence, options.blockThreshold, options.reviewThreshold),
      reasons: reasonsOut,
      allowlistedHits,
      // Plain SHA-256 of the scanned subject (post-truncation): lets any
      // consumer locally replay the decision from the exact bytes scanned.
      inputSha256: createHash('sha256').update(subject).digest('hex'),
      elapsedMs: Date.now() - started,
      cacheHit: false,
      truncated,
      warnings,
      classifierUsed,
      // Length of the text actually scanned (post-truncation), consistent
      // with inputSha256 above.
      scannedLength: subject.length,
      ruleset: RULESET_VERSION,
    };
    evict();
    cache.set(key, result);
    return result;
  }

  return {
    scan,
    clearCache() {
      cache.clear();
    },
    stats() {
      return { size: cache.size, hits, misses };
    },
    ruleset() {
      return {
        version: RULESET_VERSION,
        count: compiled.length,
        ids: compiled.map((rule) => rule.id),
      };
    },
  };
}

/** One-shot convenience scanner with defaults. */
export function scanForInjection(text, options = {}, context = {}) {
  const scanner = createInjectionScanner(options);
  return scanner.scan(text, context);
}
