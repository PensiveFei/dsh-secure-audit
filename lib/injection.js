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

// ---------------------------------------------------------------------------
// Obfuscation-resistance layer (ruleset v4):
// The rule table is plain-text patterns, so attackers try to dodge it with
// zero-width characters, full-width / Cyrillic homoglyphs, or base64-encoded
// payloads. The scanner therefore scans up to VARIANT_CAP derived texts per
// call — the raw subject, a normalized (zero-width stripped, lookalike mapped
// to ASCII) copy, and a bounded number of base64-decoded candidates. Hits are
// merged per distinct rule id (first variant wins), so scoring stays on
// distinct rules and the budget still bounds total work. Snippets for
// normalized/base64 hits show the derived text; `via` labels the channel.
// ---------------------------------------------------------------------------
const VARIANT_CAP = 4;
const MAX_BASE64_TOKENS = 4;
const MAX_BASE64_LEN = 4096;

/** Lookalike letters (Cyrillic + Greek omicron) mapped to their ASCII twin. */
const HOMOGLYPH_MAP = Object.freeze({
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y', і: 'i', ο: 'o',
});
const NEEDS_NORMALIZE_RE = /[\u200b-\u200d\u2060\ufeff\uff01-\uff5eаеорсхуіο]/;

/**
 * Strip zero-width characters and map full-width / lookalike letters to
 * ASCII so obfuscated spellings still match the rule table. Returns the
 * input unchanged when no normalization is needed (fast path).
 */
function normalizeForScan(text) {
  if (!NEEDS_NORMALIZE_RE.test(text)) return text;
  let out = text.replace(/[\u200b-\u200d\u2060\ufeff]/g, '');
  out = out.replace(/[\uff01-\uff5e]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 0xfee0));
  out = out.replace(/[аеорсхуіο]/g, (ch) => HOMOGLYPH_MAP[ch]);
  return out;
}

/**
 * Bounded base64 decoding of candidate tokens from the subject. Only tokens
 * that decode to mostly-printable text of at least 8 chars are kept, so
 * random alphanumeric runs (order numbers, hashes) are rejected by the
 * printable gate and never enter the scan loop.
 */
function tryDecodeBase64(token) {
  if (token.length < 16 || token.length > MAX_BASE64_LEN) return null;
  let decoded;
  try {
    decoded = Buffer.from(token, 'base64').toString('utf8');
  } catch {
    return null;
  }
  if (decoded.length < 8) return null;
  let printable = 0;
  for (const ch of decoded) {
    const c = ch.codePointAt(0);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable += 1;
  }
  return printable / decoded.length >= 0.8 ? decoded : null;
}

/**
 * Extract bounded base64-decoded candidates. A fresh regex per call keeps
 * the shared-lastIndex hazard out of concurrent scans (isConcurrencySafe).
 */
function base64Candidates(subject) {
  const re = /[A-Za-z0-9+/]{16,}={0,2}/g;
  const out = [];
  let m;
  while ((m = re.exec(subject)) !== null && out.length < MAX_BASE64_TOKENS) {
    const decoded = tryDecodeBase64(m[0]);
    if (decoded !== null && decoded !== m[0]) out.push(decoded);
  }
  return out;
}

/**
 * Build the bounded set of texts to scan: raw, normalized, base64-decoded.
 */
function buildVariants(subject) {
  const variants = [{ text: subject, via: 'plain' }];
  const normalized = normalizeForScan(subject);
  if (normalized !== subject) variants.push({ text: normalized, via: 'normalized' });
  for (const decoded of base64Candidates(subject)) {
    if (variants.length >= VARIANT_CAP) break;
    variants.push({ text: decoded, via: 'base64' });
  }
  return variants;
}

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
   * @param {string} subject text to scan (raw, normalized, or base64-decoded)
   * @param {number} scanStart wall-clock budget start
   * @param {string} via 'plain' | 'normalized' | 'base64' — which derived text
   *   produced the hit (snippet shows that text)
   * @returns {{reasons: object[], allowlistedHits: object[], score: number,
   *            confidence: number, anyCritical: boolean, budgetExceeded: boolean}}
   */
  function ruleScan(subject, scanStart, via = 'plain') {
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
          via,
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
    // Obfuscation-resistance pass: scan the raw text plus normalized and
    // base64-decoded variants. Hits are merged per distinct rule id (first
    // variant wins); a critical hit or the budget stops further variants,
    // matching the original early-break semantics at bounded cost.
    const byRule = new Map();
    const allowlistedById = new Map();
    let anyCritical = false;
    let budgetExceeded = false;
    for (const variant of buildVariants(subject)) {
      if (budgetExceeded || anyCritical) break;
      const pass = ruleScan(variant.text, scanStart, variant.via);
      if (pass.budgetExceeded) budgetExceeded = true;
      if (pass.anyCritical) anyCritical = true;
      for (const h of pass.reasons) if (!byRule.has(h.ruleId)) byRule.set(h.ruleId, h);
      for (const h of pass.allowlistedHits) if (!allowlistedById.has(h.ruleId)) allowlistedById.set(h.ruleId, h);
    }
    const reasons = [...byRule.values()];
    const allowlistedHits = [...allowlistedById.values()];
    let score = 0;
    for (const r of reasons) score += SEVERITY_WEIGHT[r.severity] ?? 0.4;
    const ruleConfidence = anyCritical ? Math.min(1, Math.max(score, 0.9)) : Math.min(1, score);

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
