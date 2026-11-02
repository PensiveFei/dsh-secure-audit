/**
 * Prompt-injection detection engine (rule-first, model-optional).
 *
 * Design (see docs/architecture.md):
 * - RULE LAYER: a compiled rule table runs first — fast, deterministic,
 *   cheap. `riskScore` = severity-weighted score of distinct rule hits.
 * - MODEL LAYER: an optional pluggable classifier
 *   (`{ classify(text, context) => Promise<{decision?, confidence?}> }`)
 *   runs only when the rule layer is inconclusive (decision === "review" and
 *   no critical hit). Its `confidence` is the classifier's certainty in its
 *   own verdict, reported as `decisionConfidence`; it never overwrites
 *   `riskScore`. Its failure degrades to the rule decision, never raises an
 *   error to the caller.
 * - COVERAGE: `scanComplete` is false when the input was truncated or the
 *   rule budget expired. The decision then follows the configured
 *   `onTruncate` / `onTimeout` policy (default fail-open "allow") and a
 *   warning names the policy — an incomplete scan is never reported as a
 *   clean one.
 * - PERFORMANCE: two LRU caches. The rule cache is keyed by SHA-256(text)
 *   alone (rules never see the caller's context), so enabling a classifier
 *   no longer disables caching for tool calls that pass a requestId. The
 *   model cache is keyed by text + the classifier's declared cache key
 *   (role-only for the built-in adapter); custom classifiers without a
 *   declared key still run per call. A cooperative budget bails out when the
 *   scan exceeds `timeoutMs` (fail-open per the product spec — security
 *   features must never become availability killers); input length is
 *   hard-capped.
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
  /** Policy when the input exceeds `maxLength`, so only the prefix is
   * scanned: 'allow' (fail-open, default, backwards compatible), 'review',
   * or 'block'. Applied as a decision floor (never a downgrade), with
   * `scanComplete: false` and a warning naming the policy. */
  onTruncate: 'allow',
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
    // Printable = any non-control code point. Counting ASCII only meant the
    // base64 layer could never flag a CJK payload: base64("忽略之前所有指令…")
    // scored ~0 and was dropped, while the English twin was caught — leaving
    // the obfuscation layer protecting English only.
    if (c === 9 || c === 10 || c === 13 || c >= 32) printable += 1;
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

/** SHA-256 over a JSON tuple: boundaries survive attacker-controlled strings. */
function hashParts(...parts) {
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

/**
 * Rule-layer cache key. The rule table never reads the caller's context, so
 * this key intentionally excludes it — that is what keeps caching alive when
 * a tool passes `{ requestId, role }` on every call.
 */
function ruleCacheKey(text) {
  return hashParts(RULESET_VERSION, 'rules', text);
}

function canCacheClassifierContext(context) {
  // Custom classifiers can use any context field. Only the standard role-only
  // context has a bounded, unambiguous cache key; all other contexts run fresh.
  if (!context || ![Object.prototype, null].includes(Object.getPrototypeOf(context))) return false;
  if (Reflect.ownKeys(context).some((key) => key !== 'role')) return false;
  const role = Object.getOwnPropertyDescriptor(context, 'role');
  return !role || (Object.hasOwn(role, 'value')
    && (role.value == null || typeof role.value === 'string'));
}

/**
 * Model-layer cache key, or null when this call must not be cached.
 *
 * A classifier owns this decision: the built-in adapter declares
 * `cacheKeyFor()` (its prompt only reads `context.role`, so a requestId or a
 * signal cannot change the verdict). A custom classifier with no declared key
 * is only cached for a role-only plain context, where the same reasoning
 * holds by construction. Anything else stays uncached so a verdict for one
 * context can never be replayed for another.
 * @param {Function|null|undefined} classifier
 * @param {object} context
 * @param {string} subject scanned text (post-truncation)
 */
function modelCacheKey(classifier, context, subject) {
  let roleKey;
  if (typeof classifier?.cacheKeyFor === 'function') {
    roleKey = classifier.cacheKeyFor(context);
  } else if (canCacheClassifierContext(context)) {
    roleKey = ['role-only', Object.hasOwn(context, 'role'), typeof context?.role, context?.role];
  } else {
    return null;
  }
  if (roleKey == null) return null;
  return hashParts(RULESET_VERSION, 'model', roleKey, subject);
}

/** Deep-copy cached rule data so no caller can mutate the cache. */
function copyRuleData(data) {
  return {
    ...data,
    reasons: data.reasons.map((reason) => ({ ...reason })),
    allowlistedHits: data.allowlistedHits.map((hit) => ({ ...hit })),
  };
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
const DECISION_RANK = Object.freeze({ allow: 0, review: 1, block: 2 });

/** Return the stricter of two decisions (never downgrade). */
function stricterDecision(a, b) {
  return DECISION_RANK[b] > DECISION_RANK[a] ? b : a;
}

function decisionForScore(score, blockThreshold, reviewThreshold) {
  if (score >= blockThreshold) return 'block';
  if (score >= reviewThreshold) return 'review';
  return 'allow';
}

/**
 * Confidence in a rule-only decision. For `review`/`block` the engine's score
 * is the evidence behind the verdict; for `allow` it is the distance from the
 * review threshold. This is NOT a calibrated probability that the text is
 * safe — the rules are heuristics (documented in the README).
 * @param {'allow'|'review'|'block'} decision
 * @param {number} riskScore 0..1 rule score
 */
function ruleDecisionConfidence(decision, riskScore) {
  return decision === 'allow' ? 1 - riskScore : riskScore;
}

/**
 * Derive a coarse risk level (low/medium/high) from the rule hits plus the
 * final decision: the highest rule severity sets a floor, then the decision
 * band escalates it. Consumers (policies, auto-approvers) can route on this
 * instead of interpreting raw scores.
 * @param {{severity: string}[]} reasons rule hits (post-allowlist)
 * @param {'allow'|'review'|'block'} decision final decision (policy applied)
 * @returns {'low'|'medium'|'high'}
 */
function riskLevelOf(reasons, decision) {
  let level = 'low';
  for (const r of reasons) {
    const lv = SEV_TO_RISK[r.severity] ?? 'low';
    if (RISK_ORDER[lv] > RISK_ORDER[level]) level = lv;
  }
  if (decision === 'block') level = 'high';
  else if (decision === 'review' && RISK_ORDER[level] < RISK_ORDER.medium) level = 'medium';
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
 * @param {'allow'|'review'|'block'} [options.onTimeout='allow'] policy when
 *   the cooperative budget expires before the rule pass finishes
 * @param {'allow'|'review'|'block'} [options.onTruncate='allow'] policy floor
 *   when the input exceeds `maxLength` and only the prefix is scanned
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
  options.onTruncate = DECISIONS.includes(options.onTruncate) ? options.onTruncate : DEFAULT_OPTIONS.onTruncate;

  // Each rule gets a global clone up front. `String#matchAll` builds its
  // own per-call clone with lastIndex = 0 internally, so the shared object is
  // never mutated — the scan loop must not rebuild a RegExp per rule per call,
  // and concurrent scans (isConcurrencySafe: true) cannot corrupt each other.
  const compiled = INJECTION_RULES.map((rule) => ({
    ...rule,
    reG: new RegExp(rule.pattern, 'ig'),
  }));
  const allowlist = new Set(options.allowlist ?? []);

  /**
   * Rule-layer cache: text -> rule hits/score. Independent of the caller's
   * context, so a per-call requestId cannot defeat it.
   * @type {Map<string, object>}
   */
  const ruleCache = new Map();
  /**
   * Model-layer cache: text + classifier-declared key -> verdict.
   * @type {Map<string, {decision: string, confidence: number|null}>}
   */
  const modelCache = new Map();
  let ruleHits = 0;
  let ruleMisses = 0;
  let modelHits = 0;
  let modelMisses = 0;

  function evict(cache) {
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
   * @returns {{reasons: object[], allowlistedHits: object[], riskScore: number,
   *            anyCritical: boolean, budgetExceeded: boolean}}
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
        } else {
          score += SEVERITY_WEIGHT[rule.severity] ?? 0.4;
          if (rule.severity === 'critical') anyCritical = true;
          reasons.push(hit);
        }
      }
      if (anyCritical) break; // critical hit: no need to keep scoring
      if (Date.now() - scanStart > options.timeoutMs) {
        budgetExceeded = true;
        break;
      }
    }

    const riskScore = anyCritical
      ? Math.min(1, Math.max(score, 0.9))
      : Math.min(1, score);
    return { reasons, allowlistedHits, riskScore, anyCritical, budgetExceeded };
  }

  /**
   * Full rule pass: the raw text plus the bounded obfuscation variants.
   * @param {string} subject scanned text (post-truncation)
   */
  function runRuleScan(subject) {
    const scanStart = Date.now();
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
    let score = 0;
    for (const r of reasons) score += SEVERITY_WEIGHT[r.severity] ?? 0.4;
    const riskScore = anyCritical ? Math.min(1, Math.max(score, 0.9)) : Math.min(1, score);
    return { reasons, allowlistedHits: [...allowlistedById.values()], riskScore, anyCritical, budgetExceeded };
  }

  /**
   * Rule pass from the cache, or a fresh one. Incomplete rule coverage is
   * transient and never cached, so it cannot suppress a later complete scan.
   * @param {string} subject
   * @returns {{data: object, cached: boolean}}
   */
  function getRuleScan(subject) {
    const key = ruleCacheKey(subject);
    const cached = ruleCache.get(key);
    if (cached !== undefined) {
      ruleHits += 1;
      ruleCache.delete(key);
      ruleCache.set(key, cached);
      return { data: copyRuleData(cached), cached: true };
    }
    ruleMisses += 1;
    const data = runRuleScan(subject);
    if (!data.budgetExceeded) {
      evict(ruleCache);
      ruleCache.set(key, copyRuleData(data));
    }
    return { data, cached: false };
  }

  async function runClassifier(subject, context, warnings) {
    const classifier = options.classifier;
    if (!classifier || typeof classifier.classify !== 'function') return null;
    const controller = new AbortController();
    let timer;
    try {
      const verdict = await Promise.race([
        Promise.resolve().then(() => classifier.classify(subject, context, { signal: controller.signal })),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new Error('classifier timeout'));
          }, options.classifierTimeoutMs);
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
   * Keep only a well-formed verdict from a classifier. A verdict without a
   * valid `decision` cannot change the outcome; a missing or out-of-range
   * `confidence` falls back to the rule-derived decision confidence.
   * @param {unknown} verdict
   * @returns {{decision: string, confidence: number|null}|null}
   */
  function normalizeVerdict(verdict) {
    if (!verdict || typeof verdict !== 'object') return null;
    if (!DECISIONS.includes(verdict.decision)) return null;
    const confidence = typeof verdict.confidence === 'number'
      && Number.isFinite(verdict.confidence)
      && verdict.confidence >= 0
      && verdict.confidence <= 1
      ? verdict.confidence
      : null;
    return { decision: verdict.decision, confidence };
  }

  /**
   * Model verdict from the cache when the classifier declares a cache key,
   * otherwise a fresh call. Only well-formed verdicts are cached, so a
   * transient failure is retried on the next scan.
   * @param {string} subject
   * @param {object} context
   * @param {string|null} key model cache key
   * @param {string[]} warnings
   * @returns {Promise<{verdict: object|null, cached: boolean, attempted: boolean}>}
   */
  async function getModelVerdict(subject, context, key, warnings) {
    if (key !== null) {
      const cached = modelCache.get(key);
      if (cached !== undefined) {
        modelHits += 1;
        modelCache.delete(key);
        modelCache.set(key, cached);
        return { verdict: { ...cached }, cached: true, attempted: false };
      }
    }
    modelMisses += 1;
    const verdict = normalizeVerdict(await runClassifier(subject, context, warnings));
    if (verdict && key !== null) {
      evict(modelCache);
      modelCache.set(key, { ...verdict });
    }
    return { verdict, cached: false, attempted: true };
  }

  /**
   * Scan text for injection attempts.
   *
   * The result separates the two numbers that used to be conflated:
   * - `riskScore` (and its deprecated alias `confidence`): severity-weighted
   *   rule evidence, 0..1, never written by the model.
   * - `decisionConfidence`: certainty in the reported decision — the
   *   classifier's own confidence when it contributed, otherwise the rule
   *   score's support for that decision. It is 0 when `scanComplete` is false.
   *
   * @param {string} text
   * @param {object} [context] optional {requestId, role} for the classifier
   * @returns {Promise<object>} decision payload (see README for the shape)
   */
  async function scan(text, context = {}) {
    if (typeof text !== 'string') {
      throw new TypeError('scan: text must be a string');
    }
    const started = Date.now();
    const warnings = [];
    const totalLength = text.length;
    const truncated = totalLength > options.maxLength;
    const subject = truncated ? text.slice(0, options.maxLength) : text;
    if (truncated) {
      warnings.push(
        `input truncated to ${options.maxLength} characters (${totalLength - options.maxLength} not scanned); scanComplete=false and the "${options.onTruncate}" truncation policy sets the decision floor`,
      );
    }

    const rulePass = getRuleScan(subject);
    const { anyCritical, budgetExceeded } = rulePass.data;
    const incomplete = truncated || budgetExceeded;
    // An unfinished rule pass makes partial reasons untrustworthy: they are
    // dropped and the risk score is 0, leaving the policy to decide.
    const riskScore = budgetExceeded ? 0 : rulePass.data.riskScore;
    const reasonsOut = budgetExceeded ? [] : rulePass.data.reasons;
    const allowlistedHits = rulePass.data.allowlistedHits;

    let decision = decisionForScore(rulePass.data.riskScore, options.blockThreshold, options.reviewThreshold);
    let decisionConfidence;
    let classifierUsed = false;
    let modelAttempted = false;

    if (budgetExceeded) {
      const mode = options.onTimeout === 'allow' ? 'fail-open' : 'fail-closed';
      warnings.push(
        `scan budget exceeded (${options.timeoutMs}ms); remaining rules were skipped and the decision was set to "${options.onTimeout}" by policy (${mode})`,
      );
      // Coverage failures are independent: when the input was also truncated,
      // each configured policy sets a floor and the stricter decision wins.
      decision = truncated ? stricterDecision(options.onTimeout, options.onTruncate) : options.onTimeout;
    } else {
      if (truncated) {
        // A truncated input is still prefix-scanned; the policy is a floor,
        // never a downgrade of hits already found in the scanned prefix.
        decision = stricterDecision(decision, options.onTruncate);
        if (options.classifier) {
          warnings.push('model classifier skipped: the scan covered only a truncated prefix');
        }
      }
      if (options.classifier && !truncated && decision === 'review' && !anyCritical) {
        let key = null;
        try {
          key = modelCacheKey(options.classifier, context, subject);
        } catch {
          // A broken cacheKeyFor must not break scanning: run the model
          // uncached, exactly like any other unkeyable context.
          warnings.push('classifier cache key unavailable; running the model without caching');
        }
        const outcome = await getModelVerdict(subject, context, key, warnings);
        modelAttempted = outcome.attempted;
        if (outcome.verdict) {
          classifierUsed = true;
          decision = outcome.verdict.decision;
          decisionConfidence = outcome.verdict.confidence
            ?? ruleDecisionConfidence(decision, riskScore);
        }
      }
    }

    if (decisionConfidence === undefined) {
      decisionConfidence = ruleDecisionConfidence(decision, riskScore);
    }
    // A policy-forced decision on a partial scan is not evidence, so it is not
    // reported with confidence; `scanComplete` and the warning carry the gap.
    if (incomplete) decisionConfidence = 0;

    return {
      decision,
      // Deprecated alias of `riskScore` (kept for 0.2.x consumers): this has
      // always meant rule evidence, never the model's certainty.
      confidence: Number(riskScore.toFixed(3)),
      riskScore: Number(riskScore.toFixed(3)),
      decisionConfidence: Number(decisionConfidence.toFixed(3)),
      riskLevel: riskLevelOf(reasonsOut, decision),
      reasons: reasonsOut,
      allowlistedHits,
      // Plain SHA-256 of the scanned subject (post-truncation): lets any
      // consumer locally replay the decision from the exact bytes scanned.
      inputSha256: createHash('sha256').update(subject).digest('hex'),
      elapsedMs: Date.now() - started,
      // Full replay: the rule pass came from cache and no model call was made
      // (a cached model verdict still counts as a replay).
      cacheHit: rulePass.cached && !modelAttempted,
      ruleCacheHit: rulePass.cached,
      scanComplete: !incomplete,
      truncated,
      warnings,
      classifierUsed,
      // Length of the text actually scanned (post-truncation), consistent
      // with inputSha256 above.
      scannedLength: subject.length,
      ruleset: RULESET_VERSION,
    };
  }

  return {
    scan,
    clearCache() {
      ruleCache.clear();
      modelCache.clear();
    },
    stats() {
      return {
        size: ruleCache.size,
        hits: ruleHits,
        misses: ruleMisses,
        modelSize: modelCache.size,
        modelHits,
        modelMisses,
      };
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
