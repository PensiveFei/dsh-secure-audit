/**
 * Chinese-focused PII redaction engine.
 *
 * Pure module: no I/O, no framework imports. Strategy is "regex + structural
 * validation" (see docs/architecture.md): patterns are anchored with
 * lookarounds and, for the CN ID card, require the embedded date structure so
 * that long digit runs (order numbers, tracking ids) do not false-positive.
 *
 * The output is always safe to log, store, or display.
 */

import { PII_RULES } from './rules.js';

export const DEFAULT_MAX_LENGTH = 1_000_000;
export const MAX_JSON_INPUT_LENGTH = 4 * 1024 * 1024;
export const MAX_JSON_NODES = 100_000;

/** A mask must be one Unicode scalar so it cannot erase or amplify output. */
function normalizeMaskChar(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2) return '*';
  const codePoint = value.codePointAt(0);
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) return '*';
  return String.fromCodePoint(codePoint) === value ? value : '*';
}

/**
 * Redact PII occurrences in a string.
 *
 * @param {string} input text to redact
 * @param {object} [options]
 * @param {string[]} [options.modes] subset of PII type ids; default: all
 * @param {string} [options.maskChar='*'] one Unicode character; invalid values use '*'
 * @param {number} [options.maxLength=1_000_000] input cap; longer input is
 *   truncated with `truncated: true`
 * @returns {{redacted: string, truncated: boolean, findings: Array<{type: string, label: string, count: number, sample: string}>}}
 */
export function redactText(input, options = {}) {
  if (typeof input !== 'string') {
    throw new TypeError('redactText: input must be a string');
  }
  const { maskChar: requestedMaskChar = '*', maxLength = DEFAULT_MAX_LENGTH } = options;
  const maskChar = normalizeMaskChar(requestedMaskChar);
  // Default mode set excludes `high_entropy`: random-looking strings are
  // masked only when explicitly requested (modes: ['high_entropy']) so
  // normal text with long mixed tokens is not over-redacted.
  const DEFAULT_MODES = Object.keys(PII_RULES).filter((t) => t !== 'high_entropy');
  const wanted = options.modes && options.modes.length > 0
    ? new Set(options.modes)
    : new Set(DEFAULT_MODES);

  const truncated = input.length > maxLength;
  let redacted = truncated ? input.slice(0, maxLength) : input;
  const findings = [];

  for (const [type, rule] of Object.entries(PII_RULES)) {
    if (!wanted.has(type)) continue;
    // Clone per call: a shared `g` regex would leak lastIndex across calls.
    const re = new RegExp(rule.pattern, rule.flags);
    let count = 0;
    let sample = null;
    redacted = redacted.replace(re, (match) => {
      if (rule.validate && !rule.validate(match)) return match;
      count += 1;
      const masked = rule.mask ? rule.mask(match, maskChar) : maskChar.repeat(match.length);
      if (sample === null) sample = masked;
      return masked;
    });
    if (count > 0) {
      findings.push({ type, label: rule.label, count, sample });
    }
  }

  return { redacted, truncated, findings };
}

/** Convenience: does the string contain any known PII (non-destructive)? */
export function containsPii(input, options = {}) {
  return redactText(input, options).findings.length > 0;
}

/**
 * Key names whose values are always treated as secrets in structured
 * redaction. The matcher is SEGMENT-based, not a bare substring test: a
 * substring test turned ordinary keys into false positives (author,
 * secretary, authentication, oauth_provider, tokenCount, maxTokens all matched
 * "auth"/"token"/"secret") and silently destroyed their values in the payload
 * handed to a third-party model.
 */
const SENSITIVE_KEY_SEGMENTS = new Set([
  'secret', 'secrets', 'token', 'tokens', 'password', 'passwd', 'pwd', 'passphrase',
  'authorization', 'credential', 'credentials', 'clientsecret', 'apikey', 'accesskey', 'privatekey',
]);
const KEY_QUALIFIERS = new Set([
  'api', 'access', 'private', 'public', 'secret', 'client', 'app', 'application', 'auth',
  'signing', 'encryption', 'master', 'session', 'refresh', 'bearer', 'oauth',
]);
const QUANTIFIER_SEGMENTS = new Set([
  'max', 'min', 'count', 'limit', 'length', 'size', 'type', 'name', 'id', 'ids', 'url', 'uri',
  'env', 'file', 'path', 'bytes', 'ttl', 'expiry', 'expires', 'budget', 'window', 'usage', 'total',
]);

/** Split a key into lowercase segments on separators and camelCase boundaries. */
function keySegments(key) {
  return String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1\u0000$2')
    .split(/[\u0000_.\- ]+/)
    .filter(Boolean)
    .map((seg) => seg.toLowerCase());
}

/**
 * Whether a JSON key names a secret. Segment-aware: apiKey / api_key /
 * access_token / clientSecret / password / pwd / secret / authorization /
 * credential(s) match, while author, secretary, authentication, oauth_provider,
 * tokenCount and maxTokens do not (a neighbouring quantifier segment means the
 * key MEASURES tokens rather than holds one).
 * @param {string} key object key
 * @returns {boolean}
 */
export function isSensitiveJsonKey(key) {
  if (typeof key !== 'string' || key === '') return false;
  const segments = keySegments(key);
  for (let i = 0; i < segments.length; i += 1) {
    const seg = segments[i];
    const prev = segments[i - 1];
    const next = segments[i + 1];
    const quantifierNearby = (prev !== undefined && QUANTIFIER_SEGMENTS.has(prev))
      || (next !== undefined && QUANTIFIER_SEGMENTS.has(next));
    if (SENSITIVE_KEY_SEGMENTS.has(seg) && !quantifierNearby) return true;
    // A bare "key" segment only counts when a qualifier names the secret kind.
    if (seg === 'key' && !quantifierNearby
      && ((prev !== undefined && KEY_QUALIFIERS.has(prev)) || (next !== undefined && KEY_QUALIFIERS.has(next)))) {
      return true;
    }
  }
  return false;
}

/**
 * Coarse segment-anchored pattern retained for callers that pass an explicit
 * RegExp keyPattern. The default matcher is isSensitiveJsonKey.
 */
export const SENSITIVE_JSON_KEY_RE =
  /(?:^|[_.\-])?(?:api[_.\- ]?key|access[_.\- ]?key|private[_.\- ]?key|client[_.\- ]?secret|pass(?:word|wd|phrase)?|pwd|secret|token|authorization|credential(?:s)?)(?:$|[_.\-])/i;

const REDACTED_JSON_KEY = '[REDACTED]';

/** JSONPath-ish label for a nested value, e.g. "$.config.credentials[0].token". */
function pathLabel(path) {
  return '$' + path.map((seg) => (typeof seg === 'number' ? '[' + seg + ']' : '.' + seg)).join('');
}

/**
 * Recursively redact sensitive values in structured JSON.
 *
 * Two channels:
 * 1. KEY channel — any object key matching {@link SENSITIVE_JSON_KEY_RE} has
 *    its whole value replaced by `[REDACTED]` (structural, beats obfuscation).
 * 2. VALUE channel — every other string value is passed through the PII
 *    regex engine as a fallback (phone / id / bank card / email / key...).
 *
 * The JSON structure itself is preserved: keys are never masked, only values,
 * so downstream code that reads the shape keeps working.
 * JSON text is capped at 4,194,304 UTF-16 code units before parsing. Traversal
 * is capped at 100,000 values and 4,194,304 aggregate key/value characters;
 * exceeding any limit returns an empty result with a sanitized error.
 *
 * @param {string|object} input JSON text (string) or an already-parsed value
 * @param {object} [options]
 * @param {RegExp} [options.keyPattern] additional key matcher; built-in secret
 *   key detection always remains enabled
 * @param {string} [options.keyMask='[REDACTED]'] replacement for sensitive keys
 * @param {string[]} [options.modes] PII type ids for the value channel
 * @param {string} [options.maskChar='*'] masking character for the value channel
 * @param {number} [options.maxLength=1_000_000] per-string value cap
 * @param {number} [options.maxDepth=32] recursion guard, integer from 0 to 256
 * @returns {{redactedJson: string, replacedKeys: Array<{path: string, key: string}>, piiCount: number, error: string|null}}
 */
export function redactJson(input, options = {}) {
  const {
    keyPattern,
    keyMask = REDACTED_JSON_KEY,
    modes,
    maskChar = '*',
    maxLength = DEFAULT_MAX_LENGTH,
    maxDepth = 32,
  } = options;
  const replacedKeys = [];
  let piiCount = 0;
  let nodes = 0;
  let characters = 0;
  const limitError = new RangeError('JSON redaction limit exceeded');
  const ancestors = new WeakSet();
  // A caller's global/sticky regex must not skip alternating keys or mutate
  // its lastIndex as a side effect of sanitization.
  const additionalKeyPattern = keyPattern instanceof RegExp
    ? new RegExp(keyPattern.source, keyPattern.flags)
    : null;

  let parsed;
  if (typeof input === 'string') {
    if (input.length > MAX_JSON_INPUT_LENGTH) {
      return { redactedJson: '', replacedKeys: [], piiCount: 0, error: 'JSON input exceeds maximum length' };
    }
    try {
      parsed = JSON.parse(input);
    } catch (err) {
      return { redactedJson: '', replacedKeys: [], piiCount: 0, error: 'invalid JSON (' + (err?.name ?? 'parse error') + ')' };
    }
  } else {
    parsed = input;
  }

  function visit() {
    nodes += 1;
    if (nodes > MAX_JSON_NODES) throw limitError;
  }

  function spendCharacters(length) {
    characters += length;
    if (characters > MAX_JSON_INPUT_LENGTH) throw limitError;
  }

  function maskedValue() {
    spendCharacters(keyMask.length);
    return keyMask;
  }

  function walk(value, path, depth) {
    visit();
    // Never let a function reach JSON.stringify, including beyond maxDepth:
    // an own toJSON hook could otherwise reintroduce raw values afterwards.
    if (typeof value === 'function' || typeof value === 'symbol') return undefined;
    if (depth > maxDepth) {
      // Fail safe beyond the recursion guard: strings and containers could
      // carry secrets past this point, so they are replaced instead of
      // passed through. Scalars (number/boolean/null) are kept. This also
      // breaks reference cycles at the guard instead of leaking them.
      return typeof value === 'string' || (value !== null && typeof value === 'object')
        ? maskedValue()
        : value;
    }
    if (typeof value === 'string') {
      // One value channel covers root scalars, array items and object values.
      // Keep the capped result even when there are no findings.
      spendCharacters(Math.min(value.length, maxLength));
      const redacted = redactText(value, { modes, maskChar, maxLength });
      piiCount += redacted.findings.reduce((n, f) => n + f.count, 0);
      return redacted.redacted;
    }
    if (value !== null && typeof value === 'object') {
      if (ancestors.has(value)) return maskedValue();
      ancestors.add(value);
      try {
        if (Array.isArray(value)) {
          // Do not invoke a caller-provided map method or Array species;
          // either could return an object with an unsafe serialization hook.
          const out = [];
          for (let i = 0; i < value.length; i += 1) {
            out.push(walk(value[i], [...path, i], depth + 1));
          }
          return out;
        }
        // Null-prototype sink preserves own "__proto__" keys without invoking
        // the prototype setter or allowing inherited serialization hooks.
        const out = Object.create(null);
        for (const key of Object.keys(value)) {
          spendCharacters(key.length);
          if (additionalKeyPattern) additionalKeyPattern.lastIndex = 0;
          if (isSensitiveJsonKey(key) || additionalKeyPattern?.test(key)) {
            // The WHOLE secret value is replaced regardless of its type.
            visit();
            replacedKeys.push({ path: pathLabel([...path, key]), key });
            out[key] = maskedValue();
            continue;
          }
          out[key] = walk(value[key], [...path, key], depth + 1);
        }
        return out;
      } finally {
        ancestors.delete(value);
      }
    }
    return value;
  }

  try {
    if (!Number.isSafeInteger(maxDepth) || maxDepth < 0 || maxDepth > 256) {
      throw new TypeError('invalid maxDepth');
    }
    if (!Number.isSafeInteger(maxLength) || maxLength < 0 || typeof keyMask !== 'string') {
      throw new TypeError('invalid redaction options');
    }
    const cleaned = walk(parsed, [], 0);
    const redactedJson = JSON.stringify(cleaned);
    if (typeof redactedJson !== 'string') throw new TypeError('invalid JSON value');
    return { redactedJson, replacedKeys, piiCount, error: null };
  } catch (err) {
    // A pre-parsed value may contain BigInts or throwing getters. Report a
    // sanitized failure, never stringify its exception message or raw input.
    return {
      redactedJson: '', replacedKeys: [], piiCount: 0,
      error: err === limitError ? limitError.message : 'invalid JSON value or redaction options',
    };
  }
}

/**
 * Mask a secret value for evidence display: keep at most 3 leading and 3
 * trailing characters, hide the rest. Never emits the full value.
 */
export function maskSecret(value, maskChar = '*') {
  maskChar = normalizeMaskChar(maskChar);
  const s = String(value);
  if (s.length <= 8) return maskChar.repeat(Math.min(s.length, 4));
  return s.slice(0, 3) + maskChar.repeat(6) + s.slice(-3);
}
