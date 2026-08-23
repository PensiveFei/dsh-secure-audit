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

/**
 * Redact PII occurrences in a string.
 *
 * @param {string} input text to redact
 * @param {object} [options]
 * @param {string[]} [options.modes] subset of PII type ids; default: all
 * @param {string} [options.maskChar='*'] masking character
 * @param {number} [options.maxLength=1_000_000] input cap; longer input is
 *   truncated with `truncated: true`
 * @returns {{redacted: string, truncated: boolean, findings: Array<{type: string, label: string, count: number, sample: string}>}}
 */
export function redactText(input, options = {}) {
  if (typeof input !== 'string') {
    throw new TypeError('redactText: input must be a string');
  }
  const { maskChar = '*', maxLength = DEFAULT_MAX_LENGTH } = options;
  const wanted = options.modes && options.modes.length > 0
    ? new Set(options.modes)
    : new Set(Object.keys(PII_RULES));

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
 * redaction. Mirrors the audit engine's SECRET_KEY_RE and adds the
 * authorization/credential family so tool-call arguments handed to a
 * third-party model are scrubbed by key, not just by value type.
 */
export const SENSITIVE_JSON_KEY_RE =
  /(?:api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|pass(word|wd)?|pwd|secret|token|authorization|auth|credential)/i;

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
 *
 * @param {string|object} input JSON text (string) or an already-parsed value
 * @param {object} [options]
 * @param {RegExp} [options.keyPattern=SENSITIVE_JSON_KEY_RE] key matcher
 * @param {string} [options.keyMask='[REDACTED]'] replacement for sensitive keys
 * @param {string[]} [options.modes] PII type ids for the value channel
 * @param {string} [options.maskChar='*'] masking character for the value channel
 * @param {number} [options.maxDepth=32] recursion guard against cyclic/deep input
 * @returns {{redactedJson: string, replacedKeys: Array<{path: string, key: string}>, piiCount: number, error: string|null}}
 */
export function redactJson(input, options = {}) {
  const {
    keyPattern = SENSITIVE_JSON_KEY_RE,
    keyMask = REDACTED_JSON_KEY,
    modes,
    maskChar = '*',
    maxDepth = 32,
  } = options;
  const replacedKeys = [];
  let piiCount = 0;

  let parsed;
  if (typeof input === 'string') {
    try {
      parsed = JSON.parse(input);
    } catch (err) {
      return { redactedJson: '', replacedKeys: [], piiCount: 0, error: 'invalid JSON (' + (err?.name ?? 'parse error') + ')' };
    }
  } else {
    parsed = input;
  }

  function walk(value, path, depth) {
    if (depth > maxDepth) return value;
    if (Array.isArray(value)) {
      return value.map((item, i) => walk(item, [...path, i], depth + 1));
    }
    if (value !== null && typeof value === 'object') {
      const out = {};
      for (const [key, item] of Object.entries(value)) {
        if (typeof item === 'string' && keyPattern.test(key)) {
          replacedKeys.push({ path: pathLabel([...path, key]), key });
          out[key] = keyMask;
          continue;
        }
        if (typeof item === 'string') {
          const redacted = redactText(item, { modes, maskChar });
          if (redacted.findings.length > 0) {
            piiCount += redacted.findings.reduce((n, f) => n + f.count, 0);
            out[key] = redacted.redacted;
            continue;
          }
        }
        out[key] = walk(item, [...path, key], depth + 1);
      }
      return out;
    }
    return value;
  }

  const cleaned = walk(parsed, [], 0);
  return {
    redactedJson: JSON.stringify(cleaned),
    replacedKeys,
    piiCount,
    error: null,
  };
}

/**
 * Mask a secret value for evidence display: keep at most 3 leading and 3
 * trailing characters, hide the rest. Never emits the full value.
 */
export function maskSecret(value, maskChar = '*') {
  const s = String(value);
  if (s.length <= 8) return maskChar.repeat(Math.min(s.length, 4));
  return s.slice(0, 3) + maskChar.repeat(6) + s.slice(-3);
}
