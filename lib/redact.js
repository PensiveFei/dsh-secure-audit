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
 * Mask a secret value for evidence display: keep at most 3 leading and 3
 * trailing characters, hide the rest. Never emits the full value.
 */
export function maskSecret(value, maskChar = '*') {
  const s = String(value);
  if (s.length <= 8) return maskChar.repeat(Math.min(s.length, 4));
  return s.slice(0, 3) + maskChar.repeat(6) + s.slice(-3);
}
