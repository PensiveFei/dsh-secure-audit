# Architecture

`dsh-secure-audit` is a host plugin for DeepSeek Harness. This document
records the design decisions behind the three capabilities and the
meta-security constraints that shape the code.

## Module map

```
index.js                 Cordis plugin entry: registers 3 tools + 1 runtime skill
lib/rules.js             Pure data: injection rule table + PII pattern table
lib/injection.js         Rule engine: LRU cache, budget timeout, classifier hook
lib/redact.js            PII redaction engine (regex + structural validation)
lib/audit.js             Read-only audit: 9 deterministic checks
lib/logger.js            Structured JSON-lines logger, auto-redaction
skills/security-review/  Agent skill (registered via optional `skills` service)
tests/                   node:test suite + adversarial sample library
```

Zero-dependency rule: `lib/*` (except the plugin entry) imports only Node
builtins, so the unit suite runs without installing anything. `index.js`
imports `@deepseek-ai/dsh-tools` (peer dependency, provided by the DSH
runtime).

## Capability 1 — Prompt-injection detection (`lib/injection.js`)

**Rule + model dual engine.** Rules run first (low latency, deterministic,
cheap); a model classifier runs only when the rules are inconclusive.

- **Scoring.** Confidence = severity-weighted sum of distinct rule hits,
  capped at 1. Any critical hit floors confidence at 0.9. Thresholds
  (`reviewThreshold` / `blockThreshold`) map confidence to `allow` / `review`
  / `block`.
- **Rules.** English + Chinese pattern table (`lib/rules.js`) tuned against an
  adversarial sample library (`tests/fixtures/adversarial-samples.js`), which
  doubles as the regression suite in CI. Benign-vocabulary cases
  ("act as a senior reviewer", "jailbreak detection", "build a bomb shelter",
  "运行命令 npm install", "你现在是怎么想的") are pinned to `allow`.
- **LRU cache.** SHA-256(text) + `RULESET_VERSION` key; identical inputs skip
  re-scanning. `RULESET_VERSION` is bumped whenever rule semantics change so
  stale cached verdicts cannot survive an upgrade.
- **Fail-open budget.** A cooperative timeout checks wall-clock between rules;
  on expiry the scan stops, returns `allow`, and emits an explicit warning —
  "not scanned", never "safe". Truncation behaves the same way.
- **Classifier hook.** `{ classify(text, context) → {decision?, confidence?} }`
  is invoked only on `review` verdicts without critical hits, under its own
  timeout, and its failure degrades to the rule decision with a warning.
- **Redacted evidence.** Every reason snippet is single-line, control-char
  stripped, PII-masked, and length-capped.

## Capability 2 — PII redaction (`lib/redact.js`)

Chinese PII is context-sensitive; bare regexes over-flag (an 18-digit order
number looks like an ID card). Mitigations:

- CN ID cards require the **embedded date structure**
  (`110101199001011234` matches; `2026021412345678` does not).
- CN mobiles are anchored with lookarounds so they cannot match inside longer
  digit runs; `+86`/`86-` prefixes are preserved in the mask.
- IPv4 validates octets ≤ 255. Bank cards require a valid Luhn checksum, so
  16-19 digit order numbers and tracking ids pass through unmasked.
- Masking keeps a minimal prefix/suffix (usable for correlation) and hides the
  rest: `138****5678`, `1101**********1234`, `****9012`, `zh***@example.com`,
  `***.***.***.***`, `sk-abc********`.

## Capability 3 — Read-only audit (`lib/audit.js`)

Nine deterministic checks across six scopes:

| Check | Scope | Finds |
| --- | --- | --- |
| `config-secrets` | config | secret-like keys with non-empty values; evidence shows key + line, never the value |
| `config-permissions` | config | group/other-writable config files (best-effort on Windows) |
| `sessions-structure` | sessions | session directory inventory |
| `sessions-sensitive-content` | sessions | redactable PII in a sample of session files |
| `plugins-inventory` | plugins | local plugin packages (`plugins/`, `node_modules/@deepseek-ai`) |
| `plugins-patch-sources` | plugins | `cordis.yml`/`cordis.patch.yml` lines referencing remote sources |
| `paths-permissions` | paths | world-writable key paths; workspace inside temp |
| `network-bindings` | network | `0.0.0.0`/`::` bindings from env and config; active interface count |
| `env-secrets` | env | secret-like environment variables (names only) |

Determinism: fixed check order, sorted arrays, no randomness; `generatedAt`
is metadata and can be stripped for byte-identical diffing. Every check is
wrapped: a throw becomes `status: "error"` with a sanitized message.

## Meta-security (the plugin auditing itself)

1. **Input validation.** All tool arguments are schema-validated by
   `defineTool` before `execute` runs; engine inputs are type-checked and
   length-capped.
2. **No leaky errors.** Audit checks and the classifier path convert failures
   into generic messages; internal paths are normalized to `<base>` /
   `<workspace>`.
3. **Log hygiene.** `lib/logger.js` redacts sensitive field names and truncates
   long values; it is the only sink for plugin events, so no raw text can
   reach `ctx.logger` or a log file by accident.
4. **Least privilege.** The plugin holds no credentials, writes nothing, and
   declares only the `tools` hard dependency; the `skills` service is optional
   (`ctx.get`), and skill registration is skipped when absent.
5. **Minimal attack surface.** One peer dependency; all patterns reviewed for
   catastrophic backtracking; adversarial samples enforced in CI.

## Observability roadmap

Structured JSONL events (`scan`, `redact`, `audit`) with `requestId` are
already emitted. Planned: Prometheus counters/gauges (interception rate,
false-positive rate, P99 scan latency), rule-grayscale rollout (1% traffic),
and a whitelist hot-path for fast false-positive release.
