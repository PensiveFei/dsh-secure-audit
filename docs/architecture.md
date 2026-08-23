# Architecture

`dsh-secure-audit` is a host plugin for DeepSeek Harness. This document
records the design decisions behind the three capabilities and the
meta-security constraints that shape the code.

## Module map

```
index.js                 Cordis plugin entry: registers 4 tools + 1 runtime skill
lib/rules.js             Pure data: injection rule table + PII pattern table
lib/injection.js         Rule engine: LRU cache, budget timeout, onTimeout policy,
                         riskLevel + inputSha256 output, classifier hook
lib/redact.js            PII redaction engine (regex + structural validation)
                         + redactJson (recursive sensitive-key redaction)
lib/audit.js             Read-only audit: 9 deterministic checks + reportSha256
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
- **Fail-open budget (configurable).** A cooperative timeout checks
  wall-clock between rules; on expiry the decision follows `onTimeout`
  (`allow` fail-open default / `review` / `block` fail-closed), reasons
  are dropped (the scan was incomplete), confidence is 0, and an explicit
  warning names the applied policy — "not scanned", never "safe". Truncation
  behaves the same way.
- **Risk level.** `riskLevel` (low/medium/high) is derived from the highest
  hit severity plus the decision band, giving policies a coarse routing input
  without interpreting raw confidence.
- **Replayable decisions.** Every scan result carries `inputSha256` (the
  scanned text's digest) so a decision can be replayed locally with the same
  ruleset version.
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

**Structured redaction (`redactJson`).** A second, structure-aware channel for
JSON input: any object key matching the sensitive-key pattern
(`api_key`/`token`/`secret`/`password`/`authorization`/`credential`...)
has its whole value replaced by `[REDACTED]` — structural, so obfuscated
values cannot slip through — and every other string value passes through the
regex engine as a fallback. Keys are never masked, so the JSON shape stays
readable. This is the layer to use before handing tool-call arguments or
session context to a third-party model (inspired by dsh-auto-review's
`sanitizeArguments`).

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
wrapped: a throw becomes `status: "error"` with a sanitized message. The
report carries `reportSha256` — a self-checksum over the deterministic body
(excluding `generatedAt`) — so consumers can verify a report was not altered
and diff two runs byte-for-byte.

## Meta-security (the plugin auditing itself)

1. **Input validation.** All tool arguments are schema-validated by
   `defineTool` before `execute` runs; engine inputs are type-checked and
   length-capped. Every tool output schema is additionally asserted at load
   time with `assertObjectJsonSchema`, so a schema regression fails the
   plugin loudly at startup.
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
