# Architecture

`dsh-secure-audit` is a host plugin for DeepSeek Harness. This document
records the design decisions behind the three capabilities and the
meta-security constraints that shape the code.

## Module map

```
index.js                 Cordis plugin entry: registers 4 tools + 1 runtime skill
lib/rules.js             Pure data: injection rule table + PII pattern table
lib/injection.js         Rule engine: split rule/model caches, coverage policies
                         (onTimeout / onTruncate), riskScore + decisionConfidence,
                         riskLevel + inputSha256 output, classifier hook
lib/redact.js            PII redaction engine (regex + structural validation)
                         + redactJson (recursive sensitive-key redaction)
lib/audit.js             Read-only audit: 11 deterministic checks + reportSha256
lib/logger.js            Structured JSON-lines logger, auto-redaction
skills/security-review/  Agent skill (registered via optional `skills` service)
scripts/eval.mjs         Detection-quality eval over the adversarial suite (CI)
tests/                   node:test suite + adversarial sample library
```

Zero-dependency rule: `lib/*` (except the plugin entry) imports only Node
builtins, so the unit suite runs without installing anything. `index.js`
imports `@deepseek-ai/dsh-tools` (peer dependency, provided by the DSH
runtime).

## Capability 1 — Prompt-injection detection (`lib/injection.js`)

**Rule + model dual engine.** Rules run first (low latency, deterministic,
cheap); a model classifier runs only when the rules are inconclusive.

- **Scoring.** `riskScore` = severity-weighted sum of distinct rule hits,
  capped at 1. Any critical hit floors it at 0.9. Thresholds
  (`reviewThreshold` / `blockThreshold`) map the score to `allow` / `review` /
  `block`. `confidence` is a deprecated alias of `riskScore`.
- **Two confidences, separated (0.3.0).** `riskScore` is rule evidence and is
  never written by the model. `decisionConfidence` is certainty in the reported
  decision: the classifier's own `confidence` when it contributed, otherwise
  the rule score's support for that decision (`riskScore` for review/block,
  `1 − riskScore` for allow), and 0 whenever `scanComplete` is false.
- **Rules.** English + Chinese pattern table (`lib/rules.js`) tuned against an
  adversarial sample library (`tests/fixtures/adversarial-samples.js`), which
  doubles as the regression suite in CI. Benign-vocabulary cases
  ("act as a senior reviewer", "jailbreak detection", "build a bomb shelter",
  "delete all files in the build directory", "运行命令 npm install",
  "你现在是怎么想的", security write-ups mentioning 越狱手法) are pinned to
  `allow`; quoted attack text is pinned to `review` and labelled as an accepted
  false positive.
- **Obfuscation-resistance layer (ruleset v4, current ruleset v6).** Plain-text
  rules are dodged by zero-width characters, full-width / Cyrillic homoglyphs,
  and base64 payloads, so the scanner derives up to 4 bounded variants per
  input: the raw subject, a normalized copy (zero-width stripped;
  `Ｉｇｎｏｒｅ`/`previоus` mapped to ASCII), and base64-decoded candidates
  (printable-gate filtered, ≤ 4 tokens of ≤ 4 KB). Hits are merged per distinct
  rule id (first variant wins), each reason carries `via` (`plain` |
  `normalized` | `base64`), and the shared cooperative budget still bounds
  total work — more variants mean fewer rules scanned, never unbounded decode.
  `inputSha256` is over the raw subject, so replay is stable.
- **Split caches (0.3.0).** The rule cache keys on SHA-256(text) +
  `RULESET_VERSION` only — the rule table never reads the caller's context, so
  a per-call `requestId` cannot defeat it. Model verdicts live in a second
  cache keyed by text + the classifier's declared `cacheKeyFor` (role-only for
  the built-in Ollama adapter); a custom classifier with no declared key is
  cached only for a role-only plain context. Only complete rule passes and
  well-formed model verdicts are cached. `RULESET_VERSION` is bumped whenever
  rule semantics change so stale verdicts cannot survive an upgrade.
- **Incomplete coverage is explicit (0.3.0).** `scanComplete` is false when the
  input exceeded `maxLength` or the cooperative budget expired. Truncation
  applies `onTruncate` (`allow` default / `review` / `block`) as a decision
  floor — never a downgrade of prefix hits — and skips the model, which would
  only see the prefix. Budget expiry drops the partial reasons, follows
  `onTimeout`, and sets `decisionConfidence` to 0. When both happen the stricter
  policy wins, and a warning names the applied policy — "not scanned", never
  "safe".
- **Risk level.** `riskLevel` (low/medium/high) is derived from the highest
  hit severity plus the final decision band, giving policies a coarse routing
  input without interpreting raw scores.
- **Replayable decisions.** Every scan result carries `inputSha256` (the
  scanned text's digest) so a decision can be replayed locally with the same
  ruleset version.
- **Classifier hook.** `{ classify(text, context) → {decision?, confidence?} }`
  is invoked only on complete `review` verdicts without critical hits, under
  its own timeout, and its failure degrades to the rule decision with a
  warning. Its `confidence` means certainty in its own verdict and is reported
  as `decisionConfidence`, never as `riskScore`.
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

**High-entropy mode (`high_entropy`, opt-in).** Random secret-like tokens
(length ≥ 24, Shannon entropy ≥ 4.5 bits/char, ≥ 2 character classes) are
masked only when explicitly requested via `modes: ['high_entropy']` — excluded
from the default mode set so ordinary long mixed tokens are not over-redacted.
UUIDs (~3.6 bits/char) and hex hashes (~4.0) deliberately fail the entropy
threshold. The same detector feeds `config-secrets` as an info-level auxiliary
signal for high-entropy values under non-secret key names (never escalates to
fail).

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

Eleven deterministic checks across seven scopes, each carrying an `owasp`
(OWASP Top 10 for LLM Applications 2025) and `agentic` (OWASP Agentic Top 10)
mapping for framework-aligned reporting:

| Check | Scope | Finds |
| --- | --- | --- |
| `config-secrets` | config | secret-like keys with non-empty values (+ info-level high-entropy auxiliary signal); evidence shows key + line, never the value |
| `config-permissions` | config | group/other-writable config files (best-effort on Windows) |
| `sessions-structure` | sessions | session directory inventory |
| `sessions-sensitive-content` | sessions | redactable PII in a sample of session files |
| `plugins-inventory` | plugins | local plugin packages (`plugins/`, `node_modules/@deepseek-ai`) |
| `plugins-patch-sources` | plugins | `cordis.yml`/`cordis.patch.yml` lines referencing remote sources |
| `deps-supply-chain` | plugins | plugin version inventory (offline, deterministic) or npm registry advisories (opt-in `supplyChainLive`, bounded timeout) |
| `paths-permissions` | paths | world-writable key paths; workspace inside temp |
| `network-bindings` | network | `0.0.0.0`/`::` bindings from env and config; on Linux, `/proc/net/{tcp,tcp6}` LISTEN wildcard sockets; active interface count |
| `env-secrets` | env | secret-like environment variables (names only) |
| `host-capabilities` | host | dsh-tools / dsh-session versions, skills availability, ruleset (injected from the plugin entry) |

**Profile tiers.** `profile: quick|full` (default `full`) trades depth for
speed on large trees: `quick` walks at most 50 files and samples at most 3
session files, and skips the live supply-chain lookup. Per-call
`maxFiles`/`maxBytes` overrides stay available. The report carries the
effective `profile` and a matching `limitations` note.

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
