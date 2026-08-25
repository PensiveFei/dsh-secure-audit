# Changelog

All notable changes to `dsh-secure-audit` are documented here.

Format: **Added / Fixed / Upgrade notes / Known issues**. Versioning follows
SemVer; 0.x releases mean the plugin API is not yet stable and minor versions
may introduce breaking changes.

## [0.2.2] - 2026-08-26

Bugfix release.

### Fixed

- The `security-review` runtime skill is now registered with the `source`
  field the DSH skill registry requires. Loading the skill previously failed
  with `loaded skill "security-review" source must be a string` because the
  registration only carried `content`.

## [0.2.1] - 2026-08-23

Bugfix release. Both defects were found by DeepSeek Harness (DSH) automated
code review.

### Fixed

- `cn_id` redaction now applies a real calendar check to the embedded birth
  date: impossible dates (e.g. 2000-02-31, Feb 29 in a non-leap year) are no
  longer masked as identity cards, cutting order-number false positives
  (issue #1).
- `security_audit`'s `config-secrets` check now also inspects YAML/TOML
  list items (`- key: value`), so secrets stored under arrays are no longer
  missed (issue #2).

## [0.2.0] - 2026-08-22 (unreleased)

Second feature release. Adds a fourth tool (structured JSON redaction) and
strengthens the scan and audit outputs with risk levels, replayable hashes,
configurable timeout policy, and load-time schema validation. All changes are
backwards compatible (new tool, new fields, new optional config).

### Added

- `security_redact_json` — new tool: recursively redacts sensitive values
  inside structured JSON. Any object key matching the sensitive-key pattern
  (`api_key`, `token`, `secret`, `password`, `authorization`,
  `credential`, ...) has its whole value replaced by `[REDACTED]`
  (structural, beats obfuscation); every other string value is passed through
  the PII regex engine as a fallback. The JSON structure is preserved (keys are
  never masked, only values). Returns `redactedJson`, `replacedKeys`
  (JSONPath labels), `piiCount`, and an `error` field for invalid input.
  Custom key patterns via `keyModes`.
- `security_scan_text` gains `riskLevel` (`low`/`medium`/`high`,
  derived from rule severities + decision band) and `inputSha256` (SHA-256 of
  the scanned text, so any decision can be locally replayed with the same
  `ruleset`).
- `security_scan_text` gains an `onTimeout` config
  (`allow`/`review`/`block`, default `allow`) controlling the policy on
  budget expiry — `review`/`block` provide fail-closed behavior for
  sensitive flows.
- `security_audit` reports carry `reportSha256` — a self-checksum over the
  deterministic report body (excluding `generatedAt`) so consumers can verify
  a report was not altered in transit and diff runs byte-for-byte.
- Load-time output-schema validation: every tool schema is asserted with
  `assertObjectJsonSchema` at plugin start; a schema regression now fails
  loudly at startup instead of surfacing at runtime.

### Changed

- Scan timeout warning text now names the applied policy
  (`fail-open`/`fail-closed`) and the forced decision.
- README: four-tool table, `security_redact_json` usage, `riskLevel` /
  `inputSha256` / `reportSha256` documentation, `onTimeout` config row,
  security-model and test-coverage updates.

### Upgrade notes

- No configuration or API changes required; a drop-in upgrade from 0.1.1.
- `security_redact_json` is a new tool; `riskLevel`, `inputSha256`,
  `reportSha256`, and `onTimeout` are additive.
- Tested against `@deepseek-ai/dsh-tools` 0.1.0-rc.7 (unchanged).

## [0.1.1] - 2026-08-21

First maintenance release; drop-in upgrade from 0.1.0 (no API changes).

### Added

- `security_audit` accepts `sampleLimit` to raise the session-file PII
  sampling cap (default 10) for large session directories; the report's
  `limitations` field reflects the effective value.
- Edge-case tests: empty/whitespace redaction input, unknown redaction modes,
  symbol-only scan input, classifier timeout degrade, allowlist + cache
  interaction, multiple allowlisted rules, concurrent-scan isolation.

### Changed

- Scan engine precompiles each rule's global regex once at scanner creation
  and iterates matches with `String#matchAll` (internally cloned with a
  fresh `lastIndex` per call): the per-rule-per-scan `RegExp` rebuild is
  gone, and concurrent scans on one scanner cannot corrupt each other's regex
  state.
- Render maps and protected-signal tokens hoisted to module scope (no
  behavior change).
- README FAQ covers install, false positives, Windows permissions, and
  classifier setup; the session-PII sampling limitation notes `sampleLimit`.
- CI supports manual `workflow_dispatch` runs.
- npm metadata gained `bugs` and `homepage` links.

### Upgrade notes

- No configuration or API changes; a drop-in replacement for 0.1.0.
- Tested against `@deepseek-ai/dsh-tools` 0.1.0-rc.7 (unchanged); re-run
  `security_audit` after upgrading DSH itself.
- First release published to npm: `dsh plugin add dsh-secure-audit` installs
  `dsh-secure-audit@0.1.1` from the registry.

### Known issues

- Unchanged from 0.1.0 (Windows ACL caveat, sampling bounds, rule-only
  operation without a local classifier, type-limited redaction).

## [0.1.0] - 2026-08-19

First release.

### Added

- `security_scan_text` — prompt-injection detection tool:
  - Rule engine with 24 English + Chinese patterns (instruction override,
    role switch / jailbreak, system-prompt leak, data exfiltration, tool
    abuse, harmful content).
  - LRU cache (default 512 entries) keyed by SHA-256(text) + ruleset version.
  - Fail-open cooperative budget: on timeout the scan returns `allow` with an
    explicit warning.
  - Pluggable model classifier: invoked only on `review` verdicts without
    critical hits; failure degrades to the rule decision with a warning.
  - Per-rule reasons with PII-masked, single-line snippets; optional
    `maskedText` copy of the input.
- `security_redact_text` — PII redaction tool (Chinese-first):
  - CN mobile numbers (with optional +86 prefix), CN ID cards (date-validated),
    CN bank cards (Luhn-validated), emails, IPv4 (octet-validated), API keys
    and tokens, credentials embedded in URLs.
  - Configurable mask character and PII-type filtering; per-type counts with
    masked samples.
- `security_audit` — read-only local audit tool:
  - Nine deterministic checks across config / sessions / plugins / paths /
    network / env: embedded secrets, file permissions, session-file PII,
    plugin inventory and remote patch sources, key path permissions, network
    bindings, secret-like env vars.
  - PII-redacted, path-normalized evidence; reproducible across runs.
- `security-review` runtime skill, registered via the optional `skills`
  service when present.
- Structured JSONL logger with `requestId` correlation and automatic masking
  of PII in sensitive fields.
- Adversarial sample suite (`tests/fixtures/adversarial-samples.js`) covering
  English + Chinese attack vectors and benign-vocabulary false-positive cases.
- Registration tests that build every tool through the real
  `@deepseek-ai/dsh-tools` contract and validate execution outputs against
  their declared schemas.
- CI (Node 20/22/24): lint (syntax + secret scan) and full test suite.

### Fixed

- CN ID cards no longer match arbitrary 18-digit order numbers (date
  structure required).
- CN bank cards no longer match 16-19 digit order numbers (Luhn checksum
  required).
- Chinese injection patterns added (`忽略之前所有指令`, `你现在是…`,
  `执行任意命令`, …); everyday questions (`你现在是怎么想的`) and benign
  commands (`运行命令 npm install`) are excluded.
- `build a bomb shelter` no longer triggers the explosives rule (negative
  lookahead); bare `jailbreak` in technical text no longer triggers the DAN
  rule.
- Audit placeholder values (`xxx`, `your-…`, `<…>`, `changeme`) are skipped;
  the placeholder matcher handles suffixes and hyphens.
- Tool output schemas validated against the real `@deepseek-ai/dsh-tools`
  enforcement (null-vs-string fields in audit report).
- `security_scan_text` returns `""` (not `null`) for `maskedText` when
  `maskText: false`, keeping the declared output schema valid.
- The optional `context` argument of `security_scan_text` is now forwarded to
  the model classifier.
- Built-in Ollama classifier adapter: the plugin config accepts
  `{ classifier: { adapter: "ollama", endpoint, model, timeoutMs } }` from
  `cordis.patch.yml` (previously the classifier was only settable
  programmatically).
- Bundle patch (`cordis.patch.yml`) now uses the loader's `insert` form —
  top-level rows are treated as overrides of existing entries and fail with
  "entry not found" (found during live-host install validation).
- Shipped files no longer carry a UTF-8 BOM; the bundle loader
  `JSON.parse`s each bundle manifest, and a BOM there aborts profile boot.
- `plugins-inventory` now scans each profile's `node_modules` (community
  bundles live there, not under `DSH_HOME`) and counts only packages with a
  `dsh` manifest — transitive dependencies no longer pollute the inventory
  (found during live-host install validation).
- Audit reports now carry a `limitations` array declaring what each run does
  not cover (posture snapshot, heuristic detection, sampling bounds, Windows
  ACL caveat), and renders it in the tool output.
- Tool descriptions state the heuristic and coverage limits explicitly
  (`allow` ≠ safe; redaction covers listed types only; audit is not a
  certification).
- README gained a "Limitations and disclaimer" section; the `security-review`
  skill's boundaries now state the heuristic nature and when to escalate.

### Upgrade notes

- Peer dependency: `@deepseek-ai/dsh-tools >= 0.1.0-rc.7` (provided by the
  DSH runtime; no install-time scripts or build steps in this package).
- Tested against `@deepseek-ai/dsh-tools` 0.1.0-rc.7. Because DSH is pre-1.0,
  pin your DSH version and re-run `security_audit` after upgrading either
  side; report compatibility results in the official DSH Discussions.
- No configuration changes required from a fresh install; all keys are
  optional.

### Known issues

- File-permission checks are best-effort on Windows (POSIX mode bits only).
- Session-file PII sampling covers the first 10 files; large directories are
  bounded by design.
- The model classifier is an interface only in 0.1.0; an Ollama adapter
  example ships in `examples/`, but no classifier is bundled.
