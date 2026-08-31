# Changelog

All notable changes to `dsh-secure-audit` are documented here.

Format: **Added / Fixed / Upgrade notes / Known issues**. Versioning follows
SemVer; 0.x releases mean the plugin API is not yet stable and minor versions
may introduce breaking changes.

## [0.2.8] - 2026-08-31

Compatibility release for DeepSeek Harness **0.1.2-alpha**: widen the
`@deepseek-ai/dsh-tools` peer range to the alpha line. No runtime code changes.

### Changed

- **Peer range `>=0.1.0-rc.7` → `>=0.1.2-alpha.2`**: under semver's prerelease
  rule, `>=0.1.0-rc.7` matches only the `0.1.0-rc.x` line — it does NOT admit
  `0.1.1-rc.x` or `0.1.2-alpha.x` (verified with node-semver against the
  registry). On the new harness the plugin would either resolve an outdated
  `dsh-tools` or trigger a peer-resolution conflict. The new range aligns with
  what `dsh-base@0.1.2-alpha.2` ships.
- **devDependency `@deepseek-ai/dsh-tools` 0.1.0-rc.7 → 0.1.2-alpha.2** so the
  test baseline matches the declared peer range (avoids install-time
  peer/dev version conflicts).

### Fixed

- None in this release.

### Upgrade notes

- Drop-in upgrade from 0.2.7; metadata-only change.
- Requires a host providing `@deepseek-ai/dsh-tools >= 0.1.2-alpha.2`
  (DeepSeek Harness 0.1.2-alpha or a later line with a matching tuple).

### Known issues

- Unchanged: Windows ACL caveat, session-PII sampling bounds, type-limited
  PII redaction, heuristic injection rules.

## [0.2.7] - 2026-08-30

Documentation release: verifiable release integrity and an evidence chain for
the "read-only" claim, following the community review on
[discussion #5077](https://github.com/deepseek-ai/deepseek-harness/discussions/5077).
No runtime code changes.

### Added

- **Release artifacts & integrity**: README (EN + ZH) now publishes the
  SHA-256 of every released tarball (computed from the GitHub release assets,
  with verification commands); the release checklist and `release.yml` record
  the new tarball's hash at release time.
- **docs/verification-matrix.md**: maps every claim — and each point of the
  #5077 community review — to the automated test or manual step that proves
  it, across the four phases: install, host activation, tool invocation, and
  the optional JSONL write path.
- **docs/uninstall-rollback-checklist.md**: backup-first manual procedure for
  uninstall / upgrade / rollback without disturbing the host profile
  (offline-tarball method; no `npm install` inside profile directories).

### Fixed

- None in this release (documentation only).

### Upgrade notes

- Drop-in upgrade from 0.2.6; zero API or behavior changes — documentation and
  release metadata only.
- Tested against `@deepseek-ai/dsh-tools` 0.1.0-rc.7.

### Known issues

- Unchanged: Windows ACL caveat, session-PII sampling bounds, type-limited
  PII redaction, heuristic injection rules.

## [0.2.6] - 2026-08-29

Feature + hardening release: obfuscation-resistant injection detection, two
new audit checks, audit profile tiers, OWASP mapping, a high-entropy
redaction mode, and a detection-quality eval script. Published on npm and
GitHub (Release + tag) on 2026-08-29.

### Added

- **Obfuscation-resistance layer (ruleset v4)** for `security_scan_text`:
  the scanner now also inspects a zero-width / full-width / Cyrillic-homoglyph
  normalized copy of the input and up to 4 bounded base64-decoded candidates.
  Hits are merged per distinct rule id and tagged with `via`
  (`plain` | `normalized` | `base64`); snippets show the derived text.
  `inputSha256` still covers the raw scanned bytes, so decisions remain
  locally replayable.
- **`security_audit` two new checks:**
  - `deps-supply-chain` (plugins, OWASP LLM03 / Agentic Supply Chain):
    offline plugin inventory by default (deterministic, no network); an
    opt-in `supplyChainLive` config additionally queries the npm registry
    audit endpoint with a bounded timeout. The live lookup sends installed
    plugin names+versions to registry.npmjs.org and is documented as such —
    it stays OFF by default.
  - `host-capabilities` (host scope): reports the running host's dsh-tools /
    dsh-session versions, skills-service availability, ruleset, and plugin
    version, injected from the plugin entry.
- **`security_audit` profile tiers**: `profile: quick|full` (default `full`).
  `quick` cuts the file walk to 50 files and session sampling to 3; per-call
  `maxFiles`/`maxBytes` overrides are also accepted. The report carries the
  effective `profile`.
- **OWASP mapping**: every check now carries `owasp` (OWASP Top 10 for LLM
  Applications 2025 code, e.g. LLM02/LLM03) and `agentic` (OWASP Agentic Top
  10 category name) fields.
- **Network bindings ground truth (Linux)**: `network-bindings` now parses
  `/proc/net/{tcp,tcp6}` for LISTEN sockets bound to all interfaces
  (`0.0.0.0`/`::`) — pure read-only fs, no child processes. Windows/macOS
  keep the env/config signal and note the platform limit in `limitations`.
- **High-entropy redaction mode**: `security_redact_text` accepts
  `modes: ['high_entropy']` to mask random secret-like tokens (length ≥ 24,
  Shannon entropy ≥ 4.5 bits/char, ≥ 2 character classes). Off by default
  to avoid over-redaction; UUIDs and hex hashes are deliberately not
  masked. `security_audit`'s `config-secrets` gains a matching info-level
  auxiliary signal for high-entropy values under non-secret key names
  (never escalates to fail).
- **Detection-quality eval**: `npm run eval` runs the adversarial sample
  library through the scanner and reports precision/recall/F1/accuracy; a
  pinned expectation that regresses fails the run. CI runs it after
  `npm test`.
- `security_scan_text` reason objects carry `via`; README.zh.md added;
  architecture doc and the security-review SKILL updated.

### Fixed

- None in this release (features + hardening only).

### Upgrade notes

- Drop-in upgrade from 0.2.5; no API changes. New `profile` param and
  `supplyChainLive`/`supplyChainTimeoutMs` config keys are optional.
  `security_scan_text` may now report additional `via: normalized|base64`
  hits for previously-missed obfuscated inputs (ruleset bumped to v4, so
  cached verdicts invalidate).
- Tested against `@deepseek-ai/dsh-tools` 0.1.0-rc.7.
- Published: npm latest = 0.2.6; GitHub Release v0.2.6 (non-draft, tarball attached).

### Known issues

- Unchanged: Windows ACL caveat, session-PII sampling bounds, type-limited
  PII redaction (names/addresses still need NER), heuristic injection rules.
- `deps-supply-chain` live lookup is opt-in and network-dependent; offline
  mode is the default.
## [0.2.5] - 2026-08-28

Fix release from an adversarial self-review: closes the `onTimeout` wiring gap and three structured-redaction leak paths. No new tools.

### Fixed

- `security_scan_text`: the documented `onTimeout` config (`allow`/`review`/`block`) is now wired through the plugin entry. Previously the key was silently ignored and every budget expiry stayed fail-open; fail-closed flows can now be enabled from `cordis.patch.yml`.
- `security_redact_json`: a sensitive key now replaces its WHOLE value with `[REDACTED]` regardless of type (number, boolean, array, nested object), matching the documented "structural, beats obfuscation" promise. Previously only direct string values were replaced.
- `security_redact_json`: strings inside arrays under ordinary keys now go through the PII fallback (previously any array content passed through unredacted).
- `security_redact_json`: the depth guard now fails safe — strings and containers beyond `maxDepth` (32) are replaced by `[REDACTED]` instead of passing through; reference cycles are broken at the guard.
- `security_redact_json`: invalid `keyModes` regexes return the `error` field instead of throwing a raw SyntaxError; oversized `keyModes` (more than 20 patterns, or any pattern over 200 characters) is rejected the same way.
- `security_scan_text`: `scannedLength` now reports the scanned (post-truncation) length, consistent with `inputSha256`.
- `security_audit`: the `config-secrets` message no longer implies the capped count (10) is the total.
- `lib/logger.js`: a misconfigured `logFile` (ENOENT/EACCES, sync or async) degrades to sink-only output with one sanitized warning instead of risking an unhandled stream error that could take the host down.
- Startup log and header comment now say 4 tools (4 have been registered since 0.2.0).

### Changed

- `security_audit` env checks read the injected `ctx.env` (falling back to `process.env`) for consistency.
- CI: the test job declares `permissions: contents: read`.
- Docs: SECURITY.md supported table lists 0.2.x; README documents `logEnabled` and refines the "no write paths" claim (the opt-in `logFile` is the only append-only write); the classifier adapter comment calls `/api/generate` Ollama-native.

### Upgrade notes

- Drop-in upgrade from 0.2.4 / 0.2.3 / 0.2.2; no API changes. The `redact_json` changes only ever make outputs MORE redacted.
- Behavior change to review: sensitive keys now redact whole non-string values. Flows that need to read numbers/objects under sensitive keys must move those values under non-sensitive key names.
- Tested against `@deepseek-ai/dsh-tools` 0.1.0-rc.7.

### Known issues

- Unchanged: Windows ACL caveat, session-PII sampling bounds, type-limited PII redaction, heuristic injection rules.

## [0.2.4] - 2026-08-28

Maintenance release: clears the two warnings raised by the dsh.so automated
vet scan (`netIp` + `childProcess`) so the plugin keeps a clean security
verdict. No runtime behavior change.

### Fixed

- `lib/classifier.js`: the Ollama adapter's default endpoint now uses the
  `localhost` hostname instead of the `127.0.0.1` IP literal (same default
  Ollama address; removes the `netIp` static-scan warning).
- `scripts/lint.mjs`: the syntax-check step no longer shells out to
  `node --check` via `node:child_process`; it parses sources in-process with
  `acorn` (devDependency, parse-only, never executes code). The secret scan
  is unchanged. Removes the `childProcess` static-scan warning.
- README, `examples/ollama-classifier.js` and `cordis.patch.yml`:
  classifier endpoint examples updated to `localhost` to match the new
  default.

## [0.2.3] - 2026-08-26

Bugfix release. Fixes a plugin-tool hang reported in
deepseek-ai/deepseek-harness discussion #4551: every tool call from the
harness (e.g. from `run_code`) never settled while built-in tools worked.

### Fixed

- All four `output.render` implementations now return a `ContentBlock[]`
  (an array of records each carrying a string `type` tag, e.g.
  `[{ type: 'text', text: ... }]`) instead of a bare string. The DSH
  contract is `render(args, value): ContentBlock[]`; a string is
  JSON-lossless and passed the projection snapshot, then broke in the
  consumer that assumes an array, hanging the tool call (root cause
  confirmed by @Jstn-1g and @tancheng33 in discussion #4551).
- The smoke test asserted `typeof rendered === 'string'`, pinning the
  buggy shape; it now asserts the render result is an array of records with
  string `type` tags against the real `@deepseek-ai/dsh-tools`.

### Upgrade notes

- No config changes. Verified against the same environment as 0.2.2.
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
