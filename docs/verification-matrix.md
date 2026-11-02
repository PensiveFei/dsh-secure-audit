# Verification matrix

This document answers the community review on
[discussion #5077](https://github.com/deepseek-ai/deepseek-harness/discussions/5077)
(comment by liyangbing): the "read-only" claim was asked to be split into
verifiable boundaries, with an evidence chain fixed before install. For every
point below there is either an automated test (run by CI) or a concrete manual
step. Nothing here relies on "trust us" — each row points at the file or
command that proves it.

## The four phases

A claim about this plugin lives in one of four phases, verified separately:

| Phase | What happens | Verified by |
| --- | --- | --- |
| **Install** | The tarball / git source is placed into a profile. Nothing else runs: no `prepare`/`postinstall` scripts, no build step. | `npm pack --dry-run` (release checklist), `release.yml` workflow, SHA-256 table in the README, `docs/uninstall-rollback-checklist.md` |
| **Host activation** | The bundle is patched into the profile; `apply()` registers 4 tools + 1 skill and validates every output schema at load time. | `tests/index.smoke.test.js`, CI, `dsh --profile <name> --dump-config` (manual) |
| **Tool invocation** | The four tools execute read-only: scan / redact / audit, with budgets, error handling and deterministic output. | `tests/*.test.js`, `npm run eval`, `tests/fixtures/adversarial-samples.js` |
| **Optional JSONL write path** | The single write in `lib/`: the opt-in `logFile` audit log (append-only JSONL, **disabled by default**). | `tests/logger.test.js` |

## Point-by-point evidence chain

### 1. Lock the artifact (tarball or commit) and its integrity

- Every GitHub release attaches a tarball built by the `release.yml` workflow
  (`npm pack`); its SHA-256 is published in the README section
  *Release artifacts & integrity*. Verify before installing:

  ```bash
  sha256sum dsh-secure-audit-<version>.tgz        # POSIX
  Get-FileHash dsh-secure-audit-<version>.tgz -Algorithm SHA256   # Windows
  ```

- Git installs pin a commit (`github:PensiveFei/dsh-secure-audit#<commit>`),
  so a later push cannot silently change what runs.
- The package has no lifecycle scripts by construction — `package.json`'s
  `scripts` contains only `lint` / `test` / `eval` (dev tooling), and `npm pack
  --dry-run` lists the shipped files. `lib/` imports only Node builtins and
  spawns no child processes (the single historical `spawnSync` was removed in
  v0.2.4; this is also what dsh.so's vet scan checks).
- Automated: CI runs `npm run lint` (syntax + secret scan), `npm test` and
  `npm run eval` on Node 20/22/24 for every push and PR.

### 2. Install the exact version in isolation and record what it does

Manual step (there is no way to fully automate a host audit — that is what
`security_audit` is for, and it is read-only by design):

1. Install into a copied profile or a temporary `DSH_HOME` (see
   `docs/uninstall-rollback-checklist.md` for the backup-first procedure).
2. Record: the bundle row in the profile's patch file, the 4 registered tools
   + 1 skill (`dsh --profile <name> --dump-config`), network access (none at
   install; the audit's live supply-chain lookup is **opt-in**
   `supplyChainLive: true` and documented as sending plugin names+versions to
   registry.npmjs.org), file paths touched (none besides the opt-in `logFile`),
   and process permissions (no child processes spawned by `lib/`).
3. This is exactly the procedure dsh.so's L1–L4 verification runs; the latest
   results are on the [dsh.so artifact page](https://www.dsh.so/artifact/dsh-secure-audit).

### 3. Scenario test matrix

Each scenario from the review maps to a test file (all run by `npm test`, all
green, 216 tests):

| Scenario | Covered by |
| --- | --- |
| Default-off state (JSONL log disabled, supply-chain lookup offline) | `tests/logger.test.js`, `tests/index.smoke.test.js`, `tests/audit.test.js` |
| Audit `quick` / `full` profiles, `maxFiles` / `maxBytes` overrides | `tests/audit.test.js` |
| Timeout: budget fail-open downgrade, configurable fail-closed (`onTimeout`), `scanComplete=false` | `tests/injection.test.js`, `tests/index.smoke.test.js` |
| Truncation: `onTruncate` floor (allow/review/block), no downgrade of prefix hits, model skipped, `scanComplete` + `scannedLength` | `tests/injection.test.js`, `tests/index.smoke.test.js` |
| Classifier timeout / degrade to rules-only | `tests/classifier.test.js` |
| Classifier semantics: `riskScore` not overwritten, `decisionConfidence` fallback, malformed verdicts ignored | `tests/injection.test.js`, `tests/classifier.test.js` |
| Cache layering: rule cache survives `requestId`, model cache scoped to role/declared key, transient failures retried | `tests/injection.test.js`, `tests/index.smoke.test.js` |
| Exceptions: invalid JSON, invalid `keyModes`, oversized patterns, error statuses | `tests/redact.test.js`, `tests/audit.test.js` |
| Oversized input: truncation, `scannedLength` vs `inputSha256` consistency | `tests/injection.test.js` |
| Malicious prompts incl. obfuscation (zero-width / full-width / homoglyph / base64) | `tests/injection.test.js`, `tests/fixtures/adversarial-samples.js` (64 samples), `npm run eval` (precision/recall/F1 plus FP/FN rates per language and long-text p95) |
| Ordinary dev/ops work and security education stay `allow` (scoped deletes, status prose, 越狱 write-ups, vulnerability reports) | `tests/fixtures/adversarial-samples.js`, `npm run eval` |
| Quoted attack text: pinned to `review` and labelled as an accepted false positive | `tests/fixtures/adversarial-samples.js`, `npm run eval` |
| Host contract across declared peer versions | `.github/workflows/ci.yml` job `host-compat` (6 real `@deepseek-ai/dsh-tools` versions) |
| Structured JSON redaction (key-name replacement, PII fallback, depth guard, JSONPath labels) | `tests/redact.test.js` |
| Credentials & PII redaction (CN mobile/ID/bank card w/ date + Luhn validation, email, IPv4, API keys, URL credentials) | `tests/redact.test.js` |
| Session payload decoding: concatenated zstd frames, header-only no-false-pass, plaintext caps reported as partial scans, sampling spread across workspaces, capped walk disclosed in `limitations` | `tests/audit.test.js` |
| Regex linearity: the email rule stays bounded on long non-matching filler (quadratic backtracking regression) | `tests/redact.test.js` |
| Checksum reproducibility (`reportSha256` stable across runs, `inputSha256` over raw bytes) | `tests/audit.test.js`, `tests/injection.test.js` |
| No-modification guarantee (audit leaves mtime/size untouched) | `tests/audit.test.js` |

### 4. Uninstall and failure rollback

- The plugin has no install scripts, no uninstall hooks and no code path that
  touches the profile's `package.json`, `cordis.patch.yml`, lockfiles,
  sessions, credentials or other plugins — all of that is host-managed.
- The manual procedure (backup first, minimal offline changes, `dump-config`
  verification, restart, re-verify) is `docs/uninstall-rollback-checklist.md`.

### 5. Re-run after DSH / peer upgrades; reading verdicts

- README *Compatibility* and every release's *Upgrade notes* state the tested
  `@deepseek-ai/dsh-tools` versions and require re-running `security_audit`
  after upgrading either side. The `host-compat` CI job installs six real host
  versions (0.1.0-rc.6, 0.1.2-rc.1, 0.1.7-rc.2, 0.2.0-rc.2, 0.2.1-rc.5,
  0.2.2-alpha.2) and runs the registration / execution / output-schema
  contract against each. Treat a release that bumps the peer range as a
  re-verification trigger for this whole matrix.
- `allow` means "no rule fired", not "safe". `scanComplete: false` means the
  input was truncated or the budget expired; the decision then follows
  `onTruncate` / `onTimeout` (default `allow`) — treat those as "not fully
  scanned". `security_audit` is a posture snapshot, not a certification
  (see README *Limitations and disclaimer*).

## Keeping this matrix honest

- Every new rule, redaction type or check must ship with its test (the
  adversarial-samples fixture grows with each rule — the review-era guidance
  "add a case for every new rule" is enforced in the repo's Development
  section).
- CI runs `lint` + `test` + `eval` on Node 20/22/24 before anything can merge;
  the release workflow re-runs them on the tag before building the artifact.
