# Contributing

Thanks for considering a contribution to `dsh-security-audit`. This is a
security tool; the review bar is intentionally higher than for a typical
library.

## Environment

- Node.js >= 20 (CI runs 20 / 22 / 24).
- npm (the repo commits `package-lock.json`; use `npm ci` in CI).

```bash
npm ci
npm run lint   # syntax check + secret scan
npm test       # node --test, auto-discovers tests/*.test.js
```

## Adding or changing an injection rule

Rules live in `lib/rules.js`. Every rule **must** ship with test cases:

1. An adversarial case in `tests/fixtures/adversarial-samples.js` — the
   attack text and the expected decision.
2. If the rule risks false positives (almost all do), a benign case pinned to
   `allow` (see the existing entries: "build a bomb shelter", "jailbreak
   detection", "你现在是怎么想的", "运行命令 npm install").
3. Bump `RULESET_VERSION` in `lib/rules.js` so cached scan results invalidate.

Regex requirements: no nested quantifiers, bounded alternations. Catastrophic
backtracking is rejected in review (see `SECURITY.md`).

## Changing audit checks

Checks live in `lib/audit.js` and are registered in the `CHECKS` table.
Requirements:

- Read-only: `stat` / `readdir` / `readFile` / env / `os` only. No writes.
- Deterministic: fixed order, sorted arrays, no randomness.
- Redacted evidence: run evidence through `sanitize()`; never include raw
  secret values or user paths.
- A test asserting shape, status, and evidence redaction for the new check.

## Changing the logger or redaction

- New PII types go into `lib/rules.js` (`PII_RULES`) with a `mask` function
  and a test in `tests/redact.test.js`.
- Sensitive field names in the logger are a fixed set (`REDACT_FIELDS` in
  `lib/logger.js`); extending it is a deliberate, documented decision.

## Secrets hygiene

- No real credentials, ever. Test fixtures use `sk-TEST-…` /
  `not-a-real-…` markers that match the redaction rules but not secret
  scanners (CI runs the scan on every push).
- If you add a file that looks like a key, the CI secret scan will flag it;
  change the value to an obviously fake one.

## Pull request process

1. Create a branch, make the change, add tests.
2. Run `npm run lint` and `npm test` locally — both must be green.
3. Add a `CHANGELOG.md` entry under the next version (Added / Fixed /
   Upgrade notes / Known issues).
4. Open the PR against `main`. The template lists the required checklist;
   a PR that modifies rules without adversarial cases, or any check without
   a redaction test, will be sent back.
5. CI must pass on the PR before review.

## Meta-security checklist for reviewers

- No write paths added to `lib/`.
- Error messages do not leak paths or stack traces.
- Logged fields are already-safe summary data or PII-masked.
- New dependencies: justify; the current surface is one peer dependency
  plus Node builtins.
