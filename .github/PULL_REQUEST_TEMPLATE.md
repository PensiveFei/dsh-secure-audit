## Summary

What this PR changes and why. Reference the issue if any.

## Checklist

- [ ] `npm run lint` passes (syntax + secret scan)
- [ ] `npm test` passes
- [ ] New injection rules include an adversarial case **and** a benign
      false-positive case in `tests/fixtures/adversarial-samples.js`
- [ ] New audit checks are read-only, deterministic, and have a redaction test
- [ ] `RULESET_VERSION` bumped if rule semantics changed
- [ ] `CHANGELOG.md` updated (Added / Fixed / Upgrade notes / Known issues)
- [ ] No real credentials or unredacted user paths anywhere in the diff

## Meta-security review

- [ ] No write paths added to `lib/`
- [ ] Error messages do not leak paths or stack traces
- [ ] Logged fields are already-safe or PII-masked
