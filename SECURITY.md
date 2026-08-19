# Security Policy

`dsh-secure-audit` is a security tool, so its own security matters
(mirror, meet: meta-security). Please report any vulnerability you find.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Report
privately instead:

- Open a [private security advisory](https://github.com/PensiveFei/dsh-secure-audit/security/advisories/new)
  (preferred), or
- Email the maintainers (address listed in the repository description).

Include, if possible:

- Affected version and module (`lib/redact.js`, `lib/injection.js`, ...)
- A minimal reproducer
- Impact assessment (e.g. data leak through an unredacted log line,
  ReDoS through a crafted rule, path traversal in the audit module)

We aim to acknowledge reports within 72 hours and to ship a fix in a patch
release.

## Hardening expectations for contributors

- Never log raw message content, secret values, or full file paths from user
  home directories. Log redacted evidence only.
- Regexes in `lib/rules.js` must avoid catastrophic backtracking: no nested
  quantifiers, bounded alternations. Add a red-team case for every new rule.
- Every audit check must be read-only and deterministic; anything that
  modifies state is rejected by review.
- Error messages must not leak internal paths or stack traces.
