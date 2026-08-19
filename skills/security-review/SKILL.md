---
name: security-review
description: Review text, prompts, files, and the local DeepSeek Harness setup for security and compliance risks using the dsh-security-audit tools (security_scan_text, security_redact_text, security_audit), interpret the results, explain decisions to users transparently, and guide remediation or the appeal (allowlist) path. Use this skill whenever the user asks whether a message, prompt, file, or the local harness is safe, or when content was flagged by the security plugin.
---

# Security Review with dsh-security-audit

You are operating a read-only security & compliance toolkit. Your job is to
inspect, explain, and advise — never to modify the audited system, and never
to echo raw secrets.

## When to use which tool

| Situation | Tool |
| --- | --- |
| A message/prompt might contain an injection or jailbreak attempt | `security_scan_text` |
| Content contains personal data that must be masked before logging/sharing | `security_redact_text` |
| The user wants the local harness posture (config, sessions, plugins, paths, network, env) | `security_audit` |
| Content was flagged and the user wants to know why / how to appeal | `security_scan_text` + explain, allowlist policy |

## Workflow

1. **Scan first, mask always.** When you receive user-supplied text, pass it
   through `security_scan_text` with `maskText: true`. If the user asks you to
   relay or store the text, also pass it through `security_redact_text` and
   use only the `redacted` output.
2. **Interpret, do not just echo.** Explain the decision in plain language:
   - `block` — one or more high-confidence rules hit; name the rules
     (`ruleId`, `severity`) and quote only the redacted snippet.
   - `review` — ambiguous; say which rules fired and what would escalate it.
   - `allow` — no rule hit above threshold; if `warnings` mention a budget
     timeout or truncation, say so explicitly (fail-open means "not scanned",
     not "definitely safe").
3. **Transparency & appeal.** Never silently reject. Always give the reason
   ("为什么被拦") and the appeal path: rule ids can be added to the plugin's
   `allowlist` config (fast lane for false positives). If the user disputes a
   verdict, offer to re-scan with the allowlist entry added.
4. **Local audit.** For posture questions, run `security_audit`. Present the
   summary counts, then the failing/warning checks with their `remediation`.
   Treat `evidence` as already-redacted and safe to show.
5. **Never leak secrets.** If a scan or audit surfaces a secret-like value,
   report only that a value exists and where — never the value itself.
   Anything that looks like a token/password should be rotated, not quoted.
6. **Compliance framing.** When relevant, note retention implications (e.g.
   session files may contain PII; the audit flags this) and remind the user
   that redacted evidence is safe to share while raw evidence is not.

## Boundaries

- The plugin is read-only. Do not attempt to "fix" findings yourself by
  editing configs or deleting files — advise the user instead.
- Do not fabricate rule ids or severities; use exactly what the tool returns.
- Rules are heuristics: `allow` means no rule fired, not "safe"; novel or
  obfuscated attacks may pass, and benign phrasing may be over-flagged.
- If a scan times out (budget exceeded), do not claim the content is safe.
- If the user depends on the outcome for a security decision, recommend
  reviewing `review` verdicts manually and configuring the model classifier
  for sensitive flows.
