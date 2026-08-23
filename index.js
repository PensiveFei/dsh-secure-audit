/**
 * dsh-secure-audit — host plugin entry.
 *
 * Registers three READ-ONLY tools with the DSH tool registry:
 *   - security_scan_text     prompt-injection detection (rule + optional model)
 *   - security_redact_text   Chinese-focused PII redaction
 *   - security_audit         local configuration security audit (redacted report)
 * and one runtime skill (`security-review`) when the skills service exists
 * (optional service via ctx.get — no hard dependency).
 *
 * The plugin never writes to the audited system; every capability is
 * inspection + reporting.
 */

import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { defineTool, assertObjectJsonSchema } from '@deepseek-ai/dsh-tools';
import { createInjectionScanner } from './lib/injection.js';
import { redactText, redactJson } from './lib/redact.js';
import { runSecurityAudit, CHECK_SCOPES } from './lib/audit.js';
import { createLogger } from './lib/logger.js';
import { createClassifier } from './lib/classifier.js';
import { INJECTION_RULES, INJECTION_RULE_IDS, PII_TYPE_IDS } from './lib/rules.js';

export const name = 'dsh-secure-audit';
/** Register only after the tools service is ready. */
export const inject = ['tools'];

// ---------------------------------------------------------------------------
// Skill loading (runtime registration via optional `skills` service)
// ---------------------------------------------------------------------------

function loadSkillMarkdown() {
  try {
    const url = new URL('./skills/security-review/SKILL.md', import.meta.url);
    return readFileSync(url, 'utf8');
  } catch {
    return null;
  }
}

function parseSkill(markdown) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/.exec(markdown.trimStart());
  if (!m) return { name: 'security-review', description: '', content: markdown };
  const meta = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/.exec(line);
    if (kv) meta[kv[1]] = kv[2].trim();
  }
  return {
    name: meta.name || 'security-review',
    description: meta.description || '',
    content: m[2].trim(),
  };
}

// ---------------------------------------------------------------------------
// Output renderers (UI presentation; markdown)
// ---------------------------------------------------------------------------

function renderScan(args, value) {
  const lines = [
    `**Security scan** — decision \`${value.decision}\` (confidence ${value.confidence.toFixed(2)})`,
  ];
  if (value.reasons.length > 0) {
    lines.push('Hits:');
    for (const r of value.reasons.slice(0, 8)) {
      lines.push(`- \`${r.ruleId}\` (${r.severity}, ×${r.matches}): ${r.description} — \`${r.snippet}\``);
    }
  }
  if (value.warnings.length > 0) lines.push(`⚠ ${value.warnings.join('; ')}`);
  if (value.classifierUsed) lines.push('Model classifier contributed to this decision.');
  return lines.join('\n');
}

function renderRedact(args, value) {
  const total = value.findings.reduce((n, f) => n + f.count, 0);
  const lines = [`**PII redaction** — ${total} occurrence(s) masked across ${value.findings.length} type(s).`];
  for (const f of value.findings) lines.push(`- ${f.label}: ×${f.count} (e.g. \`${f.sample}\`)`);
  if (value.truncated) lines.push('⚠ input was truncated before redaction.');
  return lines.join('\n');
}

function renderRedactJson(args, value) {
  const lines = [];
  if (value.error) {
    lines.push(`**Structured redaction** — ${value.error}`);
    return lines.join('\n');
  }
  lines.push(
    `**Structured redaction** — ${value.replacedKeys.length} sensitive key(s) replaced, ${value.piiCount} PII occurrence(s) masked in other values.`,
  );
  if (value.replacedKeys.length > 0) {
    lines.push('Replaced keys:');
    for (const k of value.replacedKeys.slice(0, 10)) lines.push(`- \`${k.path}\``);
  }
  return lines.join('\n');
}

const STATUS_ICONS = Object.freeze({
  pass: '✅',
  warn: '⚠️',
  fail: '❌',
  error: '❓',
  info: 'ℹ️',
});

function renderAudit(args, value) {
  const s = value.summary;
  const lines = [
    `**Security audit** — pass ${s.pass} / warn ${s.warn} / fail ${s.fail} / error ${s.error} / info ${s.info}`,
  ];
  for (const check of value.checks) {
    const icon = STATUS_ICONS[check.status] ?? '•';
    lines.push(`- ${icon} \`${check.id}\` (${check.severity}): ${check.message}`);
    if (check.evidence) lines.push(`  evidence: \`${check.evidence}\``);
  }
  if (value.limitations && value.limitations.length > 0) {
    lines.push('Limitations:');
    for (const limitation of value.limitations) lines.push(`- ${limitation}`);
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export function apply(ctx, config = {}) {
  const logger = createLogger({
    enabled: config.logEnabled !== false,
    logFile: typeof config.logFile === 'string' ? config.logFile : '',
    sink: ctx.logger,
  });
  ctx.on('dispose', () => logger.dispose());

  const scanner = createInjectionScanner({
    cacheSize: config.cacheSize,
    timeoutMs: config.scanTimeoutMs,
    maxLength: config.scanMaxLength,
    blockThreshold: config.blockThreshold,
    reviewThreshold: config.reviewThreshold,
    allowlist: Array.isArray(config.allowlist) ? config.allowlist : [],
    classifier: createClassifier(config.classifier ?? null),
    maskChar: typeof config.maskChar === 'string' && config.maskChar ? config.maskChar : '*',
  });

  // Load-time schema validation: a regression in any output schema must
  // fail the plugin loudly at apply(), not surface at runtime (mirrors
  // dsh-auto-review's assertObjectJsonSchema discipline).
  function registerWithSchemaCheck(def) {
    assertObjectJsonSchema(def.output.schema);
    ctx.tools.register(def);
  }

  // --- security_scan_text ---------------------------------------------------
  registerWithSchemaCheck(defineTool({
    name: 'security_scan_text',
    description: 'Scan a text for prompt-injection / jailbreak attempts. Runs a fast rule engine first; an optional pluggable model classifier can refine "review" verdicts. Returns a decision (allow/review/block), confidence, per-rule reasons with redacted snippets, and a PII-redacted copy of the input. Fail-open: on timeout or truncation it downgrades to "allow" with an explicit warning. Heuristic: the rules may miss novel attacks and may over-flag benign phrasing; treat "allow" as "no rule fired", not as a safety guarantee — for sensitive flows, review "review" verdicts and pair with the model classifier.',
    parameters: {
      text: {
        type: 'string',
        description: 'The text to scan (user message, prompt, file content, tool output).',
        required: true,
      },
      maskText: {
        type: 'boolean',
        description: 'Include a PII-redacted copy of the input as maskedText in the result.',
        default: true,
      },
      context: {
        type: 'string',
        description: 'Optional context hint (e.g. "user message", "system prompt") passed to the model classifier.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        properties: {
          requestId: { type: 'string', description: 'Audit-trail correlation id.' },
          decision: { type: 'string', enum: ['allow', 'review', 'block'], description: 'Overall verdict.' },
          confidence: { type: 'number', description: '0..1 confidence in the decision.' },
          riskLevel: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Coarse risk level derived from rule severities and the decision band; policies can route on it.' },
          inputSha256: { type: 'string', description: 'SHA-256 of the scanned text (post-truncation); lets you locally replay this decision from the exact bytes scanned.' },
          reasons: {
            type: 'array',
            description: 'Rule hits that drove the decision.',
            items: {
              type: 'object',
              additionalProperties: true,
              properties: {
                ruleId: { type: 'string' },
                category: { type: 'string' },
                severity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'] },
                action: { type: 'string' },
                description: { type: 'string' },
                matches: { type: 'integer' },
                snippet: { type: 'string' },
              },
            },
          },
          allowlistedHits: {
            type: 'array',
            description: 'Hits that matched allowlisted rules (benign by policy).',
            items: {
              type: 'object',
              additionalProperties: true,
              properties: {
                ruleId: { type: 'string' },
                snippet: { type: 'string' },
              },
            },
          },
          maskedText: { type: 'string', description: 'PII-redacted copy of the input (when maskText is true).' },
          elapsedMs: { type: 'integer' },
          cacheHit: { type: 'boolean' },
          truncated: { type: 'boolean' },
          warnings: { type: 'array', items: { type: 'string' } },
          classifierUsed: { type: 'boolean' },
          scannedLength: { type: 'integer' },
          ruleset: { type: 'integer' },
        },
      },
      render: renderScan,
    },
    timeoutMs: 8_000,
    isConcurrencySafe: () => true,
    async execute(args) {
      const requestId = randomUUID();
      const log = logger.child(requestId);
      const result = await scanner.scan(args.text, { requestId, role: args.context });
      const maskedText = args.maskText === false ? '' : redactText(args.text).redacted;
      log.scan(result);
      return {
        requestId,
        decision: result.decision,
        confidence: result.confidence,
        riskLevel: result.riskLevel,
        inputSha256: result.inputSha256,
        reasons: result.reasons,
        allowlistedHits: result.allowlistedHits,
        maskedText,
        elapsedMs: result.elapsedMs,
        cacheHit: result.cacheHit,
        truncated: result.truncated,
        warnings: result.warnings,
        classifierUsed: result.classifierUsed,
        scannedLength: args.text.length,
        ruleset: result.ruleset,
      };
    },
  }));

  // --- security_redact_text -------------------------------------------------
  registerWithSchemaCheck(defineTool({
    name: 'security_redact_text',
    description: 'Redact personally identifiable information (PII) from text, optimized for Chinese data: CN mobile numbers, CN ID cards (date-validated to avoid order-number false positives), CN bank cards, emails, IPv4 addresses, API keys/tokens, and credentials embedded in URLs. Returns the masked text plus per-type counts with masked samples. The output is always safe to log, store, or display. Covers only the listed types via regex/structural checks: names, addresses, and other context-sensitive PII are NOT masked — redaction is a mitigation, not a guarantee.',
    parameters: {
      text: {
        type: 'string',
        description: 'Text to redact.',
        required: true,
      },
      modes: {
        type: 'array',
        description: 'PII types to mask; default: all.',
        items: { type: 'string', enum: PII_TYPE_IDS },
      },
      maskChar: {
        type: 'string',
        description: 'Masking character.',
        enum: ['*', '#', 'x'],
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        properties: {
          redacted: { type: 'string', description: 'The masked text.' },
          truncated: { type: 'boolean' },
          findings: {
            type: 'array',
            description: 'Per-type masking statistics.',
            items: {
              type: 'object',
              additionalProperties: true,
              properties: {
                type: { type: 'string' },
                label: { type: 'string' },
                count: { type: 'integer' },
                sample: { type: 'string' },
              },
            },
          },
        },
      },
      render: renderRedact,
    },
    timeoutMs: 8_000,
    isConcurrencySafe: () => true,
    async execute(args) {
      const requestId = randomUUID();
      const log = logger.child(requestId);
      const result = redactText(args.text, {
        modes: args.modes,
        maskChar: args.maskChar,
      });
      log.redact(result);
      return { requestId, redacted: result.redacted, truncated: result.truncated, findings: result.findings };
    },
  }));

  // --- security_redact_json (structured redaction) -------------------------
  registerWithSchemaCheck(defineTool({
    name: 'security_redact_json',
    description: 'Redact sensitive values inside structured JSON: any object key matching a sensitive-key pattern (api_key, token, secret, password, authorization, credential, ...) has its whole value replaced by [REDACTED] (structural, beats obfuscation), and every other string value is passed through the PII regex engine as a fallback (phone / ID / bank card / email / API key / URL credentials). The JSON structure is preserved — keys are never masked, only values — so downstream code reading the shape keeps working. Returns the redacted JSON text plus a list of replaced key paths and PII counts. Use it before handing tool-call arguments or session context to a third-party model. Invalid JSON returns an error field instead of throwing.',
    parameters: {
      json: {
        type: 'string',
        description: 'JSON text (or a JSON-serializable object) to redact.',
        required: true,
      },
      keyModes: {
        type: 'array',
        description: 'Optional extra key-name patterns (regex sources) treated as sensitive; the built-in pattern (api_key, token, secret, password, authorization, credential, ...) always applies.',
        items: { type: 'string' },
      },
      maskChar: {
        type: 'string',
        description: 'Masking character for PII fallback in non-sensitive values.',
        enum: ['*', '#', 'x'],
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        properties: {
          requestId: { type: 'string', description: 'Audit-trail correlation id.' },
          redactedJson: { type: 'string', description: 'The redacted JSON text (empty when input was invalid).' },
          replacedKeys: {
            type: 'array',
            description: 'Sensitive keys whose whole value was replaced.',
            items: {
              type: 'object',
              additionalProperties: true,
              properties: {
                path: { type: 'string', description: 'JSONPath-ish location, e.g. $.config.credentials[0].token.' },
                key: { type: 'string' },
              },
            },
          },
          piiCount: { type: 'integer', description: 'PII occurrences masked in non-sensitive values.' },
          error: { type: 'string', description: 'Parse error when the input is not valid JSON (empty string on success).' },
        },
      },
      render: renderRedactJson,
    },
    timeoutMs: 8_000,
    isConcurrencySafe: () => true,
    async execute(args) {
      const requestId = randomUUID();
      const log = logger.child(requestId);
      const keyPattern = Array.isArray(args.keyModes) && args.keyModes.length > 0
        ? new RegExp(args.keyModes.join('|'), 'i')
        : undefined;
      const result = redactJson(args.json, {
        keyPattern,
        maskChar: args.maskChar,
      });
      log.emit('info', 'redact_json', {
        replacedKeys: result.replacedKeys.length,
        piiCount: result.piiCount,
        error: result.error,
      });
      return {
        requestId,
        redactedJson: result.redactedJson,
        replacedKeys: result.replacedKeys,
        piiCount: result.piiCount,
        error: result.error ?? '',
      };
    },
  }));

  // --- security_audit -------------------------------------------------------
  registerWithSchemaCheck(defineTool({
    name: 'security_audit',
    description: 'Run a read-only security audit of the local DeepSeek Harness installation: embedded secrets in config files, config file permissions, session-file structure and stored PII, installed plugin inventory and remote patch sources, key path permissions, network bindings, and secret-like environment variables. Never modifies anything. Outputs a deterministic, PII-redacted, reproducible risk report with per-check remediation. Posture snapshot, not a certification: the report lists its limitations (e.g. Windows ACLs are not inspected; detection is heuristic); absence of findings does not imply safety.',
    parameters: {
      scope: {
        type: 'array',
        description: 'Audit areas; default: all.',
        items: { type: 'string', enum: CHECK_SCOPES },
      },
      baseDir: {
        type: 'string',
        description: 'Root to audit (default: $DSH_HOME or ~/.dsh).',
      },
      workspace: {
        type: 'string',
        description: 'Optional workspace path to include in path checks.',
      },
      sampleLimit: {
        type: 'integer',
        description: 'Max session files to scan for stored PII; default 10. Raise it for large session directories.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        properties: {
          requestId: { type: 'string' },
          plugin: { type: 'string' },
          version: { type: 'string' },
          generatedAt: { type: 'string' },
          reportSha256: { type: 'string', description: 'SHA-256 of the report body (excluding generatedAt); verify the report was not altered and diff runs byte-for-byte.' },
          baseDir: { type: 'string' },
          workspace: { type: 'string' },
          scopesAudited: { type: 'array', items: { type: 'string' } },
          checks: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: true,
              properties: {
                id: { type: 'string' },
                category: { type: 'string' },
                severity: { type: 'string' },
                status: { type: 'string', enum: ['pass', 'warn', 'fail', 'error', 'info'] },
                message: { type: 'string' },
                evidence: { type: 'string' },
                remediation: { type: 'string' },
              },
            },
          },
          summary: {
            type: 'object',
            additionalProperties: true,
            properties: {
              pass: { type: 'integer' },
              warn: { type: 'integer' },
              fail: { type: 'integer' },
              error: { type: 'integer' },
              info: { type: 'integer' },
            },
          },
          limitations: {
            type: 'array',
            description: 'Declared limits of this audit run (scope, platform, heuristic nature).',
            items: { type: 'string' },
          },
        },
      },
      render: renderAudit,
    },
    timeoutMs: 60_000,
    isConcurrencySafe: () => false,
    async execute(args) {
      const requestId = randomUUID();
      const log = logger.child(requestId);
      const report = await runSecurityAudit({
        scope: args.scope,
        baseDir: args.baseDir,
        workspace: args.workspace,
        sampleLimit: args.sampleLimit,
      });
      log.audit(report.summary);
      return { requestId, ...report };
    },
  }));

  // --- optional runtime skill ------------------------------------------------
  const skills = ctx.get('skills');
  if (skills) {
    const markdown = loadSkillMarkdown();
    if (markdown) {
      const skill = parseSkill(markdown);
      skills.register({ name: skill.name, description: skill.description, content: skill.content });
      ctx.logger.info('[secure-audit] runtime skill "%s" registered', skill.name);
    } else {
      ctx.logger.warn('[secure-audit] skill markdown not found; skill registration skipped');
    }
  }

  ctx.logger.info(
    '[secure-audit] ready: %d injection rules (ruleset v%d), 3 tools registered',
    INJECTION_RULES.length,
    scanner.ruleset().version,
  );
}

// Exported for tooling/tests and for allowlist validation docs.
export { INJECTION_RULE_IDS, PII_TYPE_IDS, CHECK_SCOPES };
