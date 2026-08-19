/**
 * Rule and pattern data for dsh-secure-audit.
 *
 * This module is a pure data module: no I/O, no framework imports, so it can
 * be unit-tested with plain `node --test` and reused by any runtime.
 *
 * Meta-security constraints (see SECURITY.md):
 * - Every injection pattern must be free of catastrophic backtracking
 *   (no nested quantifiers, bounded alternations). New rules MUST ship with
 *   a red-team test case in tests/fixtures/adversarial-samples.js.
 * - Patterns are written defensively: lookarounds avoid matching inside
 *   longer digit runs, which keeps false positives (e.g. order numbers)
 *   low without a model layer.
 */

/** Bump when rule semantics change so cached scan results invalidate. */
export const RULESET_VERSION = 3;

/** Confidence weights per severity; used to fold hits into a 0..1 score. */
export const SEVERITY_WEIGHT = Object.freeze({
  info: 0.1,
  low: 0.2,
  medium: 0.4,
  high: 0.7,
  critical: 1.0,
});

/**
 * Prompt-injection / jailbreak rule table.
 * `pattern` is a RegExp source compiled with the `i` flag at scan time.
 * `action` is the *recommended* default reaction; the engine derives the
 * actual decision from aggregate confidence and configured thresholds.
 */
export const INJECTION_RULES = Object.freeze([
  // ---- instruction override ------------------------------------------------
  {
    id: 'instr-ignore-previous',
    category: 'instruction_override',
    severity: 'high',
    action: 'review',
    description: 'Tries to discard or override earlier instructions',
    pattern: 'ignore\\s+(?:all\\s+|any\\s+)?(?:previous|prior|above|earlier)\\s+(?:instructions?|prompts?|messages?|content)',
  },
  {
    id: 'instr-disregard',
    category: 'instruction_override',
    severity: 'high',
    action: 'review',
    description: 'Tries to disregard earlier instructions',
    pattern: 'disregard\\s+(?:all\\s+|any\\s+)?(?:previous|prior|above|earlier)\\s+(?:instructions?|prompts?|messages?|content)',
  },
  {
    id: 'instr-forget',
    category: 'instruction_override',
    severity: 'high',
    action: 'review',
    description: 'Asks the model to forget prior instructions',
    pattern: 'forget\\s+(?:all\\s+|everything|anything)?\\s*(?:you\\s+(?:were|have)\\s+(?:told|given|instructed)|prior\\s+instructions?|previous\\s+instructions?)',
  },
  {
    id: 'instr-start-fresh',
    category: 'instruction_override',
    severity: 'medium',
    action: 'review',
    description: 'Asks to restart the conversation and drop prior context',
    pattern: '(?:start|begin)\\s+(?:a\\s+)?(?:new|fresh)\\s+(?:conversation|session|chat)\\s+(?:from\\s+scratch|without\\s+context)?',
  },

  // ---- role switch / jailbreak ----------------------------------------------
  {
    id: 'role-you-are-now',
    category: 'role_switch',
    severity: 'high',
    action: 'review',
    description: 'Tries to switch the model into a different persona',
    pattern: 'you\\s+are\\s+now\\s+',
  },
  {
    id: 'role-act-as',
    category: 'role_switch',
    severity: 'low',
    action: 'warn',
    description: 'Persona framing ("act as ..."); benign in most professional prompts',
    pattern: '(?:act|behave)\\s+as\\s+(?:if\\s+you\\s+are\\s+|you\\s+are\\s+)?(?:a|an)?\\s*\\w{3,}',
  },
  {
    id: 'role-ignore-guardrails',
    category: 'role_switch',
    severity: 'critical',
    action: 'block',
    description: 'Tries to bypass or disable safety guardrails',
    pattern: '(?:ignore|bypass|override|disable|remove|forget)\\s+(?:all\\s+|your\\s+)?(?:safety|guardrails?|restrictions?|constraints?|policies?|filters?)',
  },
  {
    id: 'role-dan-mode',
    category: 'role_switch',
    severity: 'high',
    action: 'block',
    description: 'DAN (Do Anything Now) style jailbreak',
    pattern: '\\bDAN\\s+mode\\b|\\bdo\\s+anything\\s+now\\b|\\bdeveloper\\s+mode\\s+on\\b|\\b(?:jailbreak|jail\\s*break)\\s+(?:the|this|my|your)?\\s*(?:model|assistant|ai|bot|system)\\b',
  },

  // ---- system prompt disclosure ---------------------------------------------
  {
    id: 'leak-system-prompt',
    category: 'system_prompt_leak',
    severity: 'high',
    action: 'review',
    description: 'Asks the model to reveal its system prompt or instructions',
    pattern: '(?:reveal|show|print|output|display|dump)\\s+(?:your|the|its)\\s+(?:full\\s+)?(?:system\\s+)?(?:prompt|instructions?)',
  },
  {
    id: 'leak-repeat-instructions',
    category: 'system_prompt_leak',
    severity: 'high',
    action: 'review',
    description: 'Asks the model to repeat its instructions verbatim',
    pattern: '(?:repeat|copy|quote)\\s+(?:your|the)\\s+(?:full\\s+)?instructions?',
  },

  // ---- data exfiltration ------------------------------------------------------
  // "send/upload X to <somewhere>" is ambiguous (legit upload instructions
  // share the shape), so it lands at `review`; "…to <URL>" is a strong
  // exfiltration signal and stays critical.
  {
    id: 'exfil-send-external',
    category: 'data_exfiltration',
    severity: 'high',
    action: 'review',
    description: 'Tries to send or exfiltrate data to an external destination',
    pattern: '(?:exfiltrate|steal|send|upload|post|transmit)\\s+(?:(?:all|any|the|my|our)\\s+)*(?:data|files?|documents?|messages?|secrets?|credentials?)\\s+(?:to|via|through)',
  },
  {
    id: 'exfil-url',
    category: 'data_exfiltration',
    severity: 'critical',
    action: 'block',
    description: 'Tries to push content to a remote URL',
    pattern: '(?:send|upload|post|exfiltrate)\\s+(?:(?:all|any|the|my|our)\\s+)*(?:data|files?|documents?|messages?|everything|it|them)\\s+to\\s+https?://',
  },

  // ---- tool / environment abuse ----------------------------------------------
  {
    id: 'tool-shell-commands',
    category: 'tool_abuse',
    severity: 'critical',
    action: 'block',
    description: 'Tries to get arbitrary shell commands executed',
    pattern: '(?:run|execute)\\s+(?:arbitrary|shell|system|terminal|command\\s+line)?\\s*commands?',
  },
  {
    id: 'tool-destructive',
    category: 'tool_abuse',
    severity: 'critical',
    action: 'block',
    description: 'Destructive file operations',
    pattern: '\\brm\\s+-rf\\b|\\bdelete\\s+all\\s+files\\b|\\bwipe\\s+(?:the\\s+)?(?:disk|drive)\\b',
  },

  // ---- harmful content ----------------------------------------------------------
  {
    id: 'harm-explosive',
    category: 'harmful_content',
    severity: 'critical',
    action: 'block',
    description: 'Requests instructions for explosives',
    // Negative lookahead keeps benign compounds ("bomb shelter", "explosive
    // threat assessment") from firing the critical rule.
    pattern: '(?:how\\s+to\\s+)?(?:make|build|create)\\s+(?:a|an)?\\s*(?:bomb|explosive|incendiary\\s+device)(?!\\s*(?:shelter|threat|squad|disposal|scare|attack|scenario))',
  },
  {
    id: 'harm-weapon',
    category: 'harmful_content',
    severity: 'critical',
    action: 'block',
    description: 'Requests instructions for weapons',
    pattern: 'instructions?\\s+for\\s+(?:making|building)\\s+(?:a|an)?\\s*(?:weapon|firearm|gun)',
  },
  {
    id: 'harm-malware',
    category: 'harmful_content',
    severity: 'critical',
    action: 'block',
    description: 'Requests malware or ransomware development',
    pattern: '(?:write|create|develop)\\s+(?:a|an)?\\s*(?:malware|ransomware|virus|keylogger|trojan)',
  },

  // ---- Chinese-language patterns ----------------------------------------------
  // The plugin targets Chinese-PII scenarios; injection attempts arrive in
  // Chinese too, so the rule table covers the common phrasings.
  {
    id: 'cn-ignore-previous',
    category: 'instruction_override',
    severity: 'high',
    action: 'review',
    description: '要求模型忽略之前的指令（中文）',
    pattern: '忽略\\s*(?:之前|以上|前面|上面)\\s*(?:的)?\\s*(?:所有|全部)?\\s*(?:指令|指示|提示|要求|内容)',
  },
  {
    id: 'cn-ignore-everything',
    category: 'instruction_override',
    severity: 'high',
    action: 'review',
    description: '无视所有指令或规则（中文）',
    pattern: '无视\\s*(?:所有|全部)?\\s*(?:指令|规则|限制|要求|内容)',
  },
  {
    id: 'cn-you-are-now',
    category: 'role_switch',
    severity: 'high',
    action: 'review',
    description: '将模型切换为其他角色（中文）',
    // (?!怎么) avoids "你现在是怎么想的" type everyday questions.
    pattern: '你现在(?:是|变成)(?!怎么)',
  },
  {
    id: 'cn-leak-prompt',
    category: 'system_prompt_leak',
    severity: 'high',
    action: 'review',
    description: '要求模型透露系统提示词（中文）',
    pattern: '(?:输出|复述|展示|告诉我)\\s*(?:你的|系统|所有)?\\s*(?:提示词|系统提示|指令)',
  },
  {
    id: 'cn-jailbreak',
    category: 'role_switch',
    severity: 'high',
    action: 'review',
    description: '越狱/解除限制表达（中文）',
    pattern: '(?:越狱|解除限制|破解限制)',
  },
  {
    id: 'cn-guardrail-bypass',
    category: 'role_switch',
    severity: 'high',
    action: 'review',
    description: '绕过安全机制（中文）',
    pattern: '(?:绕过|无视|关闭)\\s*(?:安全|限制|审核)\\s*(?:机制|系统)?',
  },
  {
    id: 'cn-tool-abuse',
    category: 'tool_abuse',
    severity: 'critical',
    action: 'block',
    description: '要求执行任意命令（中文）',
    // A qualifier (任意/恶意/危险) is required so legitimate "运行命令 npm install"
    // style instructions do not fire the critical rule.
    pattern: '(?:执行|运行)\\s*(?:任意|恶意|危险|不受限制的)\\s*命令',
  },
]);

/** Public helper: rule ids, used for allowlist validation. */
export const INJECTION_RULE_IDS = Object.freeze(
  INJECTION_RULES.map((rule) => rule.id),
);

/** Luhn checksum: real bank cards always pass; random order numbers rarely do. */
function luhnValid(digits) {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * PII pattern table. Every entry has:
 * - `label`: human-readable type name
 * - `pattern` / `flags`: RegExp source, cloned per call (never shared, so a
 *   `g` flag can never leak `lastIndex` between calls)
 * - `mask(match, maskChar)`: deterministic masking that keeps a minimal
 *   identifying prefix/suffix (usable for correlation) and hides the rest
 * - `validate?(match)`: optional post-filter to cut false positives
 *
 * Chinese-PII notes:
 * - CN ID cards match on the embedded date structure, so arbitrary 18-digit
 *   order numbers do NOT match (the classic false-positive the user called out).
 * - CN bank cards require a valid Luhn checksum, so 16-19 digit order numbers
 *   and tracking ids do NOT match either.
 */
export const PII_RULES = Object.freeze({
  cn_mobile: {
    label: 'CN mobile phone number',
    pattern: '(?<!\\d)(?:\\+?86[- ]?)?1[3-9]\\d{9}(?!\\d)',
    flags: 'g',
    mask(match, maskChar) {
      const prefix = match.slice(0, match.length - 11);
      const body = match.slice(match.length - 11);
      return prefix + body.slice(0, 3) + maskChar.repeat(4) + body.slice(7);
    },
  },
  cn_id: {
    label: 'CN identity card number',
    pattern: '(?<!\\d)\\d{6}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx](?!\\d)',
    flags: 'g',
    mask(match, maskChar) {
      return match.slice(0, 4) + maskChar.repeat(match.length - 8) + match.slice(-4);
    },
  },
  cn_bank: {
    label: 'CN bank card number',
    pattern: '(?<!\\d)\\d{16,19}(?!\\d)',
    flags: 'g',
    validate: luhnValid,
    mask(match, maskChar) {
      return maskChar.repeat(4) + match.slice(-4);
    },
  },
  email: {
    label: 'Email address',
    pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}',
    flags: 'g',
    mask(match, maskChar) {
      const at = match.lastIndexOf('@');
      const local = match.slice(0, at);
      const domain = match.slice(at);
      const keep = local.slice(0, 2);
      return keep + maskChar.repeat(3) + domain;
    },
  },
  ipv4: {
    label: 'IPv4 address',
    pattern: '(?<!\\d)(?:\\d{1,3}\\.){3}\\d{1,3}(?!\\d)',
    flags: 'g',
    validate(match) {
      return match.split('.').every((octet) => Number(octet) <= 255);
    },
    mask(match, maskChar) {
      return Array.from({ length: 4 }, () => maskChar.repeat(3)).join('.');
    },
  },
  api_key: {
    label: 'API key / token (sk-, AKIA, ghp_, xox*, AIza...)',
    pattern: '\\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\\b',
    flags: 'g',
    mask(match, maskChar) {
      return match.slice(0, 6) + maskChar.repeat(8);
    },
  },
  url_credentials: {
    label: 'Credentials embedded in a URL',
    pattern: '(https?://)[^/\\s:@]+:[^/\\s@]+@',
    flags: 'g',
    mask(match, maskChar) {
      return match.replace(/:\/\/([^@]+)@/, `://${maskChar.repeat(3)}:${maskChar.repeat(3)}@`);
    },
  },
});

/** Order-preserving list of PII type ids, used for tool enums. */
export const PII_TYPE_IDS = Object.freeze(Object.keys(PII_RULES));
