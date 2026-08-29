/**
 * Read-only local security audit for DeepSeek Harness installations.
 *
 * Product principles (see README "Security model"):
 * - NEVER modifies anything: no writes, no chmod, no deletion. Every check
 *   is a pure read (stat / readdir / readFile / env / os interfaces).
 * - REPRODUCIBLE: checks are deterministic — fixed order, sorted arrays, no
 *   randomness. `generatedAt` is metadata only and can be stripped for diffs.
 * - REDACTED: every evidence string is passed through PII redaction and
 *   path normalization (`<base>` replaces the audited root), so reports are
 *   safe to share.
 * - SAFE FAILURE: a throwing check becomes `status: "error"` with a message
 *   that leaks neither stack traces nor internal paths.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { homedir, networkInterfaces, platform, tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { redactText, maskSecret } from './redact.js';
import { isHighEntropyValue } from './rules.js';

const require = createRequire(import.meta.url);
export const PLUGIN_VERSION = require('../package.json').version;

export const CHECK_SCOPES = Object.freeze(['config', 'sessions', 'plugins', 'paths', 'network', 'env', 'host']);

const MAX_FILES = 200;
const MAX_DEPTH = 4;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.venv', 'venv']);
const CONFIG_EXTS = new Set(['.yml', '.yaml', '.json', '.toml', '.env', '.ini', '.conf']);
const SECRET_KEY_RE = /(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)/i;
const PLACEHOLDER_RE = /^(x{3,}|your[-_ ][\w-]*|example[\w-]*|changeme|placeholder|<\S+>|\*+|\.\.\.)$/i;
const ENV_SECRET_RE = /(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)/i;
const BIND_RE = /(?:host|bind|listen|addr|port)/i;
/** /proc/net LISTEN state marker (hex). */
const PROC_NET_LISTEN = '0A';
/** npm audit endpoint for the opt-in live supply-chain check. */
const NPM_AUDIT_ENDPOINT = 'https://registry.npmjs.org/-/npm/v1/security/audits';
/** Default timeout for the live supply-chain registry call. */
const SUPPLY_CHAIN_TIMEOUT_MS = 3000;
/** Max high-entropy values reported per config file in the auxiliary signal. */
const MAX_ENTROPY_SIGNALS = 5;

function defaultBaseDir() {
  return resolve(process.env.DSH_HOME || join(homedir(), '.dsh'));
}

/** Normalize a path for reproducible, non-leaking evidence. */
function norm(base, workspace, p) {
  let out = String(p).split(sep).join('/');
  if (base) out = out.replace(String(base).split(sep).join('/'), '<base>');
  if (workspace) out = out.replace(String(workspace).split(sep).join('/'), '<workspace>');
  return out;
}

/** Evidence strings that look like IPs but are security signals, protected
 * from redaction so findings stay actionable (real PII is still masked). */
const PROTECTED_SIGNALS = Object.freeze([
  ['0.0.0.0', '\u0000TOK0\u0000'],
  ['::', '\u0000TOK1\u0000'],
]);

/** Sanitize evidence: single printable line, PII-redacted, length-capped. */
function sanitize(base, workspace, text, cap = 600) {
  const cleaned = String(text)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  let prepared = cleaned;
  for (const [token, placeholder] of PROTECTED_SIGNALS) {
    prepared = prepared.split(token).join(placeholder);
  }
  let redacted = redactText(prepared).redacted;
  for (const [token, placeholder] of PROTECTED_SIGNALS) {
    redacted = redacted.split(placeholder).join(token);
  }
  const normalized = norm(base, workspace, redacted);
  return normalized.length > cap ? normalized.slice(0, cap) + '…' : normalized;
}

/** Deterministic bounded file walker. */
function collectFiles(root, { maxFiles = MAX_FILES, maxDepth = MAX_DEPTH } = {}) {
  const out = [];
  const stack = [{ dir: root, depth: 0 }];
  while (stack.length > 0 && out.length < maxFiles) {
    const { dir, depth } = stack.pop();
    if (depth > maxDepth) continue;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const ent of entries) {
      if (out.length >= maxFiles) break;
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        stack.push({ dir: join(dir, ent.name), depth: depth + 1 });
      } else if (ent.isFile()) {
        out.push(join(dir, ent.name));
      }
    }
  }
  return out.sort();
}

function readSafe(file, maxBytes = MAX_FILE_BYTES) {
  try {
    const stat = statSync(file);
    if (!stat.isFile() || stat.size > maxBytes) return null;
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function modeString(mode) {
  return `0o${(mode & 0o777).toString(8)}`;
}

// ---------------------------------------------------------------------------
// Checks. Each receives `ctx = { base, workspace, baseDir, files, env }` and
// returns { status, message, evidence?, remediation? }. id/category/severity
// come from the registry entry.
// ---------------------------------------------------------------------------

function checkConfigSecrets(ctx) {
  const findings = [];
  for (const file of ctx.files) {
    if (!CONFIG_EXTS.has(file.slice(file.lastIndexOf('.')))) continue;
    const content = readSafe(file);
    if (content === null) continue;
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      // Optional `- ` prefix so YAML/TOML list items (`- key: value`) are
      // inspected too, not just top-level keys.
      const m = /^\s*(?:-\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*["']?([^"'\s][^"']*)/.exec(line);
      if (!m) continue;
      const key = m[1];
      const value = m[2].trim().replace(/["',;\s]+$/, '');
      if (!SECRET_KEY_RE.test(key)) continue;
      if (value === '' || PLACEHOLDER_RE.test(value)) continue;
      findings.push({
        rel: norm(ctx.base, ctx.workspace, file),
        key,
        line: i + 1,
      });
      if (findings.length >= 10) break;
    }
    if (findings.length >= 10) break;
  }
  // Auxiliary signal: high-entropy values under NON-secret key names (random
  // tokens with no recognizable key). This is a review hint only — it never
  // escalates the check to fail, so normal configs with random non-secret
  // values (UUIDs, salts, ports) are not hard-flagged.
  const entropyHints = [];
  if (findings.length < 10) {
    for (const file of ctx.files) {
      if (!CONFIG_EXTS.has(file.slice(file.lastIndexOf('.')))) continue;
      const content = readSafe(file);
      if (content === null) continue;
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i += 1) {
        const m = /^\s*(?:-\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*["']?([^"'\s][^"']*)/.exec(lines[i]);
        if (!m) continue;
        const key = m[1];
        if (SECRET_KEY_RE.test(key)) continue; // key channel already covers it
        const value = m[2].trim().replace(/["',;\s]+$/, '');
        if (value.length < 24 || PLACEHOLDER_RE.test(value)) continue;
        if (isHighEntropyValue(value)) {
          entropyHints.push({ rel: norm(ctx.base, ctx.workspace, file), key, line: i + 1 });
          if (entropyHints.length >= MAX_ENTROPY_SIGNALS) break;
        }
      }
      if (entropyHints.length >= MAX_ENTROPY_SIGNALS) break;
    }
  }

  if (findings.length === 0) {
    if (entropyHints.length === 0) {
      return { status: 'pass', message: 'no embedded secrets found in configuration files' };
    }
    const hintEvidence = entropyHints
      .map((f) => `${f.rel}:${f.line} ${f.key} (high-entropy value)`)
      .join(' | ');
    return {
      status: 'info',
      message: `${entropyHints.length} high-entropy value(s) found under non-secret key names (review)`,
      evidence: sanitize(ctx.base, ctx.workspace, hintEvidence),
      remediation: 'if these are real secrets, move them to the DSH credential store; otherwise document them',
    };
  }
  const evidence = findings
    .map((f) => `${f.rel}:${f.line} ${f.key} set to ${maskSecret('xxxxxxxx')}`)
    .join(' | ');
  const entropyNote = entropyHints.length > 0 ? ` + ${entropyHints.length} high-entropy value(s) under other keys` : '';
  // When the hard cap is hit, say so — "10" must not read as the total.
  const capNote = findings.length >= 10 ? ' (listing capped at 10; more may exist)' : '';
  return {
    status: 'fail',
    message: `${findings.length} secret-like key(s) found in configuration files${capNote}`,
    evidence: sanitize(ctx.base, ctx.workspace, evidence + entropyNote),
    remediation: 'move secrets to the DSH credential store or environment and rotate the exposed values',
  };
}

function checkConfigPermissions(ctx) {
  const warnings = [];
  const targets = [ctx.baseDir, ...ctx.files.slice(0, 20)];
  for (const target of targets) {
    let stat;
    try {
      stat = statSync(target);
    } catch {
      continue;
    }
    if ((stat.mode & 0o022) !== 0) {
      warnings.push(`${norm(ctx.base, ctx.workspace, target)} is group/other-writable (${modeString(stat.mode)})`);
    }
  }
  if (warnings.length === 0) {
    return { status: 'pass', message: 'audited paths are not group/other-writable (best-effort on Windows)' };
  }
  return {
    status: 'warn',
    message: `${warnings.length} path(s) group/other-writable`,
    evidence: sanitize(ctx.base, ctx.workspace, warnings.join(' | ')),
    remediation: 'tighten ACLs so only the owning user can write configuration',
  };
}

function checkSessionsStructure(ctx) {
  const sessionsDir = join(ctx.baseDir, 'sessions');
  let files = [];
  try {
    files = readdirSync(sessionsDir).sort().slice(0, 500);
  } catch {
    return {
      status: 'info',
      message: 'no sessions directory found — nothing to audit (fresh install?)',
      remediation: 'nothing to do',
    };
  }
  return {
    status: 'info',
    message: `found ${files.length} session file(s) in sessions/`,
    evidence: sanitize(ctx.base, ctx.workspace, `sessions/ contains ${files.length} file(s)`),
  };
}

function checkSessionsSensitive(ctx) {
  const sessionsDir = join(ctx.baseDir, 'sessions');
  let files;
  try {
    files = readdirSync(sessionsDir).sort();
  } catch {
    return { status: 'pass', message: 'no sessions directory to inspect' };
  }
  const types = new Map();
  let inspected = 0;
  for (const name of files.slice(0, ctx.sampleLimit)) {
    const content = readSafe(join(sessionsDir, name));
    if (content === null) continue;
    inspected += 1;
    const { findings } = redactText(content);
    for (const f of findings) {
      types.set(f.type, (types.get(f.type) ?? 0) + f.count);
    }
  }
  if (inspected === 0) {
    return { status: 'pass', message: 'no readable session files found in sample' };
  }
  if (types.size === 0) {
    return {
      status: 'pass',
      message: `no PII detected in ${inspected} sampled session file(s)`,
      evidence: sanitize(ctx.base, ctx.workspace, `sampled ${inspected} session file(s)`),
    };
  }
  const summary = [...types.entries()].map(([t, n]) => `${t}×${n}`).join(', ');
  return {
    status: 'warn',
    message: `PII detected in ${inspected} sampled session file(s) (${summary})`,
    evidence: sanitize(ctx.base, ctx.workspace, `session files contain redactable PII: ${summary}`),
    remediation: 'consider session-log retention limits, encryption at rest, and not persisting raw tool outputs',
  };
}

function packageDirsUnder(root) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return out;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const direct = join(root, entry.name);
    if (readSafe(join(direct, 'package.json'), 128 * 1024) !== null) {
      out.push(direct);
      continue;
    }
    // scoped package: <root>/@scope/<name>
    let scoped;
    try {
      scoped = readdirSync(direct, { withFileTypes: true });
    } catch {
      continue;
    }
    scoped.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const s of scoped) {
      if (s.isDirectory() && !s.name.startsWith('.')) {
        const p = join(direct, s.name);
        if (readSafe(join(p, 'package.json'), 128 * 1024) !== null) out.push(p);
      }
    }
  }
  return out;
}

/**
 * Inventory installed plugin packages (name + version). Only packages with
 * a `dsh` manifest count; transitive dependencies are excluded. Used by the
 * plugins-inventory and deps-supply-chain checks.
 */
function listPluginPackages(baseDir) {
  const roots = [join(baseDir, 'plugins'), join(baseDir, 'node_modules', '@deepseek-ai')];
  // Community bundles live in each profile's own node_modules; inventory them
  // too, or a machine that only installs plugins per-profile reads as empty.
  const profilesDir = join(baseDir, 'profiles');
  let profiles;
  try {
    profiles = readdirSync(profilesDir, { withFileTypes: true });
  } catch {
    profiles = [];
  }
  for (const p of profiles) {
    if (p.isDirectory() && !p.name.startsWith('.')) {
      roots.push(join(profilesDir, p.name, 'node_modules'));
    }
  }
  const plugins = [];
  for (const root of roots) {
    for (const dir of packageDirsUnder(root)) {
      const pkg = readSafe(join(dir, 'package.json'), 128 * 1024);
      if (pkg === null) continue;
      let manifest;
      try {
        manifest = JSON.parse(pkg);
      } catch {
        continue; // unreadable manifest — cannot be counted as a plugin
      }
      // Only packages declaring a `dsh` manifest are plugins; transitive
      // dependencies (js-yaml, undici, ...) must not show up in the list.
      if (manifest === null || typeof manifest !== 'object' || !Object.hasOwn(manifest, 'dsh')) continue;
      const version = typeof manifest.version === 'string' ? manifest.version : '?';
      const parts = dir.split(sep);
      const name = parts.length >= 2 && parts[parts.length - 2].startsWith('@')
        ? parts.slice(-2).join('/')
        : parts[parts.length - 1];
      plugins.push({ name, version });
    }
  }
  return plugins;
}

function listPlugins(baseDir) {
  return listPluginPackages(baseDir).map((p) => `${p.name}@${p.version}`);
}

function checkPluginsInventory(ctx) {
  const plugins = listPlugins(ctx.baseDir);
  return {
    status: 'info',
    message: `found ${plugins.length} local plugin package(s)`,
    evidence: sanitize(ctx.base, ctx.workspace, plugins.slice(0, 30).join(', ')),
  };
}

function checkPluginsPatchSources(ctx) {
  const remote = [];
  for (const file of ctx.files) {
    const name = file.slice(file.lastIndexOf(sep) + 1);
    if (name !== 'cordis.patch.yml' && name !== 'cordis.yml') continue;
    const content = readSafe(file, 256 * 1024);
    if (content === null) continue;
    for (const line of content.split(/\r?\n/)) {
      if (/(git\+https?:\/\/|https?:\/\/.*(?:github|gitlab|gitee))/i.test(line)) {
        remote.push(`${norm(ctx.base, ctx.workspace, file)}: ${line.trim().slice(0, 80)}`);
      }
    }
  }
  if (remote.length === 0) {
    return { status: 'pass', message: 'no remote-source plugin patch lines found' };
  }
  return {
    status: 'warn',
    message: `${remote.length} plugin patch line(s) reference remote sources`,
    evidence: sanitize(ctx.base, ctx.workspace, remote.slice(0, 10).join(' | ')),
    remediation: 'pin exact plugin versions and prefer registry-installed bundles',
  };
}

function checkPathsPermissions(ctx) {
  const warnings = [];
  const targets = [ctx.baseDir];
  if (ctx.workspace) targets.push(ctx.workspace);
  for (const target of targets) {
    let stat;
    try {
      stat = statSync(target);
    } catch {
      continue;
    }
    if ((stat.mode & 0o022) !== 0) {
      warnings.push(`${norm(ctx.base, ctx.workspace, target)} is group/other-writable (${modeString(stat.mode)})`);
    }
  }
  if (ctx.workspace && ctx.workspace.startsWith(tmpdir())) {
    warnings.push('workspace lives inside the system temp directory');
  }
  if (warnings.length === 0) {
    return { status: 'pass', message: 'key paths have sane permissions (best-effort on Windows)' };
  }
  return {
    status: 'warn',
    message: `${warnings.length} path issue(s)`,
    evidence: sanitize(ctx.base, ctx.workspace, warnings.join(' | ')),
    remediation: 'restrict write access on these directories',
  };
}

/**
 * Parse /proc/net/{tcp,tcp6} for LISTEN sockets bound to ALL interfaces
 * (0.0.0.0 / ::). Pure read-only fs parse — no child processes (the dsh.so
 * vet scan flags childProcess, and the plugin keeps zero process spawning).
 * Local address is hex: IPv4 bytes are little-endian, IPv6 groups likewise;
 * we only care whether the address is all-zero (wildcard bind).
 */
function parseProcNetWildcardBinds(netProcDir) {
  const issues = [];
  for (const file of ['tcp', 'tcp6']) {
    let content;
    try {
      content = readFileSync(join(netProcDir, file), 'utf8');
    } catch {
      continue;
    }
    for (const line of content.split(/\r?\n/)) {
      const fields = line.trim().split(/\s+/);
      if (fields.length < 4 || fields[3] !== PROC_NET_LISTEN) continue;
      const local = fields[1];
      const colon = local.indexOf(':');
      if (colon < 0) continue;
      const hexAddr = local.slice(0, colon);
      const hexPort = local.slice(colon + 1);
      if (hexAddr.length === 0 || /[^0]/.test(hexAddr)) continue; // only wildcard binds
      const port = Number.parseInt(hexPort, 16);
      if (!Number.isFinite(port)) continue;
      issues.push(`${file === 'tcp' ? '0.0.0.0' : '[::]'}:${port} LISTEN on all interfaces (/proc/net/${file})`);
    }
  }
  return issues;
}

function checkNetworkBindings(ctx) {
  const issues = [];
  for (const [key, value] of Object.entries(ctx.env ?? process.env)) {
    if (!BIND_RE.test(key)) continue;
    if (/0\.0\.0\.0|::/.test(String(value))) {
      issues.push(`env.${key} binds 0.0.0.0/:: (${key}=${String(value).slice(0, 40)})`);
    }
  }
  for (const file of ctx.files) {
    if (!CONFIG_EXTS.has(file.slice(file.lastIndexOf('.')))) continue;
    const content = readSafe(file, 256 * 1024);
    if (content === null) continue;
    for (const line of content.split(/\r?\n/)) {
      if (/^\s*(host|bind|listen)\s*:\s*["']?0\.0\.0\.0/.test(line)) {
        issues.push(`${norm(ctx.base, ctx.workspace, file)}: ${line.trim().slice(0, 80)}`);
      }
    }
  }
  // Linux ground truth: /proc/net/{tcp,tcp6} LISTEN sockets bound to all
  // interfaces (0.0.0.0 / ::). Read-only fs parse; the config/env channels
  // above stay as the cross-platform signal.
  if (ctx.scanProcNet) {
    for (const entry of parseProcNetWildcardBinds(ctx.netProcDir)) {
      issues.push(entry);
    }
  }
  const interfaces = networkInterfaces();
  const active = Object.values(interfaces)
    .flat()
    .filter((i) => i && !i.internal && i.family === 'IPv4');
  const base = {
    status: issues.length > 0 ? 'warn' : 'pass',
    message: issues.length > 0
      ? `${issues.length} network binding(s) listen on all interfaces`
      : 'no all-interface bindings detected from env/config',
    remediation: issues.length > 0
      ? 'bind the DSH web server to 127.0.0.1 or a VPN address when remote access is not required'
      : undefined,
  };
  if (issues.length > 0) {
    base.evidence = sanitize(ctx.base, ctx.workspace, issues.slice(0, 10).join(' | '));
  } else {
    base.evidence = sanitize(ctx.base, ctx.workspace, `${active.length} active non-loopback IPv4 interface(s)`);
  }
  return base;
}

function checkEnvSecrets(ctx) {
  const found = [];
  const env = ctx.env ?? process.env;
  for (const key of Object.keys(env)) {
    if (!ENV_SECRET_RE.test(key)) continue;
    const value = env[key];
    if (value === undefined || value === '' || value === 'undefined') continue;
    found.push(`env.${key} set`);
    if (found.length >= 20) break;
  }
  if (found.length === 0) {
    return { status: 'pass', message: 'no secret-like environment variables set' };
  }
  return {
    status: 'warn',
    message: `${found.length} secret-like environment variable(s) set`,
    evidence: sanitize(ctx.base, ctx.workspace, found.join(' | ')),
    remediation: 'verify each variable is required, rotate secrets, and prefer scoped secret stores',
  };
}

/**
 * Supply-chain posture for installed plugins (OWASP LLM03 / Agentic Supply
 * Chain). Default is fully OFFLINE and deterministic: inventory only, with
 * a pointer to upstream advisories. The live registry lookup is OPT-IN
 * (config `supplyChainLive: true`) and sends package names+versions to
 * registry.npmjs.org — a deliberate, documented disclosure, so it stays
 * off by default for a read-only security plugin.
 */
async function checkDepsSupplyChain(ctx) {
  const pkgs = listPluginPackages(ctx.baseDir);
  if (pkgs.length === 0) {
    return { status: 'info', message: 'no plugin packages to check', evidence: '' };
  }
  const inventory = pkgs.slice(0, 30).map((p) => `${p.name}@${p.version}`).join(', ');
  if (!ctx.supplyChainLive) {
    return {
      status: 'info',
      message: `${pkgs.length} plugin package(s) inventoried (offline; enable supplyChainLive for registry advisory checks)`,
      evidence: sanitize(ctx.base, ctx.workspace, inventory),
      remediation: 'review upstream advisories for these packages before upgrading',
    };
  }
  const dependencies = {};
  for (const p of pkgs) dependencies[p.name] = { version: p.version };
  const payload = { name: 'dsh-secure-audit', version: '0.0.0', requires: {}, dependencies };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ctx.supplyChainTimeoutMs);
    let response;
    try {
      response = await ctx.fetchImpl(NPM_AUDIT_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const vulns = data?.metadata?.vulnerabilities ?? {};
    const total = Object.values(vulns).reduce((sum, n) => sum + (Number(n) || 0), 0);
    if (total > 0) {
      const detail = Object.entries(vulns).filter(([, n]) => n > 0).map(([k, n]) => `${k}×${n}`).join(', ');
      return {
        status: 'warn',
        message: `${total} known advisory(ies) across ${pkgs.length} plugin package(s)`,
        evidence: sanitize(ctx.base, ctx.workspace, `${inventory} | advisories: ${detail}`),
        remediation: 'upgrade affected packages to patched versions and re-run the audit',
      };
    }
    return {
      status: 'pass',
      message: `no known advisories for ${pkgs.length} plugin package(s) (registry check)`,
      evidence: sanitize(ctx.base, ctx.workspace, `${pkgs.length} package(s) checked against registry.npmjs.org`),
    };
  } catch (err) {
    return {
      status: 'info',
      message: 'supply-chain registry check could not complete (offline?)',
      evidence: sanitize(ctx.base, ctx.workspace, `registry lookup failed (${err?.name ?? 'error'})`),
      remediation: 're-run with network access or rely on the offline inventory',
    };
  }
}

/**
 * Host runtime capabilities (injected by the plugin entry from apply();
 * standalone use reports the fallback message). Lets users see in one line
 * what the running harness provides — dsh-tools / dsh-session versions and
 * whether the skills service is available.
 */
function checkHostCapabilities(ctx) {
  const h = ctx.hostInfo;
  if (!h || typeof h !== 'object') {
    return { status: 'info', message: 'host capabilities not available outside the DSH runtime', evidence: '' };
  }
  const items = [
    `dsh-tools ${h.dshToolsVersion ?? 'unknown'}`,
    `skills ${h.skillsAvailable ? 'available' : 'absent'}`,
    `dsh-session ${h.dshSessionVersion ?? 'n/a'}`,
    `ruleset v${h.ruleset ?? '?'}`,
    `plugin v${h.pluginVersion ?? PLUGIN_VERSION}`,
  ];
  return {
    status: 'info',
    message: `host capabilities: ${items.join('; ')}`,
    evidence: sanitize(ctx.base, ctx.workspace, items.join(' | ')),
  };
}

// ---------------------------------------------------------------------------
// Registry + runner
// ---------------------------------------------------------------------------

const CHECKS = Object.freeze([
  // owasp: OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10);
  // agentic: OWASP Agentic Top 10 category names (2026).
  { id: 'config-secrets', category: 'config', severity: 'high', owasp: 'LLM02', agentic: 'Insecure Secrets Management', run: checkConfigSecrets },
  { id: 'config-permissions', category: 'config', severity: 'medium', owasp: null, agentic: 'Privilege Confusion', run: checkConfigPermissions },
  { id: 'sessions-structure', category: 'sessions', severity: 'info', owasp: 'LLM02', agentic: 'Insecure Memory', run: checkSessionsStructure },
  { id: 'sessions-sensitive-content', category: 'sessions', severity: 'medium', owasp: 'LLM02', agentic: 'Insecure Memory', run: checkSessionsSensitive },
  { id: 'plugins-inventory', category: 'plugins', severity: 'info', owasp: 'LLM03', agentic: 'Supply Chain', run: checkPluginsInventory },
  { id: 'plugins-patch-sources', category: 'plugins', severity: 'medium', owasp: 'LLM03', agentic: 'Supply Chain', run: checkPluginsPatchSources },
  { id: 'deps-supply-chain', category: 'plugins', severity: 'medium', owasp: 'LLM03', agentic: 'Supply Chain', run: checkDepsSupplyChain },
  { id: 'paths-permissions', category: 'paths', severity: 'medium', owasp: null, agentic: 'Unbounded Agency', run: checkPathsPermissions },
  { id: 'network-bindings', category: 'network', severity: 'medium', owasp: null, agentic: null, run: checkNetworkBindings },
  { id: 'env-secrets', category: 'env', severity: 'medium', owasp: 'LLM02', agentic: 'Insecure Secrets Management', run: checkEnvSecrets },
  { id: 'host-capabilities', category: 'host', severity: 'info', owasp: null, agentic: null, run: checkHostCapabilities },
]);

/**
 * Run the read-only audit.
 * @param {object} [options]
 * @param {string[]|string} [options.scope] subset of CHECK_SCOPES; default all
 * @param {string} [options.baseDir] audited root (default: $DSH_HOME or ~/.dsh)
 * @param {string} [options.workspace] optional workspace path to include
 * @returns {Promise<object>} report (see README for the shape)
 */
export async function runSecurityAudit(userOptions = {}) {
  const requested = userOptions.scope ?? CHECK_SCOPES;
  const scopes = new Set(Array.isArray(requested) ? requested : [requested]);
  for (const scope of scopes) {
    if (!CHECK_SCOPES.includes(scope)) {
      throw new TypeError(`security_audit: unknown scope "${scope}" (allowed: ${CHECK_SCOPES.join(', ')})`);
    }
  }

  const baseDir = resolve(userOptions.baseDir ?? defaultBaseDir());
  const workspace = userOptions.workspace ? resolve(userOptions.workspace) : undefined;

  // Profile tiers: `quick` shrinks the file/session budgets for large trees;
  // `full` (default) keeps the full deterministic walk. Budgets are also
  // overridable per call (maxFiles/maxBytes).
  const profile = userOptions.profile === 'quick' ? 'quick' : 'full';
  const maxFiles = profile === 'quick'
    ? 50
    : Number.isInteger(userOptions.maxFiles) && userOptions.maxFiles > 0 ? userOptions.maxFiles : MAX_FILES;
  const maxBytes = Number.isInteger(userOptions.maxBytes) && userOptions.maxBytes > 0
    ? userOptions.maxBytes
    : MAX_FILE_BYTES;
  const files = collectFiles(baseDir, { maxFiles });
  const userSampleLimit = Number.isInteger(userOptions.sampleLimit) && userOptions.sampleLimit > 0
    ? userOptions.sampleLimit
    : 10;
  const sampleLimit = profile === 'quick' ? Math.min(userSampleLimit, 3) : userSampleLimit;
  // Live supply-chain registry lookup is opt-in (config `supplyChainLive`)
  // and disabled in the quick profile. Default offline keeps the report
  // deterministic and avoids phoning the local plugin inventory anywhere.
  const supplyChainLive = userOptions.supplyChainLive === true && profile !== 'quick';
  const supplyChainTimeoutMs = Number.isInteger(userOptions.supplyChainTimeoutMs) && userOptions.supplyChainTimeoutMs > 0
    ? userOptions.supplyChainTimeoutMs
    : SUPPLY_CHAIN_TIMEOUT_MS;

  const ctx = {
    base: baseDir,
    workspace,
    baseDir,
    files,
    maxBytes,
    sampleLimit,
    env: process.env,
    profile,
    hostInfo: userOptions.hostInfo ?? null,
    supplyChainLive,
    supplyChainTimeoutMs,
    fetchImpl: typeof userOptions.fetchImpl === 'function' ? userOptions.fetchImpl : globalThis.fetch,
    netProcDir: userOptions.netProcDir ?? join('/proc', 'net'),
    // Linux runs the /proc/net ground-truth scan by default; passing an
    // explicit netProcDir (test hook) forces it on any platform.
    scanProcNet: platform() === 'linux' || Boolean(userOptions.netProcDir),
  };

  const checks = [];
  for (const entry of CHECKS) {
    if (!scopes.has(entry.category)) continue;
    let outcome;
    try {
      outcome = await entry.run(ctx);
    } catch (err) {
      outcome = {
        status: 'error',
        message: `check could not complete (${err?.name ?? 'error'})`,
        evidence: undefined,
        remediation: 'review this area manually',
      };
    }
    checks.push({
      id: entry.id,
      category: entry.category,
      severity: entry.severity,
      // dsh-tools string schemas coerce null to ''; keep the declared
      // schema simple ('string') by normalizing absent mappings to ''.
      owasp: entry.owasp ?? '',
      agentic: entry.agentic ?? '',
      status: outcome.status,
      message: outcome.message,
      evidence: outcome.evidence ?? '',
      remediation: outcome.remediation ?? '',
    });
  }

  const summary = { pass: 0, warn: 0, fail: 0, error: 0, info: 0 };
  for (const check of checks) summary[check.status] = (summary[check.status] ?? 0) + 1;

  // Declared limits travel with the report so consumers never mistake a
  // posture snapshot for a certification. Platform-specific items are
  // conditional on the machine the audit ran on.
  const limitations = [
    'read-only posture snapshot; not a certification, and absence of findings does not imply safety',
    'embedded-secret and PII detection is regex/heuristic and may miss or over-flag',
    `session-file PII sampling covers up to ${sampleLimit} file(s); larger directories are bounded by design`,
    ...(profile === 'quick' ? ['quick profile: reduced file/session sampling budgets apply'] : []),
    ...(supplyChainLive ? ['supply-chain check queried the npm registry (opt-in); advisory state can change between runs'] : []),
    ...(platform() === 'linux'
      ? []
      : ['live listening-port check (/proc/net) runs on Linux only; other platforms rely on env/config evidence']),
    ...(platform() === 'win32'
      ? ['file-permission checks use POSIX mode bits; Windows ACLs are not inspected']
      : []),
  ];

  const report = {
    plugin: 'dsh-secure-audit',
    version: PLUGIN_VERSION,
    generatedAt: new Date().toISOString(),
    baseDir: '<base>',
    workspace: workspace ? '<workspace>' : '',
    profile,
    scopesAudited: [...scopes].sort(),
    checks,
    summary,
    limitations,
  };

  // Self-checksum over the deterministic report body (drop `generatedAt` for
  // a stable hash): consumers can verify a report was not altered in transit
  // and diff two runs byte-for-byte. Computed over the body, so it never
  // depends on its own value.
  const { generatedAt, ...body } = report;
  const reportSha256 = createHash('sha256').update(JSON.stringify(body)).digest('hex');
  return { ...report, reportSha256 };
}
