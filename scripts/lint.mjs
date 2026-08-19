/**
 * Lint for dsh-secure-audit.
 *
 * 1. Syntax-checks every JS file with `node --check`.
 * 2. Scans the tree for accidentally committed secrets (tokens, keys, JWTs,
 *    PEM private keys). Test fixtures deliberately contain fake-looking
 *    values; the markers "TEST" / "not-a-real-" keep them out of every
 *    pattern below, so no path allowlist is needed.
 *
 * Run from the repo root: `node scripts/lint.mjs` (CI: `npm run lint`).
 */

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = process.cwd();
const SKIP_DIRS = new Set(['node_modules', '.git', '.npm-cache', 'coverage', 'dist', 'build', 'out']);
const JS_EXT = new Set(['.js', '.mjs', '.cjs']);

const SECRET_PATTERNS = [
  [/gh[pousr]_[A-Za-z0-9]{10,}/, 'GitHub token (ghp_/gho_/ghs_/ghu_/ghr_)'],
  [/AKIA[0-9A-Z]{16}/, 'AWS access key'],
  [/AIza[0-9A-Za-z_-]{35}/, 'Google API key'],
  [/xox[baprs]-[A-Za-z0-9-]{8,}/, 'Slack token'],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, 'JWT'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'PEM private key'],
  [/sk-[A-Za-z0-9]{20,}/, 'OpenAI-style API key'],
];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      out.push(...walk(join(dir, entry.name)));
    } else if (entry.isFile() && JS_EXT.has(entry.name.slice(entry.name.lastIndexOf('.')))) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

let failed = 0;

// 1. syntax check
const files = walk(ROOT);
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { stdio: 'inherit' });
  if (result.status !== 0) {
    console.error(`lint: syntax error in ${relative(ROOT, file)}`);
    failed += 1;
  }
}

// 2. secret scan
for (const file of files) {
  const content = readFileSync(file, 'utf8');
  for (const [re, label] of SECRET_PATTERNS) {
    const match = re.exec(content);
    if (match) {
      const preview = match[0].slice(0, 24).replace(/[^ -~]/g, '?');
      console.error(`lint: possible ${label} in ${relative(ROOT, file)} (${preview}…)`);
      failed += 1;
    }
  }
}

if (failed > 0) {
  console.error(`lint: ${failed} problem(s) found`);
  process.exit(1);
}
console.log(`lint: ok (${files.length} files checked, no secrets found)`);
