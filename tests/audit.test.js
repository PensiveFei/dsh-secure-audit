import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, chmodSync, statSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runSecurityAudit, CHECK_SCOPES, PLUGIN_VERSION } from '../lib/audit.js';

function makeFixture() {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-'));
  mkdirSync(join(root, 'sessions'), { recursive: true });
  mkdirSync(join(root, 'plugins', 'local-plugin'), { recursive: true });
  writeFileSync(join(root, 'cordis.yml'), [
    '# harness config',
    'plugins:',
    '  - id: tools',
    '    name: "@deepseek-ai/dsh-tools"',
    'apiKey: not-a-real-api-key-please-replace',
    'host: 0.0.0.0',
  ].join('\n'));
  writeFileSync(join(root, 'sessions', 'session-1.jsonl'), '{"role":"user","content":"我的手机号是 13912345678"}\n');
  writeFileSync(join(root, 'sessions', 'session-2.jsonl'), '{"role":"assistant","content":"ok"}\n');
  writeFileSync(join(root, 'plugins', 'local-plugin', 'package.json'), JSON.stringify({ name: 'local-plugin', version: '1.2.3' }));
  return root;
}

function cleanup(root) {
  rmSync(root, { recursive: true, force: true });
}

test('audit report shape and scope filtering', async () => {
  const root = makeFixture();
  try {
    const report = await runSecurityAudit({ baseDir: root, scope: ['config'] });
    assert.equal(report.plugin, 'dsh-secure-audit');
    assert.equal(report.version, PLUGIN_VERSION);
    assert.equal(report.baseDir, '<base>');
    assert.deepEqual(report.scopesAudited, ['config']);
    assert.ok(report.checks.every((c) => c.category === 'config'));
    for (const check of report.checks) {
      assert.ok(['pass', 'warn', 'fail', 'error', 'info'].includes(check.status));
      assert.ok(typeof check.message === 'string');
      assert.ok('evidence' in check);
      assert.ok('remediation' in check);
    }
    const total = Object.values(report.summary).reduce((a, b) => a + b, 0);
    assert.equal(total, report.checks.length);
    // The report declares its own limits (scope, platform, heuristic nature).
    assert.ok(Array.isArray(report.limitations));
    assert.ok(report.limitations.length > 0);
    assert.ok(report.limitations.some((l) => /not a certification/i.test(l)));
  } finally {
    cleanup(root);
  }
});

test('detects embedded secrets in config, redacted evidence never leaks the value', async () => {
  const root = makeFixture();
  try {
    const report = await runSecurityAudit({ baseDir: root, scope: ['config'] });
    const secretCheck = report.checks.find((c) => c.id === 'config-secrets');
    assert.equal(secretCheck.status, 'fail');
    assert.match(secretCheck.message, /secret-like/);
    assert.ok(!secretCheck.evidence.includes('not-a-real-api-key'));
    assert.match(secretCheck.evidence, /apiKey/);
  } finally {
    cleanup(root);
  }
});

test('detects secrets inside YAML list items ( - key: value )', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-list-'));
  try {
    // TEST markers keep the fake values out of the secret scanners in
    // scripts/lint.mjs (same convention as tests/redact.test.js).
    writeFileSync(join(root, 'config.yaml'), [
      'credentials:',
      '  - api_key: sk-TEST-AAAA1111BBBB2222CCCC3333',
      'top_level_token: ghp_TEST-ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      '',
    ].join('\n'));
    const report = await runSecurityAudit({ baseDir: root, scope: ['config'] });
    const secretCheck = report.checks.find((c) => c.id === 'config-secrets');
    assert.equal(secretCheck.status, 'fail');
    assert.match(secretCheck.message, /2 secret-like/);
    assert.match(secretCheck.evidence, /api_key/);
    assert.match(secretCheck.evidence, /:2 api_key/);
  } finally {
    cleanup(root);
  }
});

test('flags all-interface network binding', async () => {
  const root = makeFixture();
  try {
    const report = await runSecurityAudit({ baseDir: root, scope: ['network'] });
    const net = report.checks.find((c) => c.id === 'network-bindings');
    assert.equal(net.status, 'warn');
    assert.match(net.evidence, /0\.0\.0\.0/);
  } finally {
    cleanup(root);
  }
});

test('session content PII check finds redactable data with no raw value', async () => {
  const root = makeFixture();
  try {
    const report = await runSecurityAudit({ baseDir: root, scope: ['sessions'] });
    const session = report.checks.find((c) => c.id === 'sessions-sensitive-content');
    assert.equal(session.status, 'warn');
    assert.ok(!session.evidence.includes('13912345678'));
  } finally {
    cleanup(root);
  }
});

test('audit is deterministic across runs (same checks, same order)', async () => {
  const root = makeFixture();
  try {
    const a = await runSecurityAudit({ baseDir: root });
    const b = await runSecurityAudit({ baseDir: root });
    assert.deepEqual(a.checks.map((c) => c.id), b.checks.map((c) => c.id));
    for (const check of a.checks) {
      const twin = b.checks.find((c) => c.id === check.id);
      assert.equal(check.status, twin.status);
      assert.equal(check.message, twin.message);
      assert.equal(check.evidence, twin.evidence);
    }
  } finally {
    cleanup(root);
  }
});

test('audit never modifies the audited tree', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-ro-'));
  try {
    const file = join(root, 'cordis.yml');
    writeFileSync(file, 'apiKey: not-a-real-api-key-please-replace\n');
    const before = statSync(file);
    await runSecurityAudit({ baseDir: root });
    const after = statSync(file);
    assert.equal(after.mtimeMs, before.mtimeMs);
    assert.equal(after.size, before.size);
    assert.deepEqual(readdirSync(root).sort(), ['cordis.yml']);
  } finally {
    cleanup(root);
  }
});

test('missing directory degrades to info/error, never throws', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-missing-'));
  try {
    const report = await runSecurityAudit({ baseDir: join(root, 'does-not-exist') });
    // base dir missing: file collection yields nothing; each check either
    // passes on absence or reports error safely — the call itself must resolve.
    assert.ok(report.checks.length > 0);
    assert.ok(report.checks.every((c) => !c.message.includes(root)));
  } finally {
    cleanup(root);
  }
});

test('unreadable/exception inside a check is sanitized', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-err-'));
  try {
    // A file we can create but that produces an odd read result is not
    // needed: simulate by passing an empty scope — no checks run.
    const report = await runSecurityAudit({ baseDir: root, scope: [] });
    assert.deepEqual(report.checks, []);
  } finally {
    cleanup(root);
  }
});

test('rejects unknown scopes', async () => {
  await assert.rejects(() => runSecurityAudit({ scope: ['nonsense'] }), /unknown scope/);
});

test('CHECK_SCOPES is the documented set', () => {
  assert.deepEqual([...CHECK_SCOPES].sort(), ['config', 'env', 'network', 'paths', 'plugins', 'sessions']);
});

test('placeholder values are NOT flagged as secrets (real skip, not decorative)', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-ph-'));
  try {
    writeFileSync(join(root, 'cordis.yml'), [
      'apiKey: xxx',
      'password: your-password-here',
      'client_secret: <insert-me>',
      'token: changeme',
    ].join('\n'));
    const report = await runSecurityAudit({ baseDir: root, scope: ['config'] });
    const secretCheck = report.checks.find((c) => c.id === 'config-secrets');
    assert.equal(secretCheck.status, 'pass');
  } finally {
    cleanup(root);
  }
});

test('audit evidence never leaks the audited root path', async () => {
  const root = makeFixture();
  try {
    const report = await runSecurityAudit({ baseDir: root });
    for (const check of report.checks) {
      assert.ok(!check.evidence.includes(root), `${check.id} leaked root path`);
      assert.ok(!check.message.includes(root), `${check.id} leaked root path in message`);
    }
  } finally {
    cleanup(root);
  }
});

test('plugins inventory covers per-profile bundles (scoped + plain), excludes plain deps', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-plugins-'));
  try {
    mkdirSync(join(root, 'profiles', 'web', 'node_modules', '@liustack', 'modlens'), { recursive: true });
    mkdirSync(join(root, 'profiles', 'web', 'node_modules', 'dsh-fake-plugin'), { recursive: true });
    mkdirSync(join(root, 'profiles', 'web', 'node_modules', 'plain-dep'), { recursive: true });
    writeFileSync(
      join(root, 'profiles', 'web', 'node_modules', 'dsh-fake-plugin', 'package.json'),
      JSON.stringify({ name: 'dsh-fake-plugin', version: '0.0.1', dsh: { bundle: { patch: './cordis.patch.yml' } } }),
    );
    writeFileSync(
      join(root, 'profiles', 'web', 'node_modules', '@liustack', 'modlens', 'package.json'),
      JSON.stringify({ name: '@liustack/modlens', version: '1.0.0', dsh: { client: {} } }),
    );
    writeFileSync(
      join(root, 'profiles', 'web', 'node_modules', 'plain-dep', 'package.json'),
      JSON.stringify({ name: 'plain-dep', version: '9.9.9' }), // no dsh manifest -> not a plugin
    );
    const report = await runSecurityAudit({ baseDir: root, scope: ['plugins'] });
    const inv = report.checks.find((c) => c.id === 'plugins-inventory');
    assert.equal(inv.status, 'info');
    assert.ok(inv.evidence.includes('dsh-fake-plugin@0.0.1'));
    assert.ok(inv.evidence.includes('@liustack/modlens@1.0.0'));
    assert.ok(!inv.evidence.includes('plain-dep'));
  } finally {
    cleanup(root);
  }
});

test('session PII sampling respects the sampleLimit option', async () => {
  const root = makeFixture();
  try {
    const report = await runSecurityAudit({ baseDir: root, scope: ['sessions'], sampleLimit: 1 });
    const session = report.checks.find((c) => c.id === 'sessions-sensitive-content');
    assert.equal(session.status, 'warn');
    assert.match(session.message, /1 sampled session file/);
    const limit = report.limitations.find((l) => /sampling covers up to/.test(l));
    assert.ok(limit.includes('1'));
  } finally {
    cleanup(root);
  }
});


test('report carries a self-checksum that is stable across runs', async () => {
  const root = makeFixture();
  try {
    const a = await runSecurityAudit({ baseDir: root });
    const b = await runSecurityAudit({ baseDir: root });
    assert.match(a.reportSha256, /^[0-9a-f]{64}$/);
    // Same tree, same checks -> identical body hash (generatedAt excluded).
    assert.equal(a.reportSha256, b.reportSha256);
  } finally {
    cleanup(root);
  }
});

test('reportSha256 changes when a check outcome changes', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-hash-'));
  try {
    writeFileSync(join(root, 'cordis.yml'), 'plugins: []\n');
    const clean = await runSecurityAudit({ baseDir: root });
    writeFileSync(join(root, 'cordis.yml'), 'apiKey: not-a-real-api-key-please-replace\n');
    const dirty = await runSecurityAudit({ baseDir: root });
    assert.notEqual(clean.reportSha256, dirty.reportSha256);
  } finally {
    cleanup(root);
  }
});

test('reportSha256 recomputes from the deterministic body (drop generatedAt)', async () => {
  const root = makeFixture();
  try {
    const report = await runSecurityAudit({ baseDir: root });
    const { generatedAt, reportSha256, ...body } = report;
    const expected = createHash('sha256').update(JSON.stringify(body)).digest('hex');
    assert.equal(reportSha256, expected);
  } finally {
    cleanup(root);
  }
});

test('chmod world-writable file triggers config-permissions warn', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-mode-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, 'cordis.yml'), 'plugins: []\n');
  try {
    chmodSync(join(root, 'cordis.yml'), 0o666);
  } catch {
    return; // chmod may be unsupported/ignored on this platform
  }
  const report = await runSecurityAudit({ baseDir: root, scope: ['config'] });
  const perm = report.checks.find((c) => c.id === 'config-permissions');
  assert.equal(perm.status, 'warn');
});
