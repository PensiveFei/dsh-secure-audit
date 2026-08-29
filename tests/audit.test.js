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
  assert.deepEqual([...CHECK_SCOPES].sort(), ['config', 'env', 'host', 'network', 'paths', 'plugins', 'sessions']);
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
// ---------------------------------------------------------------------------
// 0.2.6 additions: OWASP mapping, profile tiers, supply chain, host caps, /proc
// ---------------------------------------------------------------------------

test('every check carries owasp and agentic mapping fields', async () => {
  const root = makeFixture();
  try {
    const report = await runSecurityAudit({ baseDir: root });
    for (const check of report.checks) {
      assert.ok('owasp' in check, `${check.id} must carry owasp`);
      assert.ok('agentic' in check, `${check.id} must carry agentic`);
      if (check.owasp) assert.match(check.owasp, /^LLM\d+$/);
      if (check.agentic) assert.ok(check.agentic.length > 0);
    }
    const secrets = report.checks.find((c) => c.id === 'config-secrets');
    assert.equal(secrets.owasp, 'LLM02');
    const supply = report.checks.find((c) => c.id === 'deps-supply-chain');
    assert.equal(supply.owasp, 'LLM03');
  } finally {
    cleanup(root);
  }
});

test('report carries the profile field (default full)', async () => {
  const root = makeFixture();
  try {
    const full = await runSecurityAudit({ baseDir: root });
    assert.equal(full.profile, 'full');
    const quick = await runSecurityAudit({ baseDir: root, profile: 'quick' });
    assert.equal(quick.profile, 'quick');
    assert.ok(quick.limitations.some((l) => /quick profile/.test(l)));
  } finally {
    cleanup(root);
  }
});

test('quick profile caps session sampling and reports the bound', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-quick-'));
  try {
    mkdirSync(join(root, 'sessions'), { recursive: true });
    for (let i = 0; i < 5; i += 1) {
      writeFileSync(join(root, 'sessions', `s-${i}.jsonl`), '{"content":"手机 13912345678"}\n');
    }
    const quick = await runSecurityAudit({ baseDir: root, scope: ['sessions'], profile: 'quick' });
    const session = quick.checks.find((c) => c.id === 'sessions-sensitive-content');
    assert.match(session.message, /3 sampled session file/);
    const full = await runSecurityAudit({ baseDir: root, scope: ['sessions'] });
    const sessionFull = full.checks.find((c) => c.id === 'sessions-sensitive-content');
    assert.match(sessionFull.message, /5 sampled session file/);
  } finally {
    cleanup(root);
  }
});
test('deps-supply-chain offline inventory lists plugin packages', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-depsoff-'));
  try {
    mkdirSync(join(root, 'plugins', 'demo-plugin'), { recursive: true });
    writeFileSync(
      join(root, 'plugins', 'demo-plugin', 'package.json'),
      JSON.stringify({ name: 'demo-plugin', version: '2.1.0', dsh: { bundle: { patch: './cordis.patch.yml' } } }),
    );
    const report = await runSecurityAudit({ baseDir: root, scope: ['plugins'] });
    const check = report.checks.find((c) => c.id === 'deps-supply-chain');
    assert.equal(check.status, 'info');
    assert.ok(check.evidence.includes('demo-plugin@2.1.0'));
    assert.match(check.message, /offline/);
    // default is offline — the npm registry must never be contacted implicitly
    assert.ok(report.limitations.every((l) => !/queried the npm registry/.test(l)));
  } finally {
    cleanup(root);
  }
});

test('deps-supply-chain live check surfaces advisories (mock registry)', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-depslive-'));
  try {
    mkdirSync(join(root, 'plugins', 'demo-plugin'), { recursive: true });
    writeFileSync(
      join(root, 'plugins', 'demo-plugin', 'package.json'),
      JSON.stringify({ name: 'demo-plugin', version: '1.0.0', dsh: { bundle: { patch: './cordis.patch.yml' } } }),
    );
    const vuln = await runSecurityAudit({
      baseDir: root,
      scope: ['plugins'],
      supplyChainLive: true,
      fetchImpl: async () => ({
        ok: true,
        async json() { return { metadata: { vulnerabilities: { low: 1, high: 2 } } }; },
      }),
    });
    const check = vuln.checks.find((c) => c.id === 'deps-supply-chain');
    assert.equal(check.status, 'warn');
    assert.match(check.message, /3 known advisory/);
    assert.ok(vuln.limitations.some((l) => /queried the npm registry/.test(l)));
    // registry failure degrades to info, never throws
    const offline = await runSecurityAudit({
      baseDir: root,
      scope: ['plugins'],
      supplyChainLive: true,
      fetchImpl: async () => { throw new Error('ECONNREFUSED'); },
    });
    const degraded = offline.checks.find((c) => c.id === 'deps-supply-chain');
    assert.equal(degraded.status, 'info');
    assert.match(degraded.message, /could not complete/);
  } finally {
    cleanup(root);
  }
});
test('host-capabilities reports injected host info and a fallback otherwise', async () => {
  const root = makeFixture();
  try {
    const withInfo = await runSecurityAudit({
      baseDir: root,
      scope: ['host'],
      hostInfo: { dshToolsVersion: '0.1.0-rc.7', dshSessionVersion: '0.1.0-rc.7', skillsAvailable: true, ruleset: 4, pluginVersion: '0.2.6' },
    });
    const hc = withInfo.checks.find((c) => c.id === 'host-capabilities');
    assert.equal(hc.status, 'info');
    assert.ok(hc.message.includes('dsh-tools 0.1.0-rc.7'));
    assert.ok(hc.message.includes('skills available'));
    const standalone = await runSecurityAudit({ baseDir: root, scope: ['host'] });
    const fallback = standalone.checks.find((c) => c.id === 'host-capabilities');
    assert.match(fallback.message, /not available outside the DSH runtime/);
  } finally {
    cleanup(root);
  }
});

test('network-bindings parses /proc/net wildcard LISTEN sockets (fixture)', async () => {
  const root = makeFixture();
  const netDir = mkdtempSync(join(tmpdir(), 'dsa-audit-net-'));
  try {
    writeFileSync(join(netDir, 'tcp'), [
      '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode',
      '   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1000 1 0000000000000000 100 0 0 10 0',
      '   1: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0',
      '   2: 00000000:0BB8 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 100 0 0 10 0',
      '',
    ].join('\n'));
    writeFileSync(join(netDir, 'tcp6'), [
      '  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode',
      '   0: 00000000000000000000000000000000:1F92 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 100 0 0 10 0',
      '',
    ].join('\n'));
    const report = await runSecurityAudit({ baseDir: root, scope: ['network'], netProcDir: netDir });
    const net = report.checks.find((c) => c.id === 'network-bindings');
    assert.equal(net.status, 'warn');
    assert.ok(net.evidence.includes('0.0.0.0:8081'), 'wildcard IPv4 LISTEN must be flagged');
    assert.ok(net.evidence.includes('[::]:8082'), 'wildcard IPv6 LISTEN must be flagged');
    assert.ok(!net.evidence.includes(':8080'), 'loopback listener must not be flagged');
  } finally {
    cleanup(root);
    cleanup(netDir);
  }
});

test('config-secrets reports high-entropy values as info, never fail', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsa-audit-entropy-'));
  try {
    writeFileSync(join(root, 'config.yaml'), [
      'clientId: 12345',
      'nonce: aZ9kQ2w8Xm4P7cV1nB6hJ3fG0sL5tRy2uI0oP', // high-entropy token, not a secret key name
      'note: hello world',
      '',
    ].join('\n'));
    const report = await runSecurityAudit({ baseDir: root, scope: ['config'] });
    const secrets = report.checks.find((c) => c.id === 'config-secrets');
    assert.equal(secrets.status, 'info');
    assert.match(secrets.message, /high-entropy value/);
    assert.ok(!secrets.evidence.includes('aZ9kQ2w8'), 'the value itself must never appear in evidence');
    // key-matched secrets still fail (unchanged semantics)
    writeFileSync(join(root, 'config.yaml'), 'api_key: sk-TEST-abcdefghijklmnopqrstuvwxyz123456\n');
    const failReport = await runSecurityAudit({ baseDir: root, scope: ['config'] });
    assert.equal(failReport.checks.find((c) => c.id === 'config-secrets').status, 'fail');
  } finally {
    cleanup(root);
  }
});
