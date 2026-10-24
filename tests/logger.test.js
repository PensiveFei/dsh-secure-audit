import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLogger } from '../lib/logger.js';

function capture() {
  const lines = [];
  return {
    sink: { log: (line) => lines.push(line) },
    lines,
  };
}

test('emits one JSON line per event with requestId', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  logger.child('req-1').emit('info', 'scan', { decision: 'allow', confidence: 0 });
  assert.equal(lines.length, 1);
  const parsed = JSON.parse(lines[0]);
  assert.equal(parsed.level, 'info');
  assert.equal(parsed.event, 'scan');
  assert.equal(parsed.requestId, 'req-1');
  assert.equal(parsed.decision, 'allow');
  assert.ok(typeof parsed.ts === 'string');
});

test('never logs raw text/content/evidence — auto-redacted', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  logger.child('req-2').emit('info', 'test', {
    text: '我的手机 13912345678 和邮箱 zhangsan@example.com',
    evidence: 'secret sk-TEST-abcdefghijklmnopqrstuvwxyz123456',
    decision: 'review',
  });
  const parsed = JSON.parse(lines[0]);
  assert.ok(!parsed.text.includes('13912345678'));
  assert.ok(!parsed.text.includes('zhangsan@example.com'));
  assert.ok(!parsed.evidence.includes('sk-TEST'));
  assert.equal(parsed.evidence, 'secret sk-TES********');
  assert.equal(parsed.decision, 'review'); // non-sensitive fields pass through
});

test('over-long strings are truncated', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  logger.child('req-3').emit('info', 'x', { note: 'a'.repeat(10_000) });
  const parsed = JSON.parse(lines[0]);
  assert.ok(parsed.note.length <= 4100);
});

test('redacts nested PII and sensitive keys in every field', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  logger.child('req-nested').emit('info', 'test', {
    note: 'call 13812345678',
    content: { password: 'not-a-real-secret', items: [{ evidence: 'zhangsan@example.com' }] },
    access_token: 'not-a-real-token',
  });
  const result = JSON.parse(lines[0]);
  assert.equal(result.note, 'call 138****5678');
  assert.deepEqual(result.content, {
    password: '[REDACTED]', items: [{ evidence: 'zh***@example.com' }],
  });
  assert.equal(result.access_token, '[REDACTED]');
});

test('caps strings within protected and nested fields too', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  logger.child('req-capped').emit('info', 'test', { text: 'a'.repeat(10_000), nested: ['b'.repeat(10_000)] });
  const result = JSON.parse(lines[0]);
  assert.equal(result.text.length, 4000);
  assert.equal(result.nested[0].length, 4000);
});

test('fields cannot forge audit metadata', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  logger.child('req-real').emit('warn', 'real_event', {
    ts: 'fake', level: 'info', event: 'forged_event', requestId: 'req-forged',
  });
  const result = JSON.parse(lines[0]);
  assert.notEqual(result.ts, 'fake');
  assert.equal(result.level, 'warn');
  assert.equal(result.event, 'real_event');
  assert.equal(result.requestId, 'req-real');
});

test('cyclic and non-JSON log fields do not crash the logger', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  const fields = { text: '13812345678' };
  fields.self = fields;
  logger.child('req-cycle').emit('info', 'test', fields);
  logger.child('req-bigint').emit('info', 'test', { count: 1n });
  assert.equal(JSON.parse(lines[0]).self, '[REDACTED]');
  assert.equal(JSON.parse(lines[0]).text, '138****5678');
  assert.equal(JSON.parse(lines[1]).error, 'log_fields_unserializable');
});

test('typed helpers emit scan/redact/audit events', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  const log = logger.child('req-4');
  log.scan({ decision: 'block', confidence: 0.9, reasons: [{}], cacheHit: false, elapsedMs: 2, warnings: [] });
  log.redact({ findings: [{ type: 'cn_mobile', count: 2 }] });
  log.audit({ pass: 1, warn: 0, fail: 1, error: 0, info: 0, total: 2 });
  assert.equal(lines.length, 3);
  assert.equal(JSON.parse(lines[0]).event, 'scan');
  assert.equal(JSON.parse(lines[1]).event, 'redact');
  assert.equal(JSON.parse(lines[2]).event, 'audit');
});

test('non-string fields pass through without crashing', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink });
  logger.child('req-6').emit('info', 'x', { count: 3, ok: true, nothing: null, ratio: 0.5 });
  const parsed = JSON.parse(lines[0]);
  assert.equal(parsed.count, 3);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.nothing, null);
  assert.equal(parsed.ratio, 0.5);
});

test('disabled logger writes nothing', () => {
  const { sink, lines } = capture();
  const logger = createLogger({ sink, enabled: false });
  logger.child('req-5').emit('info', 'x', {});
  assert.equal(lines.length, 0);
});

test('disabled logger never opens the optional file', async () => {
  const { sink, lines } = capture();
  const dir = mkdtempSync(join(tmpdir(), 'dsh-logger-disabled-'));
  try {
    const logFile = join(dir, 'audit.log');
    const logger = createLogger({ sink, enabled: false, logFile });
    logger.child('req-disabled-file').emit('info', 'test', {});
    await new Promise((resolve) => setImmediate(resolve));
    logger.dispose();
    assert.equal(existsSync(logFile), false);
    assert.deepEqual(lines, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a misconfigured logFile degrades to sink output without crashing', async () => {
  const { sink, lines } = capture();
  // A drive/dir that must not exist: the append stream fails, and the logger
  // must fall back to the sink instead of letting the stream error escape.
  const logger = createLogger({ sink, logFile: 'Q:/definitely-missing-dir/audit.log' });
  logger.child('req-6').emit('info', 'x', {});
  await new Promise((resolve) => setTimeout(resolve, 50));
  logger.child('req-7').emit('info', 'y', {});
  logger.dispose();
  assert.ok(lines.length >= 1, 'events must still reach the sink after the file stream fails');
});
