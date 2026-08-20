import { test } from 'node:test';
import assert from 'node:assert/strict';
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
