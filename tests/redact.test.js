import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactText, containsPii, maskSecret } from '../lib/redact.js';
import { PII_RULES } from '../lib/rules.js';

test('redacts a CN mobile number keeping prefix and suffix', () => {
  const input = '联系电话 13812345678，请尽快联系。';
  const { redacted, findings } = redactText(input);
  assert.equal(redacted, '联系电话 138****5678，请尽快联系。');
  assert.deepEqual(findings, [{ type: 'cn_mobile', label: PII_RULES.cn_mobile.label, count: 1, sample: '138****5678' }]);
});

test('redacts a CN mobile with +86 prefix and dash', () => {
  const { redacted, findings } = redactText('+86-13912345678');
  assert.equal(redacted, '+86-139****5678');
  assert.equal(findings[0].count, 1);
});

test('redacts a CN ID card with date validation', () => {
  const { redacted, findings } = redactText('身份证号 110101199001011234');
  assert.equal(redacted, '身份证号 1101**********1234');
  assert.equal(findings[0].type, 'cn_id');
  assert.equal(findings[0].count, 1);
});

test('does NOT treat an arbitrary 18-digit order number as an ID card', () => {
  const { redacted, findings } = redactText('订单号 2026021412345678');
  assert.equal(redacted, '订单号 2026021412345678');
  assert.equal(findings.length, 0);
});

test('does NOT treat a 16-digit order number as a bank card (Luhn guard)', () => {
  const { redacted, findings } = redactText('订单号 2026021412345678，请查询');
  assert.equal(redacted, '订单号 2026021412345678，请查询');
  assert.equal(findings.length, 0);
});

test('redacts a Luhn-valid CN bank card number', () => {
  const { redacted, findings } = redactText('银行卡 6222020000000007');
  assert.equal(redacted, '银行卡 ****0007');
  assert.equal(findings[0].type, 'cn_bank');
});

test('redacts an email address keeping a 2-char local prefix', () => {
  const { redacted } = redactText('contact me at zhangsan@example.com ok');
  assert.equal(redacted, 'contact me at zh***@example.com ok');
});

test('redacts an IPv4 address but skips invalid octets', () => {
  const { redacted, findings } = redactText('server 192.168.1.10 and bogus 999.1.1.1');
  assert.equal(redacted, 'server ***.***.***.*** and bogus 999.1.1.1');
  assert.equal(findings[0].type, 'ipv4');
  assert.equal(findings[0].count, 1);
});

test('redacts API keys and URL credentials', () => {
  // Test vector only: a real-looking key format proves masking works. The
  // "TEST" marker keeps it out of secret scanners.
  const api = redactText('key sk-TEST-abcdefghijklmnopqrstuvwxyz123456');
  assert.match(api.redacted, /sk-TES\*{8}/);
  assert.equal(api.findings[0].type, 'api_key');

  const url = redactText('https://admin:s3cr3t@example.com/page');
  assert.equal(url.redacted, 'https://***:***@example.com/page');
  assert.ok(url.findings.some((f) => f.type === 'url_credentials'));
  assert.ok(url.findings.some((f) => f.type === 'email')); // userinfo also trips the email rule; both get masked
});

test('honors the modes filter', () => {
  const { redacted, findings } = redactText('13812345678 zhangsan@example.com', { modes: ['email'] });
  assert.equal(redacted, '13812345678 zh***@example.com');
  assert.deepEqual(findings.map((f) => f.type), ['email']);
});

test('honors a custom mask char', () => {
  const { redacted } = redactText('13812345678', { maskChar: '#' });
  assert.equal(redacted, '138####5678');
});

test('truncates oversized input and reports it', () => {
  const big = 'a'.repeat(100) + '13812345678' + 'b'.repeat(100);
  const { redacted, truncated } = redactText(big, { maxLength: 120 });
  assert.equal(truncated, true);
  assert.ok(!redacted.includes('13812345678'));
});

test('throws on non-string input', () => {
  assert.throws(() => redactText(null), /input must be a string/);
  assert.throws(() => redactText(42), /input must be a string/);
});

test('containsPii detects and is non-destructive', () => {
  assert.equal(containsPii('我的手机 13912345678'), true);
  assert.equal(containsPii('完全正常的一句话'), false);
});

test('maskSecret never reveals a full secret', () => {
  const secret = 'not-a-real-secret-token-123456';
  const masked = maskSecret(secret);
  assert.notEqual(masked, secret);
  assert.ok(!masked.includes('secret'));
  assert.equal(maskSecret('abc'), '***'); // very short values are fully masked
});

test('empty and whitespace-only input passes through cleanly', () => {
  assert.deepEqual(redactText(''), { redacted: '', truncated: false, findings: [] });
  assert.deepEqual(redactText('   '), { redacted: '   ', truncated: false, findings: [] });
});

test('unknown modes are ignored silently', () => {
  const { redacted, findings } = redactText('13812345678', { modes: ['not-a-real-type'] });
  assert.equal(redacted, '13812345678');
  assert.deepEqual(findings, []);
});
