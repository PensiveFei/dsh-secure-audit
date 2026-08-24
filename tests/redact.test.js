import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactText, containsPii, maskSecret, redactJson } from '../lib/redact.js';
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

test('does NOT treat an 18-digit number with an impossible date as an ID card', () => {
  // 2000-02-31 does not exist on the calendar; the pattern's date check is
  // structural only, so the calendar guard must reject it (order-number case).
  const { redacted, findings } = redactText('订单号 110105200002310015');
  assert.equal(redacted, '订单号 110105200002310015');
  assert.equal(findings.length, 0);
});

test('redacts ID cards with a real date and applies the leap-year rule', () => {
  const leap = redactText('110105200402290011'); // 2004-02-29 is a leap day
  assert.equal(leap.findings[0].type, 'cn_id');
  const nonLeap = redactText('110105200302290011'); // 2003-02-29 does not exist
  assert.equal(nonLeap.redacted, '110105200302290011');
  assert.equal(nonLeap.findings.length, 0);
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

test('redactJson replaces sensitive-key values structurally', () => {
  const input = JSON.stringify({ config: { api_key: 'sk-abcdefghijklmnop', token: 'tok_123456', phone: '13812345678' } });
  const { redactedJson, replacedKeys, piiCount, error } = redactJson(input);
  assert.equal(error, null);
  const out = JSON.parse(redactedJson);
  assert.equal(out.config.api_key, '[REDACTED]');
  assert.equal(out.config.token, '[REDACTED]');
  // non-sensitive values keep the PII fallback
  assert.equal(out.config.phone, '138****5678');
  assert.equal(piiCount, 1);
  assert.deepEqual(replacedKeys.map((k) => k.key), ['api_key', 'token']);
});

test('redactJson handles nested objects and arrays with JSONPath labels', () => {
  const input = JSON.stringify({ credentials: [{ user: 'a', password: 'p@ss' }], items: ['x'] });
  const { redactedJson, replacedKeys } = redactJson(input);
  const out = JSON.parse(redactedJson);
  assert.equal(out.credentials[0].password, '[REDACTED]');
  assert.deepEqual(out.items, ['x']);
  assert.equal(replacedKeys[0].path, '$.credentials[0].password');
});

test('redactJson accepts an already-parsed object', () => {
  const { redactedJson } = redactJson({ client_secret: 's3cr3t', name: 'ok' });
  const out = JSON.parse(redactedJson);
  assert.equal(out.client_secret, '[REDACTED]');
  assert.equal(out.name, 'ok');
});

test('redactJson preserves non-secret structure and numbers/booleans', () => {
  const input = JSON.stringify({ enabled: true, count: 3, label: 'hello world', token: 'abc' });
  const { redactedJson, replacedKeys } = redactJson(input);
  const out = JSON.parse(redactedJson);
  assert.equal(out.enabled, true);
  assert.equal(out.count, 3);
  assert.equal(out.label, 'hello world');
  assert.equal(out.token, '[REDACTED]');
  assert.equal(replacedKeys.length, 1);
});

test('redactJson reports invalid JSON without throwing', () => {
  const { redactedJson, error } = redactJson('{not json');
  assert.equal(redactedJson, '');
  assert.match(error, /invalid JSON/i);
});

test('redactJson honors custom key patterns', () => {
  const { redactedJson, replacedKeys } = redactJson('{"myCustom": "v", "token": "x"}', {
    keyPattern: /custom/i,
  });
  const out = JSON.parse(redactedJson);
  assert.equal(out.myCustom, '[REDACTED]');
  assert.equal(out.token, 'x'); // custom pattern replaces the built-in one
  assert.deepEqual(replacedKeys.map((k) => k.key), ['myCustom']);
});

test('redactJson depth guard does not crash on deep nesting', () => {
  let deep = 'x';
  for (let i = 0; i < 100; i += 1) deep = { child: deep };
  const { redactedJson, error } = redactJson(JSON.stringify({ a: deep }));
  assert.equal(error, null);
  assert.ok(redactedJson.length > 0);
});

