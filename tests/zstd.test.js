import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { scanZstdFrames, decodeZstdFrames, decodeZstdFramesAsync } from '../lib/zstd.js';

const hasZstd = typeof zlib.zstdCompressSync === 'function';

test('frame scanner reports every short trailing fragment', { skip: !hasZstd }, () => {
  const frame = zlib.zstdCompressSync(Buffer.from('clean prefix'));
  for (let size = 1; size <= 3; size += 1) {
    const result = scanZstdFrames(Buffer.concat([frame, Buffer.alloc(size, 0x28)]));
    assert.equal(result.frames.length, 1);
    assert.equal(result.tornStart, frame.length);
  }
});

test('skippable frames consume the structural scan budget', () => {
  const skipped = Buffer.alloc(8);
  skipped.writeUInt32LE(0x184d2a50, 0);
  const result = scanZstdFrames(Buffer.concat([skipped, skipped]), 1);
  assert.equal(result.tornStart, skipped.length);
});

test('later invalid frames preserve the prefix and report the failure', { skip: !hasZstd }, async () => {
  const first = zlib.zstdCompressSync(Buffer.from('clean prefix'));
  // Valid frame structure with a compressed block containing invalid data.
  const bad = Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x01, 0x0d, 0, 0, 0xff]);
  const container = Buffer.concat([first, bad]);
  assert.equal(scanZstdFrames(container).frames.length, 2);
  for (const decode of [decodeZstdFrames, decodeZstdFramesAsync]) {
    const result = await decode(container);
    assert.equal(result.text, 'clean prefix');
    assert.equal(result.reason, 'frame-decode-failed');
    assert.equal(result.frames, 1);
    assert.equal(result.totalFrames, 2);
  }
});

test('async decoder scans prefixes of oversized frames; sync decoder bounds its output', { skip: !hasZstd }, async () => {
  const frame = zlib.zstdCompressSync(Buffer.from('prefix-' + 'x'.repeat(1024 * 1024)));
  const streamed = await decodeZstdFramesAsync(frame, { maxBytes: 128 });
  assert.equal(Buffer.byteLength(streamed.text), 128);
  assert.ok(streamed.text.startsWith('prefix-'));
  assert.equal(streamed.truncated, true);
  const sync = decodeZstdFrames(frame, { maxBytes: 128 });
  assert.equal(sync.text, null);
  assert.equal(sync.reason, 'plaintext-limit');
  assert.equal(sync.truncated, true);
});
