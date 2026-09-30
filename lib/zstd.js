/**
 * Concatenated-frame Zstandard decoding for DSH session payloads.
 *
 * DSH 0.1.2 stores each session as `session.jsonl.zstd`, a *container* of
 * independently decodable, checksummed Zstandard frames: one small header
 * frame followed by one frame per durable event batch (the persistence
 * backend appends frames so it can recover a torn tail). Node's public zstd
 * API is one-shot per frame — `zstdDecompressSync`, `zstdDecompress` and
 * even a `createZstdDecompress` stream all stop after the FIRST frame.
 * Feeding a whole session file to any of them therefore yields the ~241-byte
 * session header and nothing else, which is why a PII scan built on it can
 * report "clean" while never having read a single message.
 *
 * This module walks the container structurally (no decompression) and decodes
 * every complete frame, so the plaintext is real session content. It is pure
 * JavaScript over the Node standard library: no child_process, no native
 * addon, no dependency.
 *
 * @module dsh-secure-audit/zstd
 */

import zlib from 'node:zlib';

/** Frame magic (little-endian `28 B5 2F FD`). */
const ZSTD_MAGIC = 0xfd2fb528;
/** Skippable-frame magic range; payload length follows in 4 bytes. */
const SKIPPABLE_MAGIC_MIN = 0x184d2a50;
const SKIPPABLE_MAGIC_MAX = 0x184d2a5f;
/** Frame_Header_Descriptor: Dictionary_ID field size, indexed by the 2-bit flag. */
const DICT_ID_BYTES = [0, 1, 2, 4];
/** Frame_Header_Descriptor: Frame_Content_Size field size, indexed by the 2-bit flag. */
const FCS_BYTES = [0, 2, 4, 8];
/** Defensive ceiling: a crafted container must not spin the scanner forever. */
export const MAX_FRAME_COUNT = 100000;

/**
 * True when this Node release exposes the synchronous zstd decoder used per
 * frame. Node 20 has none; the caller reports that instead of guessing.
 * @returns {boolean} whether `zlib.zstdDecompressSync` is callable
 */
export function zstdAvailable() {
  return typeof zlib.zstdDecompressSync === 'function';
}

/**
 * Locate complete Zstandard frames without decompressing their blocks.
 * Structure only: magic, frame header, block headers. An incomplete final
 * frame (EOF mid-frame) is reported through `tornStart` rather than thrown,
 * because a session log being written right now legitimately ends torn.
 * @param {Buffer} buffer - bytes of a concatenated zstd container
 * @param {number} [maxFrames] - stop after this many complete frames
 * @returns {{frames: {start: number, end: number}[], tornStart: number|undefined}}
 */
export function scanZstdFrames(buffer, maxFrames = MAX_FRAME_COUNT) {
  const frames = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    if (frames.length >= maxFrames) return { frames, tornStart: offset };
    const magic = buffer.readUInt32LE(offset);
    if (magic >= SKIPPABLE_MAGIC_MIN && magic <= SKIPPABLE_MAGIC_MAX) {
      if (offset + 8 > buffer.length) return { frames, tornStart: offset };
      const size = buffer.readUInt32LE(offset + 4);
      const next = offset + 8 + size;
      if (next > buffer.length) return { frames, tornStart: offset };
      offset = next;
      continue;
    }
    if (magic !== ZSTD_MAGIC) return { frames, tornStart: offset };
    const start = offset;
    if (offset + 5 > buffer.length) return { frames, tornStart: start };
    const descriptor = buffer[offset + 4];
    const fcsFlag = descriptor >> 6;
    const singleSegment = (descriptor & 0x20) !== 0;
    const contentChecksum = (descriptor & 0x04) !== 0;
    const dictFlag = descriptor & 0x03;
    offset += 5;
    if (!singleSegment) offset += 1; // Window_Descriptor
    offset += DICT_ID_BYTES[dictFlag]; // Dictionary_ID
    offset += fcsFlag === 0 ? (singleSegment ? 1 : 0) : FCS_BYTES[fcsFlag]; // Frame_Content_Size
    if (offset > buffer.length) return { frames, tornStart: start };
    for (;;) {
      if (offset + 3 > buffer.length) return { frames, tornStart: start };
      const header = buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16);
      const lastBlock = (header & 0x01) !== 0;
      const blockType = (header >> 1) & 0x03;
      const blockSize = header >> 3;
      offset += 3;
      // Block type 3 is reserved: the container is not structurally valid.
      if (blockType === 3) return { frames, tornStart: start };
      offset += blockType === 1 ? 1 : blockSize; // RLE blocks carry a single byte
      if (offset > buffer.length) return { frames, tornStart: start };
      if (lastBlock) break;
    }
    if (contentChecksum) offset += 4;
    if (offset > buffer.length) return { frames, tornStart: start };
    frames.push({ start, end: offset });
  }
  return { frames, tornStart: undefined };
}

/**
 * Decode a concatenated Zstandard container, stopping at `maxBytes` of
 * plaintext. Decoding is per frame, so the byte budget bounds real work
 * instead of forcing the caller to skip a large session outright.
 * @param {Buffer} buffer - bytes of a concatenated zstd container
 * @param {{maxBytes?: number, maxFrames?: number}} [options] - plaintext budget
 * @returns {{text: string|null, reason: string|null, frames: number, totalFrames: number, truncated: boolean, tornTail: boolean}}
 */
export function decodeZstdFrames(buffer, { maxBytes = Number.POSITIVE_INFINITY, maxFrames = MAX_FRAME_COUNT } = {}) {
  const { frames, tornStart } = scanZstdFrames(buffer, maxFrames);
  const tornTail = tornStart !== undefined;
  if (!zstdAvailable()) {
    return { text: null, reason: 'zstd-unsupported', frames: 0, totalFrames: frames.length, truncated: false, tornTail };
  }
  if (frames.length === 0) {
    return { text: null, reason: tornTail ? 'incomplete-frame' : 'no-frames', frames: 0, totalFrames: 0, truncated: false, tornTail };
  }
  const parts = [];
  let bytes = 0;
  let decoded = 0;
  let truncated = false;
  for (const frame of frames) {
    let plain;
    try {
      plain = zlib.zstdDecompressSync(buffer.subarray(frame.start, frame.end));
    } catch {
      if (decoded === 0) {
        return { text: null, reason: 'frame-decode-failed', frames: 0, totalFrames: frames.length, truncated: false, tornTail };
      }
      break; // keep the plaintext already recovered from earlier frames
    }
    decoded += 1;
    if (bytes + plain.length > maxBytes) {
      const room = Math.max(0, maxBytes - bytes);
      if (room > 0) parts.push(plain.subarray(0, room));
      bytes += room;
      truncated = true;
      break;
    }
    parts.push(plain);
    bytes += plain.length;
  }
  if (bytes === 0) {
    return { text: null, reason: 'empty-payload', frames: decoded, totalFrames: frames.length, truncated: false, tornTail };
  }
  return { text: Buffer.concat(parts).toString('utf8'), reason: null, frames: decoded, totalFrames: frames.length, truncated, tornTail };
}
