/**
 * Structured JSON-lines logger with automatic redaction.
 *
 * Meta-security rule: this logger can NEVER write raw message content,
 * secrets, or user paths. Fields named `text`, `content`, `evidence`,
 * `snippet` or `value` are redacted before serialization. Everything else is
 * trusted to be already-safe summary data produced by the plugin itself.
 *
 * Pure-ish module: the only I/O is an optional append-only log file stream.
 */

import { createWriteStream } from 'node:fs';
import { redactText, maskSecret } from './redact.js';

const REDACT_FIELDS = new Set(['text', 'content', 'evidence', 'snippet', 'value']);

/**
 * @param {object} [options]
 * @param {object} [options.sink] logger-like object; defaults to console
 * @param {boolean} [options.enabled=true]
 * @param {string} [options.logFile=''] append-only JSONL file; empty = sink only
 * @returns logger with `emit`, `child`, and typed helpers
 */
export function createLogger(options = {}) {
  const { sink = console, enabled = true, logFile = '' } = options;
  let fileStream = null;
  if (logFile) {
    fileStream = createWriteStream(logFile, { flags: 'a' });
  }

  function safeFields(fields) {
    const out = {};
    for (const [key, value] of Object.entries(fields ?? {})) {
      if (REDACT_FIELDS.has(key) && typeof value === 'string') {
        out[key] = redactText(value).redacted;
      } else if (typeof value === 'string' && value.length > 4000) {
        out[key] = value.slice(0, 4000) + '…(truncated)';
      } else {
        out[key] = value;
      }
    }
    return out;
  }

  function emit(requestId, level, event, fields = {}) {
    if (!enabled) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level,
      event,
      requestId,
      ...safeFields(fields),
    });
    if (fileStream) {
      fileStream.write(line + '\n');
    } else if (sink && typeof sink.log === 'function') {
      sink.log(line);
    }
  }

  /** Bind a request id; every line then carries it (audit trail). */
  function child(requestId) {
    return {
      emit: (level, event, fields) => emit(requestId, level, event, fields),
      scan: (result) => emit(requestId, 'info', 'scan', {
        decision: result.decision,
        confidence: result.confidence,
        rulesHit: result.reasons.length,
        cacheHit: result.cacheHit,
        elapsedMs: result.elapsedMs,
        warnings: result.warnings,
      }),
      redact: (summary) => emit(requestId, 'info', 'redact', {
        typesHit: summary.findings.map((f) => f.type),
        total: summary.findings.reduce((n, f) => n + f.count, 0),
      }),
      audit: (summary) => emit(requestId, 'info', 'audit', {
        statuses: summary,
        checks: summary ? Object.values(summary).reduce((n, v) => n + v, 0) : 0,
      }),
      warn: (event, fields) => emit(requestId, 'warn', event, fields),
      error: (event, fields) => emit(requestId, 'error', event, fields),
    };
  }

  return {
    emit,
    child,
    maskSecret,
    /** Close the file stream; idempotent. */
    dispose() {
      if (fileStream) {
        fileStream.end();
        fileStream = null;
      }
    },
  };
}
