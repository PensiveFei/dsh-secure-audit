/**
 * Structured JSON-lines logger with automatic redaction.
 *
 * Every string value passes through PII redaction and sensitive key values
 * are structurally masked, including values nested in arrays and objects.
 * Callers still supply summary data rather than raw message content or paths.
 *
 * Pure-ish module: the only I/O is an optional append-only log file stream.
 */

import { createWriteStream } from 'node:fs';
import { redactJson, maskSecret } from './redact.js';

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
  if (enabled && logFile) {
    try {
      fileStream = createWriteStream(logFile, { flags: 'a' });
      // An unhandled 'error' event on the stream would crash the host
      // (e.g. ENOENT/EACCES on a misconfigured logFile). Log one sanitized
      // line via the sink and degrade to sink-only output.
      fileStream.on('error', (err) => {
        if (sink && typeof sink.log === 'function') {
          sink.log(JSON.stringify({
            ts: new Date().toISOString(),
            level: 'warn',
            event: 'log_file_error',
            error: err?.code ?? err?.name ?? 'error',
          }));
        }
        fileStream = null;
      });
    } catch (err) {
      if (sink && typeof sink.log === 'function') {
        sink.log(JSON.stringify({
          ts: new Date().toISOString(),
          level: 'warn',
          event: 'log_file_error',
          error: err?.code ?? err?.name ?? 'error',
        }));
      }
      fileStream = null;
    }
  }

  function safeFields(fields) {
    const result = redactJson(fields ?? {}, { maxLength: 4000 });
    if (result.error) return { error: 'log_fields_unserializable' };
    return JSON.parse(result.redactedJson);
  }

  function emit(requestId, level, event, fields = {}) {
    if (!enabled) return;
    const line = JSON.stringify({
      ...safeFields(fields),
      ts: new Date().toISOString(),
      level,
      event,
      requestId,
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
        riskLevel: result.riskLevel,
        inputSha256: result.inputSha256,
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
