/**
 * Pluggable model classifier wiring.
 *
 * The rule engine stays decisive for most inputs; a classifier only refines
 * ambiguous "review" verdicts (see lib/injection.js), and its failure or
 * timeout degrades to the rule decision with a warning.
 *
 * The plugin config accepts a classifier in two forms:
 *
 *   1. Descriptor (usable from cordis.patch.yml — YAML cannot carry
 *      functions):
 *        classifier: { adapter: "ollama", endpoint, model, timeoutMs }
 *
 *   2. Programmatic (when embedding the plugin or wrapping the scanner):
 *        classifier: { classify(text, context) -> Promise<{decision?, confidence?}> }
 *
 * `createClassifier` normalizes the config; unknown adapters yield null
 * (rule-only mode), never a throw.
 */

export function createClassifier(config) {
  if (!config || typeof config !== 'object') return null;
  if (typeof config.classify === 'function') return config;
  if (config.adapter === 'ollama') return createOllamaClassifier(config);
  return null;
}

/**
 * Local guard-model adapter (Llama-Guard via an OpenAI-compatible
 * `/api/generate` endpoint, e.g. Ollama).
 * @param {object} [options]
 * @param {string} [options.endpoint]
 * @param {string} [options.model='llama3-guard']
 * @param {number} [options.timeoutMs=1500]
 * @param {Function} [options.fetchImpl] injectable fetch for tests
 */
export function createOllamaClassifier(options = {}) {
  const endpoint = options.endpoint ?? 'http://localhost:11434/api/generate';
  const model = options.model ?? 'llama3-guard';
  const timeoutMs = options.timeoutMs ?? 1500;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  return {
    async classify(text, context = {}) {
      if (typeof fetchImpl !== 'function') {
        throw new Error('classifier: no fetch implementation available');
      }
      const prompt = [
        'You are a content-safety classifier. Reply with exactly one word:',
        'SAFE, or UNSAFE. Then on the next line a number 0..1 for confidence.',
        '',
        'Context:', String(context.role ?? 'user message'),
        'Text:', text,
      ].join('\n');

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetchImpl(endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ model, prompt, stream: false }),
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        const lines = String(data.response ?? '').trim().split(/\r?\n/);
        const verdict = (lines[0] ?? '').trim().toUpperCase();
        const confidence = Number.parseFloat(lines[1] ?? '');
        if (verdict === 'SAFE') {
          return { decision: 'allow', confidence: Number.isFinite(confidence) ? confidence : 0.1 };
        }
        if (verdict === 'UNSAFE') {
          return { decision: 'block', confidence: Number.isFinite(confidence) ? confidence : 0.95 };
        }
        return { decision: 'review', confidence: 0.5 };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
