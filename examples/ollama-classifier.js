/**
 * Example classifier adapter (Ollama / Llama-Guard).
 *
 * The canonical implementation lives in lib/classifier.js. Two ways to use it:
 *
 *   1. From the plugin config (cordis.patch.yml), as a descriptor:
 *        classifier:
 *          adapter: ollama
 *          endpoint: http://127.0.0.1:11434/api/generate
 *          model: llama3-guard
 *          timeoutMs: 1500
 *
 *   2. Programmatically, when embedding the plugin or wrapping the scanner:
 *        import { createOllamaClassifier } from 'dsh-security-audit/lib/classifier.js';
 *        config.classifier = createOllamaClassifier({ endpoint, model });
 *
 * The adapter satisfies the scanner contract:
 *   async classify(text, context) -> { decision?: "allow"|"review"|"block",
 *                                       confidence?: 0..1 }
 * Failures are caught by the engine and degrade to the rule decision, so a
 * missing local model never breaks the pipeline.
 */

export { createClassifier, createOllamaClassifier } from '../lib/classifier.js';
