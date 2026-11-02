/**
 * Example classifier adapter (Ollama / Llama-Guard).
 *
 * The canonical implementation lives in lib/classifier.js. Two ways to use it:
 *
 *   1. From the plugin config (cordis.patch.yml), as a descriptor:
 *        classifier:
 *          adapter: ollama
 *          endpoint: http://localhost:11434/api/generate
 *          model: llama3-guard
 *          timeoutMs: 1500
 *
 *   2. Programmatically, when embedding the plugin or wrapping the scanner:
 *        import { createOllamaClassifier } from 'dsh-secure-audit/lib/classifier.js';
 *        config.classifier = createOllamaClassifier({ endpoint, model });
 *
 * The adapter satisfies the scanner contract:
 *   async classify(text, context) -> { decision?: "allow"|"review"|"block",
 *                                       confidence?: 0..1 }
 * `confidence` is certainty in that decision and is reported by the scanner
 * as `decisionConfidence`; the rule-layer `riskScore` is never overwritten.
 * `cacheKeyFor(context)` declares the role-only cache scope, so repeated
 * scans with a new requestId reuse the verdict.
 * Failures are caught by the engine and degrade to the rule decision, so a
 * missing local model never breaks the pipeline.
 */

export { createClassifier, createOllamaClassifier } from '../lib/classifier.js';
