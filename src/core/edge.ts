// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Edge-Compatible Core Exports
// ═══════════════════════════════════════════════════════════════
// This entry point exports ONLY Edge Runtime compatible functions.
// It deliberately excludes createDetectionEngine (which uses
// filesystem-based payload loading via fs/path).
//
// Use 'xpecto-shield/core/edge' in Next.js middleware.
// ═══════════════════════════════════════════════════════════════

export { AhoCorasickAutomaton } from './aho-corasick'
export { createDetectionEngineFromCompiled } from './detection-engine-edge'
export { decodeInput } from './input-decoder'
export { loadPayloadsFromCompiled, parsePayloadFile } from './payload-loader'
export * from './types'
