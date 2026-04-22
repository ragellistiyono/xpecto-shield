// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Core Module Exports
// ═══════════════════════════════════════════════════════════════
// NOTE: loadPayloadsFromDir is NOT exported here because it uses
// Node.js APIs (fs, path) which break Edge Runtime. It is loaded
// dynamically by createDetectionEngine() when payloadDir is set.

export { AhoCorasickAutomaton } from './aho-corasick'
export { createDetectionEngine, createDetectionEngineFromCompiled } from './detection-engine'
export { decodeInput } from './input-decoder'
export { loadPayloadsFromCompiled, parsePayloadFile } from './payload-loader'
export * from './types'

