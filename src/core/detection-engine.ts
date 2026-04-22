// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Detection Engine (Node.js)
// ═══════════════════════════════════════════════════════════════
//
// This file adds the filesystem-based createDetectionEngine()
// on top of the edge-safe detection logic.
//
// ⚠️ This file imports payload-loader-node which uses fs/path.
// Do NOT import this from Edge Runtime environments.
// ═══════════════════════════════════════════════════════════════

import { loadPayloadsFromDir } from './payload-loader-node'
import { buildEngine } from './detection-engine-edge'
import type {
  DetectionEngine,
  DetectionEngineConfig,
  PayloadDatabase,
} from './types'
import { THREAT_CATEGORIES } from './types'

// Re-export edge-safe functions so existing imports still work
export { createDetectionEngineFromCompiled, buildEngine } from './detection-engine-edge'

/**
 * Create a new detection engine instance.
 *
 * ⚠️ Node.js ONLY — uses filesystem to load payload patterns.
 * For Edge Runtime, use createDetectionEngineFromCompiled() instead.
 *
 * @param config - Engine configuration
 * @returns Promise resolving to a ready-to-use DetectionEngine
 *
 * @example
 * ```typescript
 * const engine = await createDetectionEngine({
 *   payloadDir: './payloads',
 *   confidenceThreshold: 0.7,
 * })
 *
 * const result = engine.analyze("1' OR '1'='1")
 * // → { detected: true, threats: [...], scanTimeMs: 0.5 }
 * ```
 */
export async function createDetectionEngine(
  config: DetectionEngineConfig = {}
): Promise<DetectionEngine> {
  const {
    payloadDir,
    categories = THREAT_CATEGORIES,
    confidenceThreshold = 0.7,
    whitelist = [],
  } = config

  // ─── Load Payloads ─────────────────────────────────────────
  let payloadDb: PayloadDatabase

  if (payloadDir) {
    payloadDb = await loadPayloadsFromDir(payloadDir, categories)
  } else {
    // Empty payload database — patterns can be added later
    payloadDb = {
      patterns: new Map(),
      totalCount: 0,
      categoryCounts: {
        sqli: 0,
        xss: 0,
        lfi: 0,
        ssrf: 0,
        'path-traversal': 0,
      },
    }
  }

  const { engine, buildTimeMs } = buildEngine(payloadDb, confidenceThreshold, whitelist)

  console.log(
    `[xpecto-shield] Detection engine built in ${buildTimeMs.toFixed(1)}ms — ` +
    `${payloadDb.totalCount} patterns loaded across ${categories.length} categories`
  )

  return engine
}
