export { AhoCorasickAutomaton, createDetectionEngineFromCompiled, decodeInput, loadPayloadsFromCompiled, parsePayloadFile } from './edge.js';
import { e as DetectionEngineConfig, d as DetectionEngine } from '../types-wAOtwm6s.js';
export { A as AIConfig, a as AIReport, b as AhoCorasickMatch, c as AppwriteConfig, B as BlockedIP, C as CATEGORY_LABELS, D as DateRange, f as DetectionResult, E as EngineStats, I as IncidentFilters, g as IncidentLog, h as IncidentStats, P as PaginatedResult, i as PaginationOptions, j as PayloadDatabase, S as ShieldAPIConfig, k as ShieldAppwriteClient, l as ShieldMiddlewareConfig, n as THREAT_CATEGORIES, T as ThreatCategory, m as ThreatMatch } from '../types-wAOtwm6s.js';

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
declare function createDetectionEngine(config?: DetectionEngineConfig): Promise<DetectionEngine>;

export { DetectionEngine, DetectionEngineConfig, createDetectionEngine };
