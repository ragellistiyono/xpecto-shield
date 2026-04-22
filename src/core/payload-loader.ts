// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Payload Loader (Edge-Safe)
// ═══════════════════════════════════════════════════════════════
//
// Edge Runtime compatible payload parsing and loading utilities.
// This file has NO Node.js dependencies (no fs, no path).
//
// For filesystem-based loading, use loadPayloadsFromDir() from
// './payload-loader-node' instead (Node.js environments only).
// ═══════════════════════════════════════════════════════════════

import type { ThreatCategory, PayloadDatabase } from './types'

/**
 * Parse a single payload file's content into a Map of patterns.
 *
 * File format:
 * - One payload per line
 * - Lines starting with # are comments
 * - Empty lines are skipped
 * - Lines ending with : are category headers (e.g., "MySQL Blind (Time Based):")
 * - All patterns are lowercased for case-insensitive matching
 *
 * @param content - Raw file content
 * @param category - The threat category for these patterns
 * @returns Map of normalized pattern → category
 */
export function parsePayloadFile(
  content: string,
  category: ThreatCategory
): Map<string, ThreatCategory> {
  const patterns = new Map<string, ThreatCategory>()
  const lines = content.split('\n')

  for (const rawLine of lines) {
    const line = rawLine.trim()

    // Skip empty lines
    if (line.length === 0) continue

    // Skip comments
    if (line.startsWith('#')) continue

    // Skip category headers (lines ending with ":")
    // e.g., "MySQL Blind (Time Based):" or "Error Based:"
    if (line.endsWith(':') && !line.includes(' ') === false && line.length < 100) {
      // Additional check: category headers are typically short descriptive text
      // Don't skip actual payloads that happen to end with ":"
      const hasLettersOnly = /^[A-Za-z0-9\s()_/-]+:$/.test(line)
      if (hasLettersOnly) continue
    }

    // Normalize: lowercase for case-insensitive matching
    const normalized = line.toLowerCase()

    // Skip very short patterns (< 3 chars) as they cause too many false positives
    if (normalized.length < 3) continue

    patterns.set(normalized, category)
  }

  return patterns
}

/**
 * Load payloads from pre-compiled data (for serverless environments
 * where fs access may not be available at runtime).
 *
 * @param compiledData - Pre-compiled patterns as a plain object { pattern: category }
 * @returns PayloadDatabase
 */
export function loadPayloadsFromCompiled(
  compiledData: Record<string, ThreatCategory>
): PayloadDatabase {
  const patterns = new Map<string, ThreatCategory>()
  const categoryCounts: Record<ThreatCategory, number> = {
    sqli: 0,
    xss: 0,
    lfi: 0,
    ssrf: 0,
    'path-traversal': 0,
  }

  for (const [pattern, category] of Object.entries(compiledData)) {
    patterns.set(pattern, category)
    categoryCounts[category]++
  }

  return {
    patterns,
    totalCount: patterns.size,
    categoryCounts,
  }
}
