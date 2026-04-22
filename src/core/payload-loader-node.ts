// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Payload Loader (Node.js Only)
// ═══════════════════════════════════════════════════════════════
//
// Loads attack payload patterns from .txt files on disk.
// This file uses Node.js APIs (fs, path) and MUST NOT be imported
// in Edge Runtime environments. For Edge-compatible loading, use
// loadPayloadsFromCompiled() from './payload-loader' instead.
// ═══════════════════════════════════════════════════════════════

import { readFileSync, existsSync } from 'fs'
import { join } from 'path'
import type { ThreatCategory, PayloadDatabase } from './types'
import { THREAT_CATEGORIES } from './types'
import { parsePayloadFile } from './payload-loader'

/** Mapping of category → expected filename */
const CATEGORY_FILES: Record<ThreatCategory, string> = {
  sqli: 'sqli.txt',
  xss: 'xss.txt',
  lfi: 'lfi.txt',
  ssrf: 'ssrf.txt',
  'path-traversal': 'path-traversal.txt',
}

/**
 * Load payloads from .txt files in a directory.
 *
 * ⚠️ Node.js ONLY — do NOT use in Edge Runtime / Next.js middleware.
 * For Edge environments, pre-compile payloads and use
 * createDetectionEngineFromCompiled() instead.
 *
 * @param dir - Absolute or relative path to the payloads directory
 * @param categories - Which categories to load (default: all)
 * @returns PayloadDatabase with all loaded patterns
 */
export async function loadPayloadsFromDir(
  dir: string,
  categories: ThreatCategory[] = THREAT_CATEGORIES
): Promise<PayloadDatabase> {
  const patterns = new Map<string, ThreatCategory>()
  const categoryCounts: Record<ThreatCategory, number> = {
    sqli: 0,
    xss: 0,
    lfi: 0,
    ssrf: 0,
    'path-traversal': 0,
  }

  for (const category of categories) {
    const filename = CATEGORY_FILES[category]
    const filepath = join(dir, filename)

    if (!existsSync(filepath)) {
      console.warn(
        `[xpecto-shield] Payload file not found: ${filepath} — skipping ${category}`
      )
      continue
    }

    try {
      const content = readFileSync(filepath, 'utf-8')
      const categoryPatterns = parsePayloadFile(content, category)

      for (const [pattern, cat] of categoryPatterns) {
        if (!patterns.has(pattern)) {
          patterns.set(pattern, cat)
          categoryCounts[cat]++
        }
      }
    } catch (error) {
      console.error(
        `[xpecto-shield] Error loading ${filepath}:`,
        error instanceof Error ? error.message : error
      )
    }
  }

  return {
    patterns,
    totalCount: patterns.size,
    categoryCounts,
  }
}
