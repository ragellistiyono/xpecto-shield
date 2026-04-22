#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// Compile Payloads → Static TypeScript Module
// ═══════════════════════════════════════════════════════════════
// Reads .txt payload files from ../payloads/ and generates a
// compiled-payloads.ts that can be statically imported in Edge
// Runtime without needing fs or path.
// ═══════════════════════════════════════════════════════════════

import { readFileSync, existsSync, writeFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const PAYLOADS_DIR = join(__dirname, '../../payloads')
const OUTPUT_FILE = join(__dirname, '../compiled-payloads.ts')

const CATEGORY_FILES = {
  sqli: 'sqli.txt',
  xss: 'xss.txt',
  lfi: 'lfi.txt',
  ssrf: 'ssrf.txt',
  'path-traversal': 'path-traversal.txt',
}

/**
 * Parse a payload file into an array of normalized patterns.
 * Same logic as payload-loader.ts parsePayloadFile().
 */
function parsePayloadFile(content, category) {
  const patterns = []
  const lines = content.split('\n')

  for (const rawLine of lines) {
    const line = rawLine.trim()

    // Skip empty lines
    if (line.length === 0) continue

    // Skip comments
    if (line.startsWith('#')) continue

    // Skip category headers (lines ending with ":")
    if (line.endsWith(':') && line.length < 100) {
      const hasLettersOnly = /^[A-Za-z0-9\s()_/-]+:$/.test(line)
      if (hasLettersOnly) continue
    }

    // Normalize: lowercase for case-insensitive matching
    const normalized = line.toLowerCase()

    // Skip very short patterns (< 3 chars)
    if (normalized.length < 3) continue

    patterns.push(normalized)
  }

  return patterns
}

// ─── Main ──────────────────────────────────────────────────────

console.log('[compile-payloads] Starting compilation...')
console.log(`[compile-payloads] Payloads dir: ${PAYLOADS_DIR}`)

const allPatterns = {}
let totalCount = 0

for (const [category, filename] of Object.entries(CATEGORY_FILES)) {
  const filepath = join(PAYLOADS_DIR, filename)

  if (!existsSync(filepath)) {
    console.warn(`[compile-payloads] ⚠ Missing: ${filepath} — skipping ${category}`)
    continue
  }

  const content = readFileSync(filepath, 'utf-8')
  const patterns = parsePayloadFile(content, category)

  let added = 0
  for (const pattern of patterns) {
    if (!(pattern in allPatterns)) {
      allPatterns[pattern] = category
      added++
      totalCount++
    }
  }

  console.log(`[compile-payloads] ✓ ${category}: ${added} patterns loaded from ${filename}`)
}

// ─── Generate TypeScript Module ────────────────────────────────

const tsContent = `// ═══════════════════════════════════════════════════════════════
// Xpecto Shield Dev — Compiled Payloads (auto-generated)
// ═══════════════════════════════════════════════════════════════
// Generated at: ${new Date().toISOString()}
// Total patterns: ${totalCount}
//
// DO NOT EDIT — run \`npm run compile-payloads\` to regenerate.
// ═══════════════════════════════════════════════════════════════

import type { ThreatCategory } from 'xpecto-shield/core'

export const COMPILED_PAYLOADS: Record<string, ThreatCategory> = ${JSON.stringify(allPatterns, null, 2)} as const
`

writeFileSync(OUTPUT_FILE, tsContent, 'utf-8')

console.log(`[compile-payloads] ✓ Generated: ${OUTPUT_FILE}`)
console.log(`[compile-payloads] ✓ Total: ${totalCount} unique patterns compiled`)
