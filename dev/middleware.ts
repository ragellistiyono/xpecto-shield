// ═══════════════════════════════════════════════════════════════
// Xpecto Shield Dev — Next.js Middleware
// ═══════════════════════════════════════════════════════════════
// Integrates the Shield detection engine directly (without the
// full createShieldMiddleware which requires Appwrite config).
// Uses the core detection engine + custom blocking logic.
//
// NOTE: Uses createDetectionEngineFromCompiled to avoid Node.js
// fs/path APIs which are not supported in Edge Runtime.
// Run `npm run compile-payloads` to regenerate compiled data.
// ═══════════════════════════════════════════════════════════════

import { NextRequest, NextResponse } from 'next/server'
import {
  createDetectionEngineFromCompiled,
  type DetectionEngine,
  type ThreatCategory,
} from 'xpecto-shield/core/edge'
import { COMPILED_PAYLOADS } from './compiled-payloads'

// ─── Inline Block Responses (avoids importing xpecto-shield/middleware
// which pulls in Node.js deps via createShieldMiddleware) ────────

const CATEGORY_NAMES: Record<string, string> = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  lfi: 'Local File Inclusion',
  ssrf: 'Server-Side Request Forgery',
  'path-traversal': 'Path Traversal',
}

function buildBlockResponseJSON(category: string, _clientIP: string): Response {
  return new Response(
    JSON.stringify({
      error: 'REQUEST_BLOCKED',
      message: 'Your request has been blocked by Xpecto Shield.',
      category,
      timestamp: new Date().toISOString(),
    }),
    {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'X-Shield-Status': 'blocked',
        'X-Shield-Category': category,
        'Cache-Control': 'no-store',
      },
    }
  )
}

function buildBlockResponse(category: string, _clientIP: string): Response {
  const name = CATEGORY_NAMES[category] || category
  return new Response(
    `<html><body><h1>403 Blocked</h1><p>Xpecto Shield blocked this request: ${name}</p></body></html>`,
    {
      status: 403,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Shield-Status': 'blocked',
        'X-Shield-Category': category,
        'Cache-Control': 'no-store',
      },
    }
  )
}

// ─── Engine Singleton ──────────────────────────────────────────

let engine: DetectionEngine | null = null
let enginePromise: Promise<DetectionEngine> | null = null

async function getEngine(): Promise<DetectionEngine> {
  if (engine) return engine
  if (enginePromise) return enginePromise

  enginePromise = createDetectionEngineFromCompiled(COMPILED_PAYLOADS, {
    confidenceThreshold: 0.6,
  })

  engine = await enginePromise
  return engine
}

// ─── Strike Counter ────────────────────────────────────────────

const strikes = new Map<string, number>()
const MAX_STRIKES = 3

// ─── Middleware ────────────────────────────────────────────────

export async function middleware(request: NextRequest) {
  const url = new URL(request.url)
  const pathname = url.pathname

  // Skip internal Next.js and shield API routes
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/api/shield') ||
    pathname === '/favicon.ico' ||
    pathname === '/' ||
    pathname === '/dashboard' ||
    pathname === '/tester'
  ) {
    return NextResponse.next()
  }

  // Get detection engine
  let det: DetectionEngine
  try {
    det = await getEngine()
  } catch (err) {
    console.error('[shield-dev] Engine init error:', err)
    return NextResponse.next()
  }

  // Extract inputs from request
  const inputs: Record<string, string> = {}

  // Query parameters
  for (const [key, value] of url.searchParams.entries()) {
    inputs[`query.${key}`] = value
  }

  // URL path segments (for path traversal)
  inputs['path'] = pathname

  // Request headers that might contain payloads
  const referer = request.headers.get('referer')
  if (referer) inputs['header.referer'] = referer

  const userAgent = request.headers.get('user-agent')
  if (userAgent) inputs['header.user-agent'] = userAgent

  // POST body
  if (request.method === 'POST' || request.method === 'PUT') {
    try {
      const cloned = request.clone()
      const text = await cloned.text()
      if (text) {
        inputs['body'] = text
        // Try to parse JSON body and add individual fields
        try {
          const json = JSON.parse(text)
          if (typeof json === 'object' && json !== null) {
            for (const [key, value] of Object.entries(json)) {
              if (typeof value === 'string') {
                inputs[`body.${key}`] = value
              }
            }
          }
        } catch {
          // Not JSON, body already added as text
        }
      }
    } catch {
      // Body read error, continue
    }
  }

  // Skip if no inputs to scan
  if (Object.keys(inputs).length === 0) {
    return NextResponse.next()
  }

  // Analyze
  const result = det.analyzeMultiple(inputs)

  if (!result.detected) {
    return NextResponse.next()
  }

  // Threat detected!
  const topThreat = result.threats[0]
  const clientIP = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || request.headers.get('x-real-ip')
    || '127.0.0.1'

  // Update strikes
  const currentStrikes = (strikes.get(clientIP) || 0) + 1
  strikes.set(clientIP, currentStrikes)

  // Log incident to in-memory store via API
  const incident = {
    timestamp: new Date().toISOString(),
    sourceIP: clientIP,
    requestPath: pathname,
    requestMethod: request.method,
    attackCategory: topThreat.category,
    matchedPayload: topThreat.matchedPayload,
    confidence: topThreat.confidence,
    rawInput: topThreat.rawInput.substring(0, 300),
    action: 'blocked' as const,
    userAgent: request.headers.get('user-agent') || 'unknown',
  }

  // Fire-and-forget log to our API
  const baseUrl = `${url.protocol}//${url.host}`
  fetch(`${baseUrl}/api/shield/log-incident`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(incident),
  }).catch(() => {})

  // Console log
  console.warn(
    `[xpecto-shield] ⚠ BLOCKED | IP: ${clientIP} | ` +
    `Category: ${topThreat.category} | ` +
    `Path: ${pathname} | ` +
    `Confidence: ${topThreat.confidence.toFixed(2)} | ` +
    `Matched: "${topThreat.matchedPayload.substring(0, 50)}" | ` +
    `Strikes: ${currentStrikes}/${MAX_STRIKES} | ` +
    `Scan: ${result.scanTimeMs.toFixed(1)}ms`
  )

  // Return block response
  const isAPI = request.headers.get('accept')?.includes('application/json')
    || pathname.startsWith('/api/')

  if (isAPI) {
    return buildBlockResponseJSON(topThreat.category, clientIP)
  }

  return buildBlockResponse(topThreat.category, clientIP)
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
