// ═══════════════════════════════════════════════════════════════
// Xpecto Shield Dev — Test Target Endpoint
// ═══════════════════════════════════════════════════════════════
// This is a "dummy" API that acts as the target for exploit testing.
// The middleware will scan all requests to this endpoint.

import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  const url = new URL(request.url)
  const params = Object.fromEntries(url.searchParams.entries())

  return NextResponse.json({
    status: 'ok',
    message: '✅ Request passed through Shield — no threats detected.',
    method: 'GET',
    receivedParams: params,
    timestamp: new Date().toISOString(),
  })
}

export async function POST(request: NextRequest) {
  let body: Record<string, unknown> = {}
  try {
    body = await request.json()
  } catch {
    try {
      const text = await request.text()
      body = { raw: text }
    } catch {
      body = { error: 'Could not parse body' }
    }
  }

  return NextResponse.json({
    status: 'ok',
    message: '✅ Request passed through Shield — no threats detected.',
    method: 'POST',
    receivedBody: body,
    timestamp: new Date().toISOString(),
  })
}
