'use client'

import { useState, useCallback } from 'react'
import Link from 'next/link'

// ─── Quick Payload Presets ─────────────────────────────────────

const QUICK_PAYLOADS: Record<string, Array<{ label: string; value: string }>> = {
  sqli: [
    { label: "' OR '1'='1'--", value: "' OR '1'='1'--" },
    { label: "UNION SELECT null", value: "1 UNION SELECT null,null,null--" },
    { label: "DROP TABLE", value: "'; DROP TABLE users;--" },
    { label: "SLEEP injection", value: "1' AND SLEEP(5)--" },
    { label: "Benchmark", value: "1' AND benchmark(10000000,SHA1('test'))--" },
  ],
  xss: [
    { label: "<script>alert</script>", value: "<script>alert(1)</script>" },
    { label: "img onerror", value: '<img src=x onerror=alert(1)>' },
    { label: "svg onload", value: '<svg onload=alert(1)>' },
    { label: "javascript: URI", value: "javascript:alert(document.cookie)" },
    { label: "Event handler", value: '" onclick=alert(1) x="' },
  ],
  lfi: [
    { label: "/etc/passwd", value: "../../etc/passwd" },
    { label: "/etc/shadow", value: "../../../../etc/shadow" },
    { label: "Windows path", value: "..\\..\\windows\\system32\\config\\sam" },
    { label: "/proc/self/environ", value: "/proc/self/environ" },
  ],
  'path-traversal': [
    { label: "../../../", value: "../../../" },
    { label: "URL encoded", value: "..%2f..%2f..%2f" },
    { label: "Double encoded", value: "..%252f..%252f" },
    { label: "Dotdot slash", value: "....//....//....//etc/passwd" },
  ],
  ssrf: [
    { label: "AWS Metadata", value: "http://169.254.169.254/latest/meta-data/" },
    { label: "Localhost", value: "http://127.0.0.1:8080/admin" },
    { label: "IPv6 localhost", value: "http://[::1]/admin" },
    { label: "Internal", value: "http://localhost:3000/api/internal" },
  ],
}

type LogEntry = {
  id: number
  time: string
  status: 'blocked' | 'passed'
  statusCode: number
  payload: string
  category?: string
  duration: number
}

export default function TesterPage() {
  const [method, setMethod] = useState<'GET' | 'POST'>('GET')
  const [payload, setPayload] = useState('')
  const [paramName, setParamName] = useState('q')
  const [category, setCategory] = useState('sqli')
  const [loading, setLoading] = useState(false)
  const [response, setResponse] = useState<{
    status: number
    statusText: string
    body: string
    blocked: boolean
    headers: Record<string, string>
  } | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])

  let logIdRef = 0

  const firePayload = useCallback(async () => {
    if (!payload.trim()) return
    setLoading(true)

    const startTime = performance.now()

    try {
      let res: Response

      if (method === 'GET') {
        const params = new URLSearchParams({ [paramName]: payload })
        res = await fetch(`/api/test-target?${params}`, {
          headers: { 'Accept': 'application/json' },
        })
      } else {
        res = await fetch('/api/test-target', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify({ [paramName]: payload }),
        })
      }

      const duration = Math.round(performance.now() - startTime)
      const bodyText = await res.text()
      const blocked = res.status === 403

      // Parse response headers
      const headers: Record<string, string> = {}
      res.headers.forEach((value, key) => {
        headers[key] = value
      })

      setResponse({
        status: res.status,
        statusText: res.statusText,
        body: bodyText,
        blocked,
        headers,
      })

      // Add to log
      const logEntry: LogEntry = {
        id: logIdRef++,
        time: new Date().toLocaleTimeString('en-US', { hour12: false }),
        status: blocked ? 'blocked' : 'passed',
        statusCode: res.status,
        payload: payload.substring(0, 80),
        category: blocked ? headers['x-shield-category'] || '?' : undefined,
        duration,
      }

      setLogs(prev => [logEntry, ...prev.slice(0, 49)])
    } catch (err) {
      setResponse({
        status: 0,
        statusText: 'Network Error',
        body: err instanceof Error ? err.message : 'Request failed',
        blocked: false,
        headers: {},
      })
    } finally {
      setLoading(false)
    }
  }, [payload, method, paramName])

  const handleQuickPayload = (value: string) => {
    setPayload(value)
  }

  const fireSafe = useCallback(async () => {
    setPayload('Hello, I am a normal user browsing your website')
    setLoading(true)
    const startTime = performance.now()

    try {
      const params = new URLSearchParams({ q: 'Hello, I am a normal user browsing your website' })
      const res = await fetch(`/api/test-target?${params}`, {
        headers: { 'Accept': 'application/json' },
      })
      const duration = Math.round(performance.now() - startTime)
      const bodyText = await res.text()
      const headers: Record<string, string> = {}
      res.headers.forEach((v, k) => { headers[k] = v })

      setResponse({
        status: res.status,
        statusText: res.statusText,
        body: bodyText,
        blocked: res.status === 403,
        headers,
      })

      setLogs(prev => [{
        id: logIdRef++,
        time: new Date().toLocaleTimeString('en-US', { hour12: false }),
        status: 'passed',
        statusCode: res.status,
        payload: 'Hello, I am a normal user...',
        duration,
      }, ...prev.slice(0, 49)])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  return (
    <div className="tester">
      <div className="tester-content">
        {/* Header */}
        <div className="tester-header">
          <h1 className="tester-title">
            ⚡ Payload Tester
          </h1>
          <Link href="/" className="tester-back">← Back</Link>
        </div>

        {/* Main Grid */}
        <div className="tester-grid">
          {/* Left: Input Panel */}
          <div className="tester-panel">
            <div className="tester-panel-title">Attack Configuration</div>

            {/* Method & Param */}
            <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
              <div style={{ flex: '0 0 100px' }}>
                <label className="tester-label">Method</label>
                <select
                  className="tester-select"
                  value={method}
                  onChange={e => setMethod(e.target.value as 'GET' | 'POST')}
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label className="tester-label">Param Name</label>
                <input
                  className="tester-input"
                  value={paramName}
                  onChange={e => setParamName(e.target.value)}
                  placeholder="q"
                />
              </div>
            </div>

            {/* Payload Input */}
            <div className="tester-input-group">
              <label className="tester-label">Payload</label>
              <textarea
                className="tester-textarea"
                value={payload}
                onChange={e => setPayload(e.target.value)}
                placeholder="Enter your exploit payload here..."
                rows={3}
              />
            </div>

            {/* Action Buttons */}
            <div className="tester-btn-row" style={{ marginBottom: '1.5rem' }}>
              <button
                className="tester-btn tester-btn--fire"
                onClick={firePayload}
                disabled={loading || !payload.trim()}
              >
                {loading ? '⟳ Sending...' : '🔥 Fire!'}
              </button>
              <button
                className="tester-btn"
                onClick={fireSafe}
                disabled={loading}
              >
                ✅ Send Safe
              </button>
              <button
                className="tester-btn tester-btn--sm"
                onClick={() => { setPayload(''); setResponse(null) }}
              >
                ✕ Clear
              </button>
            </div>

            {/* Quick Payloads */}
            <div>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.5rem' }}>
                <label className="tester-label" style={{ marginBottom: 0 }}>Quick Payloads</label>
                <select
                  className="tester-select"
                  style={{ width: '160px', padding: '0.25rem 0.5rem', fontSize: '0.7rem' }}
                  value={category}
                  onChange={e => setCategory(e.target.value)}
                >
                  <option value="sqli">SQL Injection</option>
                  <option value="xss">XSS</option>
                  <option value="lfi">LFI</option>
                  <option value="path-traversal">Path Traversal</option>
                  <option value="ssrf">SSRF</option>
                </select>
              </div>
              <div className="quick-payloads">
                {QUICK_PAYLOADS[category]?.map((p, i) => (
                  <button
                    key={i}
                    className="quick-payload-btn"
                    onClick={() => handleQuickPayload(p.value)}
                    title={p.value}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Right: Response Panel */}
          <div className="tester-panel">
            <div className="tester-panel-title">Response</div>
            <div className="tester-response">
              {response ? (
                <>
                  <div className={`tester-response-status ${
                    response.blocked
                      ? 'tester-response-status--blocked'
                      : 'tester-response-status--passed'
                  }`}>
                    {response.blocked ? '🛡️ BLOCKED' : '✅ PASSED'} — {response.status} {response.statusText}
                    {response.headers['x-shield-category'] && (
                      <span style={{ marginLeft: '0.75rem', opacity: 0.7 }}>
                        [{response.headers['x-shield-category'].toUpperCase()}]
                      </span>
                    )}
                  </div>
                  <pre className="tester-response-body">
                    {(() => {
                      try {
                        return JSON.stringify(JSON.parse(response.body), null, 2)
                      } catch {
                        // For HTML block pages, show a summary
                        if (response.body.includes('Access Denied')) {
                          return `[HTML Block Page]\n\nXpecto Shield blocked this request.\nCategory: ${response.headers['x-shield-category'] || 'unknown'}\nStatus: 403 Forbidden\n\nThe full HTML block page was returned to the client.`
                        }
                        return response.body.substring(0, 500)
                      }
                    })()}
                  </pre>
                </>
              ) : (
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: '100%',
                  minHeight: '150px',
                  color: 'rgba(255,255,255,0.2)',
                  fontFamily: 'var(--dev-font-accent)',
                  fontSize: '0.75rem',
                  textTransform: 'uppercase',
                  letterSpacing: '2px',
                }}>
                  <div style={{ fontSize: '2rem', marginBottom: '0.75rem', opacity: 0.3 }}>⏳</div>
                  Awaiting payload...
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Log Panel */}
        <div className="tester-log">
          <div className="tester-panel-title">
            Detection Log ({logs.length} entries)
          </div>
          {logs.length === 0 ? (
            <div style={{
              textAlign: 'center',
              padding: '2rem',
              color: 'rgba(255,255,255,0.2)',
              fontFamily: 'var(--dev-font-accent)',
              fontSize: '0.7rem',
              textTransform: 'uppercase',
              letterSpacing: '2px',
            }}>
              No requests sent yet
            </div>
          ) : (
            logs.map((entry) => (
              <div key={entry.id} className="tester-log-entry">
                <span className="tester-log-time">{entry.time}</span>
                <span className={`tester-log-status tester-log-status--${entry.status}`}>
                  {entry.status === 'blocked' ? '⛔ Blocked' : '✅ Passed'}
                </span>
                <span className="tester-log-detail">
                  {entry.statusCode} — {entry.payload}
                </span>
                {entry.category && (
                  <span className="tester-log-category" style={{
                    color: entry.category === 'sqli' ? 'var(--dev-destructive)' :
                           entry.category === 'xss' ? 'var(--dev-accent-secondary)' :
                           'var(--dev-accent-tertiary)',
                    borderColor: 'currentColor',
                  }}>
                    {entry.category}
                  </span>
                )}
                <span style={{
                  fontSize: '0.6rem',
                  color: 'rgba(255,255,255,0.25)',
                  fontFamily: 'var(--dev-font-body)',
                }}>
                  {entry.duration}ms
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
