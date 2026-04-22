// ═══════════════════════════════════════════════════════════════
// Xpecto Shield Dev — In-Memory Mock Store
// ═══════════════════════════════════════════════════════════════
// Replaces Appwrite for local development. All data lives in RAM.

import type {
  IncidentLog,
  BlockedIP,
  AIReport,
  IncidentStats,
  ThreatCategory,
  PaginatedResult,
} from 'xpecto-shield/core'

// ─── Data Store ────────────────────────────────────────────────

const incidents: IncidentLog[] = []
const blockedIPs: BlockedIP[] = []
const reports: AIReport[] = []
const settings: Record<string, string> = {
  confidenceThreshold: '0.7',
  maxStrikes: '3',
  blockDuration: '86400',
}

// ─── Seed Data ─────────────────────────────────────────────────

function seedData() {
  if (incidents.length > 0) return // Already seeded

  const now = Date.now()
  const categories: ThreatCategory[] = ['sqli', 'xss', 'lfi', 'ssrf', 'path-traversal']
  const ips = ['192.168.1.100', '10.0.0.55', '172.16.0.33', '203.0.113.42', '198.51.100.7']
  const paths = ['/api/users', '/api/auth/login', '/api/search', '/api/files', '/api/admin']
  const payloads = [
    "' OR '1'='1'--",
    '<script>alert(1)</script>',
    '../../etc/passwd',
    'http://169.254.169.254/latest',
    '../../../etc/shadow',
  ]

  // Generate 25 seed incidents over the last 24 hours
  for (let i = 0; i < 25; i++) {
    const catIndex = i % categories.length
    const hoursAgo = Math.floor(Math.random() * 24)
    const timestamp = new Date(now - hoursAgo * 3600000 - Math.random() * 3600000)

    incidents.push({
      id: `seed-${i}`,
      timestamp: timestamp.toISOString(),
      sourceIP: ips[i % ips.length],
      requestPath: paths[catIndex],
      requestMethod: i % 3 === 0 ? 'POST' : 'GET',
      attackCategory: categories[catIndex],
      matchedPayload: payloads[catIndex],
      confidence: 0.7 + Math.random() * 0.3,
      rawInput: payloads[catIndex],
      action: 'blocked',
      userAgent: 'Mozilla/5.0 (TestBot)',
    })
  }

  // Sort by timestamp descending
  incidents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

  // Seed 2 blocked IPs
  blockedIPs.push({
    id: 'block-1',
    ipAddress: '203.0.113.42',
    reason: 'auto',
    strikeCount: 5,
    blockedAt: new Date(now - 3600000).toISOString(),
    expiresAt: new Date(now + 82800000).toISOString(),
    lastAttackCategory: 'sqli',
    isActive: true,
  })
  blockedIPs.push({
    id: 'block-2',
    ipAddress: '198.51.100.7',
    reason: 'auto',
    strikeCount: 3,
    blockedAt: new Date(now - 7200000).toISOString(),
    expiresAt: new Date(now + 79200000).toISOString(),
    lastAttackCategory: 'xss',
    isActive: true,
  })
}

// Seed on module load
seedData()

// ─── Public API ────────────────────────────────────────────────

let idCounter = 100

export function addIncident(incident: IncidentLog): IncidentLog {
  const withId = { ...incident, id: `inc-${idCounter++}` }
  incidents.unshift(withId) // Add to front (newest first)
  // Keep max 500 incidents in memory
  if (incidents.length > 500) incidents.pop()
  return withId
}

export function getIncidents(
  page: number = 1,
  limit: number = 20,
  category?: string,
): PaginatedResult<IncidentLog> {
  let filtered = incidents
  if (category) {
    filtered = incidents.filter(i => i.attackCategory === category)
  }

  const start = (page - 1) * limit
  const data = filtered.slice(start, start + limit)

  return {
    data,
    total: filtered.length,
    page,
    limit,
    hasMore: start + limit < filtered.length,
  }
}

export function getStats(): IncidentStats {
  const now = Date.now()
  const last24h = incidents.filter(
    i => now - new Date(i.timestamp).getTime() < 86400000
  )

  // Category breakdown
  const categoryBreakdown: Record<ThreatCategory, number> = {
    sqli: 0, xss: 0, lfi: 0, ssrf: 0, 'path-traversal': 0,
  }
  for (const inc of last24h) {
    categoryBreakdown[inc.attackCategory]++
  }

  // Hourly timeline
  const hourlyMap = new Map<string, number>()
  for (let h = 23; h >= 0; h--) {
    const d = new Date(now - h * 3600000)
    const key = `${d.getHours().toString().padStart(2, '0')}:00`
    hourlyMap.set(key, 0)
  }
  for (const inc of last24h) {
    const d = new Date(inc.timestamp)
    const key = `${d.getHours().toString().padStart(2, '0')}:00`
    hourlyMap.set(key, (hourlyMap.get(key) || 0) + 1)
  }
  const hourlyTimeline = Array.from(hourlyMap.entries()).map(([hour, count]) => ({ hour, count }))

  // Top attacker IPs
  const ipMap = new Map<string, { count: number; lastCategory: ThreatCategory }>()
  for (const inc of last24h) {
    const existing = ipMap.get(inc.sourceIP)
    if (existing) {
      existing.count++
      existing.lastCategory = inc.attackCategory
    } else {
      ipMap.set(inc.sourceIP, { count: 1, lastCategory: inc.attackCategory })
    }
  }
  const topAttackerIPs = Array.from(ipMap.entries())
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)

  // Average confidence
  const avgConf = last24h.length > 0
    ? last24h.reduce((sum, i) => sum + i.confidence, 0) / last24h.length
    : 0

  return {
    totalIncidents: incidents.length,
    totalBlockedIPs: blockedIPs.filter(b => b.isActive).length,
    activeThreats: last24h.length,
    categoryBreakdown,
    hourlyTimeline,
    topAttackerIPs,
    averageConfidence: avgConf,
  }
}

export function getBlockedIPsList(
  page: number = 1,
  limit: number = 20,
): PaginatedResult<BlockedIP> {
  const active = blockedIPs.filter(b => b.isActive)
  const start = (page - 1) * limit
  const data = active.slice(start, start + limit)
  return {
    data,
    total: active.length,
    page,
    limit,
    hasMore: start + limit < active.length,
  }
}

export function blockIP(ip: string, duration: number = 86400): void {
  const existing = blockedIPs.find(b => b.ipAddress === ip)
  if (existing) {
    existing.isActive = true
    existing.blockedAt = new Date().toISOString()
    existing.expiresAt = new Date(Date.now() + duration * 1000).toISOString()
    return
  }
  blockedIPs.push({
    id: `block-${idCounter++}`,
    ipAddress: ip,
    reason: 'manual',
    strikeCount: 0,
    blockedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + duration * 1000).toISOString(),
    lastAttackCategory: 'sqli',
    isActive: true,
  })
}

export function unblockIP(ip: string): void {
  const entry = blockedIPs.find(b => b.ipAddress === ip)
  if (entry) entry.isActive = false
}

export function getReportsList(): PaginatedResult<AIReport> {
  return {
    data: reports,
    total: reports.length,
    page: 1,
    limit: 25,
    hasMore: false,
  }
}

export function getSettings(): Record<string, string> {
  return { ...settings }
}

export function saveSettings(newSettings: Record<string, string>): void {
  Object.assign(settings, newSettings)
}
