import Link from 'next/link'

export default function HomePage() {
  return (
    <div className="landing">
      <div className="landing-hero">
        <div className="landing-shield-icon">🛡️</div>
        <h1 className="landing-title">Xpecto Shield</h1>
        <p className="landing-subtitle">IDPS Dev Console // Testing Environment</p>

        <nav className="landing-nav">
          <Link href="/dashboard" className="landing-card">
            <div className="landing-card-icon">📊</div>
            <div className="landing-card-title">Dashboard</div>
            <div className="landing-card-desc">
              View the Shield admin dashboard<br />
              with real-time threat monitoring
            </div>
          </Link>

          <Link href="/tester" className="landing-card">
            <div className="landing-card-icon">💉</div>
            <div className="landing-card-title">Payload Tester</div>
            <div className="landing-card-desc">
              Fire exploit payloads and see<br />
              the detection engine in action
            </div>
          </Link>
        </nav>
      </div>

      <div className="landing-footer">
        Development Mode // In-Memory Store // No Database Required
      </div>
    </div>
  )
}
