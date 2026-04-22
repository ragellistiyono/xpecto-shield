'use client'

import { ShieldDashboard } from 'xpecto-shield/dashboard'

export default function DashboardPage() {
  return (
    <div className="dashboard-wrapper">
      <ShieldDashboard apiBase="/api/shield" />
    </div>
  )
}
