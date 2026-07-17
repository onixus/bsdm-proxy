import { useCallback, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { fetchDashboardMetrics, fetchTopMlScores } from '../api/metrics'
import type { DashboardMetric, MlScoreRow } from '../api/metrics'
import { MetricWidget, Panel, WidgetGrid } from '../components/dashboard/MetricWidget'
import { ThreatIndicator } from '../components/xai/ThreatIndicator'
import { Button } from '../components/ui/Button'
import { severityBadge } from '../theme/tokens'

export function DashboardPage() {
  const [metrics, setMetrics] = useState<DashboardMetric[]>([])
  const [mlScores, setMlScores] = useState<MlScoreRow[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    const [m, s] = await Promise.all([fetchDashboardMetrics(), fetchTopMlScores()])
    setMetrics(m)
    setMlScores(s)
    setLoading(false)
  }, [])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Dashboard</h1>
          <p className="text-sm text-text-secondary">
            Proxy health, cache performance, and ML anomaly overview
          </p>
        </div>
        <Button variant="secondary" onClick={load} disabled={loading}>
          <RefreshCw className={`size-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      <WidgetGrid>
        {metrics.map((m) => (
          <MetricWidget key={m.id} metric={m} />
        ))}
      </WidgetGrid>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Top ML anomalies (UEBA)">
          {mlScores.length === 0 ? (
            <p className="text-sm text-text-secondary">No scores available.</p>
          ) : (
            <ul className="space-y-4">
              {mlScores.map((row) => (
                <li key={`${row.entity_type}-${row.entity_id}`} className="space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <span className="font-mono text-sm text-text-primary">{row.entity_id}</span>
                      <span className="ml-2 text-xs text-text-secondary">({row.entity_type})</span>
                    </div>
                    <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${severityBadge(row.severity)}`}>
                      {row.severity}
                    </span>
                  </div>
                  <ThreatIndicator score={row.score} size="sm" />
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Quick ACL status">
          <p className="mb-4 text-sm text-text-secondary">
            Manage category blocks and runtime rules on the Policies page. REST API:
            <code className="ml-1 rounded bg-surface-0 px-1.5 py-0.5 font-mono text-xs">/api/acl/rules</code>
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            {['malware', 'phishing', 'gambling', 'adult'].map((cat) => (
              <div
                key={cat}
                className="flex items-center justify-between rounded-md border border-border bg-surface-0 px-3 py-2"
              >
                <span className="text-sm capitalize text-text-primary">{cat}</span>
                <span className="text-xs text-success">configured</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  )
}
