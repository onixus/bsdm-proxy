import { RefreshCw } from 'lucide-react'

import { fetchTelemetry } from '../api/metrics'
import { fetchHierarchyPeers } from '../api/node'
import { fetchThreatScores } from '../api/threatScores'
import { WidgetGrid } from '../components/dashboard/MetricWidget'
import { DecisionSourcePanel } from '../components/dashboard/widgets/DecisionSourcePanel'
import { DistributionOverview } from '../components/dashboard/widgets/DistributionOverview'
import { HealthOverview } from '../components/dashboard/widgets/HealthOverview'
import { PeerOverview } from '../components/dashboard/widgets/PeerOverview'
import { ThreatOverview } from '../components/dashboard/widgets/ThreatOverview'
import { TrafficOverview } from '../components/dashboard/widgets/TrafficOverview'
import { UpstreamOverview } from '../components/dashboard/widgets/UpstreamOverview'
import { Button } from '../components/ui/Button'
import { ErrorState, Skeleton, SourceBadge } from '../components/ui/DataState'
import { PageHeader } from '../components/ui/PageHeader'
import { useSourcedQuery } from '../hooks/useSourced'
import { fmt, translations, useLanguage } from '../lib/i18n'

const POLL_MS = 10_000

export function DashboardPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]

  const telemetry = useSourcedQuery(['telemetry'], fetchTelemetry, { refetchInterval: POLL_MS })
  const threats = useSourcedQuery(['threat-scores'], fetchThreatScores, { refetchInterval: 60_000 })
  const peers = useSourcedQuery(['hierarchy-peers'], fetchHierarchyPeers, { refetchInterval: 60_000 })

  const snapshot = telemetry.data?.data

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="surface-panel rounded-2xl p-5">
        <PageHeader
          title={tr.dashboard.title}
          subtitle={`${tr.dashboard.subtitle} · ${fmt(tr.widgets.autoRefresh, { seconds: POLL_MS / 1000 })}`}
          badge={telemetry.data ? <SourceBadge source={telemetry.data.source} /> : undefined}
          actions={
            <Button variant="secondary" onClick={() => telemetry.refetch()} disabled={telemetry.isFetching}>
              <RefreshCw className={`size-4 ${telemetry.isFetching ? 'animate-spin' : ''}`} />
              {tr.common.refresh}
            </Button>
          }
        />
      </div>

      {telemetry.isPending && (
        <WidgetGrid>
          {Array.from({ length: 6 }, (_, index) => (
            <Skeleton key={index} className="h-24 rounded-xl" />
          ))}
        </WidgetGrid>
      )}

      {telemetry.isError && (
        <ErrorState
          title={tr.widgets.controlApiError}
          detail={telemetry.error.message}
          onRetry={() => telemetry.refetch()}
        />
      )}

      {snapshot && <HealthOverview telemetry={snapshot} lang={lang} />}
      {snapshot && <TrafficOverview telemetry={snapshot} />}
      {snapshot && <DistributionOverview telemetry={snapshot} />}
      {snapshot && <DecisionSourcePanel telemetry={snapshot} />}

      <div className="grid gap-6 lg:grid-cols-3">
        {snapshot && <UpstreamOverview telemetry={snapshot} />}
        <ThreatOverview
          snapshot={threats.data?.data}
          source={threats.data?.source}
          error={threats.isError}
        />
        <PeerOverview peers={peers.data?.data} source={peers.data?.source} error={peers.isError} />
      </div>
    </div>
  )
}
