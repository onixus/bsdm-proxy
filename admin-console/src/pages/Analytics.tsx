import { useMemo, useState } from 'react'
import { fetchThreatScores } from '../api/threatScores'
import { enrichLog, searchLogs } from '../api/search'
import { AnalyticsToolbar } from '../components/analytics/AnalyticsToolbar'
import { DistributionAnalytics } from '../components/analytics/DistributionAnalytics'
import { ThreatAnalytics } from '../components/analytics/ThreatAnalytics'
import { TrafficAnalytics } from '../components/analytics/TrafficAnalytics'
import { aggregateAnalytics, exportAnalyticsSummary } from '../components/analytics/analyticsUtils'
import { EmptyState, ErrorState, SkeletonRows, SourceBadge } from '../components/ui/DataState'
import { useSourcedQuery } from '../hooks/useSourced'
import { translations, useLanguage } from '../lib/i18n'

export function AnalyticsPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]
  const [days, setDays] = useState('7')
  const [limit, setLimit] = useState('1000')

  const logsQuery = useSourcedQuery(['analytics-logs', days, limit], () =>
    searchLogs({ days: Number(days), limit: Number(limit) }),
  )
  const threats = useSourcedQuery(['threat-scores'], fetchThreatScores)

  const logs = useMemo(() => (logsQuery.data?.data ?? []).map(enrichLog), [logsQuery.data])
  const agg = useMemo(
    () => aggregateAnalytics(logs, {
      allowed: tr.analytics.allowed,
      aclBlocked: tr.analytics.aclBlocked,
      mlBlocked: tr.analytics.mlBlocked,
      threatIntel: tr.analytics.threatIntel,
    }),
    [logs, tr],
  )

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <AnalyticsToolbar
        title={tr.analytics.title}
        subtitle={tr.analytics.subtitle}
        source={logsQuery.data ? <SourceBadge source={logsQuery.data.source} /> : undefined}
        days={days}
        limit={limit}
        labels={tr.analytics}
        isRefreshing={logsQuery.isFetching}
        canExport={logs.length > 0}
        onDaysChange={setDays}
        onLimitChange={setLimit}
        onRefresh={() => logsQuery.refetch()}
        onExport={() => exportAnalyticsSummary(agg)}
      />

      {logsQuery.isPending && <SkeletonRows rows={6} />}
      {logsQuery.isError && (
        <ErrorState title={tr.analytics.apiError} detail={logsQuery.error.message} onRetry={() => logsQuery.refetch()} />
      )}
      {logsQuery.data && logs.length === 0 && <EmptyState message={tr.analytics.emptyIndex} />}

      {logs.length > 0 && (
        <>
          <TrafficAnalytics
            title={tr.analytics.eventsOverTime}
            allLabel={tr.analytics.allEvents}
            blockedLabel={tr.analytics.blocked}
            all={agg.overTime.all}
            blocked={agg.overTime.blocked}
          />
          <DistributionAnalytics
            labels={tr.analytics}
            statusSegments={agg.statusSegments}
            cacheSegments={agg.cacheSegments}
            decisionSegments={agg.decisionSegments}
            topDomains={agg.topDomains}
            topClients={agg.topClients}
            topBlocked={agg.topBlocked}
          />
        </>
      )}

      <ThreatAnalytics
        labels={{
          threatSeverity: tr.analytics.threatSeverity,
          threatByModel: tr.analytics.threatByModel,
          mlUnreachable: tr.analytics.mlUnreachable,
          noActiveScores: tr.analytics.noActiveScores,
        }}
        snapshot={threats.data?.data}
        source={threats.data?.source}
        error={threats.isError}
      />
    </div>
  )
}
