import { Link } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { fetchTelemetry, formatUptime, type Telemetry } from '../api/metrics'
import { fetchThreatScores } from '../api/threatScores'
import { fetchHierarchyPeers } from '../api/node'
import { useSourcedQuery } from '../hooks/useSourced'
import { Panel, StatTile, WidgetGrid } from '../components/dashboard/MetricWidget'
import { LineChart } from '../components/charts/LineChart'
import { SegmentBar, type Segment } from '../components/charts/SegmentBar'
import { BarList } from '../components/charts/BarList'
import { ThreatIndicator } from '../components/xai/ThreatIndicator'
import { Button } from '../components/ui/Button'
import { ErrorState, EmptyState, Skeleton, SourceBadge } from '../components/ui/DataState'
import { severityBadge } from '../theme/tokens'
import { cacheStatusColor, formatNumber, seriesColor, STATUS_VARS } from '../components/charts/common'

const POLL_MS = 10_000

export function DashboardPage() {
  const telemetry = useSourcedQuery(['telemetry'], fetchTelemetry, { refetchInterval: POLL_MS })
  const threats = useSourcedQuery(['threat-scores'], fetchThreatScores, { refetchInterval: 60_000 })
  const peers = useSourcedQuery(['hierarchy-peers'], fetchHierarchyPeers, { refetchInterval: 60_000 })

  const t = telemetry.data?.data

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">Dashboard</h1>
            {telemetry.data && <SourceBadge source={telemetry.data.source} />}
          </div>
          <p className="text-sm text-text-secondary">
            Proxy health, traffic, cache and threat overview · auto-refresh {POLL_MS / 1000}s
          </p>
        </div>
        <Button variant="secondary" onClick={() => telemetry.refetch()} disabled={telemetry.isFetching}>
          <RefreshCw className={`size-4 ${telemetry.isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {telemetry.isPending && (
        <WidgetGrid>
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </WidgetGrid>
      )}

      {telemetry.isError && (
        <ErrorState
          title="Proxy control API unreachable"
          detail={telemetry.error.message}
          onRetry={() => telemetry.refetch()}
        />
      )}

      {t && <HealthRow t={t} />}

      {t && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Panel title="Request rate (req/s)">
            <LineChart
              series={[
                { name: 'Requests', points: t.reqRate, slot: 0 },
                { name: 'ACL denies', points: t.denyRate, slot: 1 },
                { name: '5xx errors', points: t.errRate, slot: 7 },
              ]}
              area={false}
            />
          </Panel>
          <Panel title="Cache hit ratio (%)">
            <LineChart series={[{ name: 'Hit ratio', points: t.hitRatio, slot: 2 }]} area yMax={100} unit="%" />
          </Panel>
        </div>
      )}

      {t && (
        <div className="grid gap-6 lg:grid-cols-3">
          <Panel title="HTTP status mix (cumulative)">
            <SegmentBar segments={statusSegments(t.statusClasses)} />
          </Panel>
          <Panel title="Cache disposition (cumulative)">
            <SegmentBar segments={cacheSegments(t.cacheStatus)} />
          </Panel>
          <Panel title="ACL decisions (cumulative)">
            <SegmentBar
              segments={[
                { label: 'allow', value: t.aclDecisions.allow ?? 0, color: STATUS_VARS.good },
                { label: 'deny', value: (t.aclDecisions.deny ?? 0) + (t.aclDecisions.block ?? 0), color: STATUS_VARS.critical },
              ]}
            />
            {t.rateLimitRejected > 0 && (
              <p className="mt-3 text-xs text-text-secondary">
                Rate-limit rejections: <span className="tabular-nums text-warning">{formatNumber(t.rateLimitRejected)}</span>
              </p>
            )}
          </Panel>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        {t && (
          <Panel title="Top upstream hosts">
            {t.topUpstreams.length === 0 ? (
              <EmptyState message="No upstream metrics yet — traffic will populate this panel." />
            ) : (
              <BarList
                items={t.topUpstreams.map((u) => ({
                  label: u.host,
                  value: u.requests,
                  extra: u.errors > 0 ? `${formatNumber(u.errors)} err` : undefined,
                }))}
              />
            )}
          </Panel>
        )}

        <Panel
          title="Top ML anomalies (UEBA)"
          action={threats.data && <SourceBadge source={threats.data.source} />}
        >
          {threats.isError && <EmptyState message="ML worker unreachable — no scores." />}
          {threats.data && threats.data.data.scores.length === 0 && (
            <EmptyState message="No active threat scores in the write-back snapshot." />
          )}
          {threats.data && threats.data.data.scores.length > 0 && (
            <ul className="space-y-3">
              {[...threats.data.data.scores]
                .sort((a, b) => b.score - a.score)
                .slice(0, 5)
                .map((row) => (
                  <li key={`${row.entity_type}-${row.entity_id}-${row.model}`} className="space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Link
                        to={`/logs?q=${encodeURIComponent(entityQuery(row.entity_id))}`}
                        className="font-mono text-sm text-text-primary underline-offset-2 hover:underline"
                        title="Investigate related traffic"
                      >
                        {row.entity_id}
                      </Link>
                      <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${severityBadge(row.severity)}`}>
                        {row.severity}
                      </span>
                    </div>
                    <ThreatIndicator score={row.score} size="sm" label={row.model} />
                  </li>
                ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Hierarchy peers (ICP/HTCP)"
          action={peers.data && <SourceBadge source={peers.data.source} />}
        >
          {peers.isError && <EmptyState message="Hierarchy API unreachable or hierarchy disabled." />}
          {peers.data && peers.data.data.length === 0 && <EmptyState message="No cache hierarchy peers configured." />}
          {peers.data && peers.data.data.length > 0 && (
            <ul className="divide-y divide-border/50 text-sm">
              {peers.data.data.map((p, i) => (
                <li key={`${p.name ?? p.host ?? i}`} className="flex items-center justify-between gap-2 py-2">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-xs text-text-primary">{String(p.name ?? p.host ?? '—')}</p>
                    <p className="text-xs text-text-secondary">
                      {String(p.peer_type ?? 'peer')} · {String(p.host ?? '')}:{String(p.http_port ?? '')}
                    </p>
                  </div>
                  <span className={`text-xs font-semibold ${p.state === 'dead' ? 'text-danger' : 'text-success'}`}>
                    {String(p.state ?? 'alive')}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}

function HealthRow({ t }: { t: Telemetry }) {
  const errShare = shareOf(t.statusClasses, '5xx')
  const latP95Ms = t.latency ? t.latency.p95 * 1000 : null
  return (
    <WidgetGrid>
      <StatTile
        label="Requests / s"
        value={t.reqRate.length ? formatNumber(t.reqRate[t.reqRate.length - 1].v) : '—'}
        trend={t.reqRate}
        trendColor={seriesColor(0)}
        hint={`Total since start: ${t.totalRequests.toLocaleString()}`}
      />
      <StatTile
        label="Error share (5xx)"
        value={errShare === null ? '—' : (errShare * 100).toFixed(2)}
        unit="%"
        trend={t.errRate}
        trendColor={seriesColor(7)}
        status={errShare !== null && errShare > 0.05 ? 'error' : errShare !== null && errShare > 0.01 ? 'warn' : 'ok'}
      />
      <StatTile
        label="Cache hit rate"
        value={t.stats ? (t.stats.cache.hit_ratio * 100).toFixed(1) : '—'}
        unit="%"
        trend={t.hitRatio}
        trendColor={seriesColor(2)}
        hint={t.stats ? `${t.stats.cache.entries}/${t.stats.cache.capacity} L1 entries · ${formatNumber(t.cacheEvictions)} evictions` : undefined}
      />
      <StatTile
        label="Latency p95"
        value={latP95Ms === null ? '—' : formatNumber(latP95Ms)}
        unit="ms"
        trend={t.latP95}
        trendColor={seriesColor(3)}
        hint={t.latency ? `p50 ${(t.latency.p50 * 1000).toFixed(1)}ms · p99 ${(t.latency.p99 * 1000).toFixed(0)}ms` : 'Histogram not available'}
        status={latP95Ms !== null && latP95Ms > 500 ? 'warn' : 'ok'}
      />
      <StatTile
        label="In flight"
        value={t.stats ? String(t.stats.requests_in_flight) : '—'}
        trend={t.inFlight}
        trendColor={seriesColor(4)}
      />
      <StatTile
        label="Uptime"
        value={t.stats ? formatUptime(t.stats.uptime_secs) : '—'}
        hint={t.stats?.service}
      />
    </WidgetGrid>
  )
}

function shareOf(classes: Record<string, number>, key: string): number | null {
  const total = Object.values(classes).reduce((sum, v) => sum + v, 0)
  if (total === 0) return null
  return (classes[key] ?? 0) / total
}

function statusSegments(classes: Record<string, number>): Segment[] {
  const palette: Record<string, string> = {
    '2xx': STATUS_VARS.good,
    '3xx': seriesColor(0),
    '4xx': STATUS_VARS.warning,
    '5xx': STATUS_VARS.critical,
  }
  return Object.entries(classes)
    .sort()
    .map(([label, value]) => ({ label, value, color: palette[label] ?? seriesColor(6) }))
}

function cacheSegments(cache: Record<string, number>): Segment[] {
  const order = ['HIT', 'MISS', 'BYPASS', 'DENIED', 'COALESCED']
  const entries = Object.entries(cache).sort(
    (a, b) => (order.indexOf(a[0]) + 99) - (order.indexOf(b[0]) + 99) || b[1] - a[1],
  )
  return entries.map(([label, value]) => ({ label, value, color: cacheStatusColor(label) }))
}

/** client_ip|domain composite ids → search the domain part. */
function entityQuery(entityId: string): string {
  const parts = entityId.split('|')
  return parts[parts.length - 1]
}
