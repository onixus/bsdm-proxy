import { useMemo, useState } from 'react'
import { Download, RefreshCw } from 'lucide-react'
import { enrichLog, searchLogs, type EnrichedLog } from '../api/search'
import { fetchThreatScores } from '../api/threatScores'
import { useSourcedQuery } from '../hooks/useSourced'
import { Panel } from '../components/dashboard/MetricWidget'
import { LineChart } from '../components/charts/LineChart'
import { SegmentBar, type Segment } from '../components/charts/SegmentBar'
import { BarList } from '../components/charts/BarList'
import { Button } from '../components/ui/Button'
import { Select } from '../components/ui/Form'
import { ErrorState, EmptyState, SkeletonRows, SourceBadge } from '../components/ui/DataState'
import { cacheStatusColor, seriesColor, STATUS_VARS } from '../components/charts/common'
import type { TsPoint } from '../lib/timeseries'

export function AnalyticsPage() {
  const [days, setDays] = useState('7')
  const [limit, setLimit] = useState('1000')

  const logsQuery = useSourcedQuery(['analytics-logs', days, limit], () =>
    searchLogs({ days: Number(days), limit: Number(limit) }),
  )
  const threats = useSourcedQuery(['threat-scores'], fetchThreatScores)

  const logs = useMemo(() => (logsQuery.data?.data ?? []).map(enrichLog), [logsQuery.data])
  const agg = useMemo(() => aggregate(logs), [logs])

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">Analytics</h1>
            {logsQuery.data && <SourceBadge source={logsQuery.data.source} />}
          </div>
          <p className="text-sm text-text-secondary">
            Aggregations over the retro-search sample — traffic mix, blocking activity, top talkers
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <Select
            label="Window"
            value={days}
            onChange={(e) => setDays(e.target.value)}
            options={[
              { value: '1', label: 'Last 24h' },
              { value: '7', label: 'Last 7 days' },
              { value: '30', label: 'Last 30 days' },
            ]}
          />
          <Select
            label="Sample"
            value={limit}
            onChange={(e) => setLimit(e.target.value)}
            options={[
              { value: '500', label: '500 events' },
              { value: '1000', label: '1000 events' },
              { value: '5000', label: '5000 events' },
            ]}
          />
          <Button variant="secondary" onClick={() => logsQuery.refetch()} disabled={logsQuery.isFetching}>
            <RefreshCw className={`size-4 ${logsQuery.isFetching ? 'animate-spin' : ''}`} />
          </Button>
          <Button variant="secondary" onClick={() => exportSummary(agg)} disabled={logs.length === 0}>
            <Download className="size-4" /> Summary CSV
          </Button>
        </div>
      </div>

      {logsQuery.isPending && <SkeletonRows rows={6} />}
      {logsQuery.isError && (
        <ErrorState title="Search API unreachable" detail={logsQuery.error.message} onRetry={() => logsQuery.refetch()} />
      )}
      {logsQuery.data && logs.length === 0 && (
        <EmptyState message="No events in the selected window — analytics needs traffic in the Search index." />
      )}

      {logs.length > 0 && (
        <>
          <p className="text-xs text-text-secondary">
            Sample: <span className="tabular-nums text-text-primary">{logs.length.toLocaleString()}</span> events,{' '}
            {new Date(agg.tMin * 1000).toLocaleString()} → {new Date(agg.tMax * 1000).toLocaleString()}. Counts below
            describe this sample, not total traffic.
          </p>

          <Panel title="Events over time">
            <LineChart
              series={[
                { name: 'All events', points: agg.overTime.all, slot: 0 },
                { name: 'Blocked', points: agg.overTime.blocked, slot: 7 },
              ]}
              height={220}
            />
          </Panel>

          <div className="grid gap-6 lg:grid-cols-3">
            <Panel title="HTTP status mix">
              <SegmentBar segments={agg.statusSegments} />
            </Panel>
            <Panel title="Cache disposition">
              <SegmentBar segments={agg.cacheSegments} />
            </Panel>
            <Panel title="Decision mix">
              <SegmentBar segments={agg.decisionSegments} />
            </Panel>
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <Panel title="Top domains">
              <BarList items={agg.topDomains.map(([label, value]) => ({ label, value }))} />
            </Panel>
            <Panel title="Top clients">
              <BarList items={agg.topClients.map(([label, value]) => ({ label, value, color: seriesColor(1) }))} />
            </Panel>
            <Panel title="Top blocked domains">
              {agg.topBlocked.length === 0 ? (
                <EmptyState message="No blocked requests in this sample." />
              ) : (
                <BarList items={agg.topBlocked.map(([label, value]) => ({ label, value, color: STATUS_VARS.critical }))} />
              )}
            </Panel>
          </div>
        </>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Threat score severity" action={threats.data && <SourceBadge source={threats.data.source} />}>
          {threats.isError && <EmptyState message="ML worker unreachable." />}
          {threats.data && <SegmentBar segments={severitySegments(threats.data.data.scores.map((s) => s.severity))} />}
        </Panel>
        <Panel title="Threat scores by model">
          {threats.data && threats.data.data.scores.length > 0 ? (
            <BarList
              items={countBy(threats.data.data.scores.map((s) => s.model))
                .slice(0, 8)
                .map(([label, value], i) => ({ label, value, color: seriesColor(i) }))}
            />
          ) : (
            <EmptyState message="No active scores." />
          )}
        </Panel>
      </div>
    </div>
  )
}

interface Aggregates {
  tMin: number
  tMax: number
  overTime: { all: TsPoint[]; blocked: TsPoint[] }
  statusSegments: Segment[]
  cacheSegments: Segment[]
  decisionSegments: Segment[]
  topDomains: [string, number][]
  topClients: [string, number][]
  topBlocked: [string, number][]
}

function aggregate(logs: EnrichedLog[]): Aggregates {
  const ts = logs.map((l) => l.ts)
  const tMin = ts.length ? Math.min(...ts) : 0
  const tMax = ts.length ? Math.max(...ts) : 1

  const bucketCount = 40
  const span = Math.max(tMax - tMin, 1)
  const bucketSize = span / bucketCount
  const all = new Array(bucketCount).fill(0)
  const blocked = new Array(bucketCount).fill(0)
  for (const l of logs) {
    const i = Math.min(Math.floor((l.ts - tMin) / bucketSize), bucketCount - 1)
    all[i] += 1
    if (l.blockReason !== 'none') blocked[i] += 1
  }
  const toPoints = (arr: number[]): TsPoint[] =>
    arr.map((v, i) => ({ t: (tMin + (i + 0.5) * bucketSize) * 1000, v }))

  const statusPalette: Record<string, string> = {
    '2xx': STATUS_VARS.good,
    '3xx': seriesColor(0),
    '4xx': STATUS_VARS.warning,
    '5xx': STATUS_VARS.critical,
  }
  const decisions: Record<string, { label: string; color: string }> = {
    none: { label: 'Allowed', color: STATUS_VARS.good },
    acl: { label: 'ACL blocked', color: seriesColor(1) },
    ml: { label: 'ML blocked', color: STATUS_VARS.critical },
    threat: { label: 'Threat intel', color: STATUS_VARS.serious },
  }

  return {
    tMin,
    tMax,
    overTime: { all: toPoints(all), blocked: toPoints(blocked) },
    statusSegments: countBy(logs.map((l) => (l.status ? `${String(l.status)[0]}xx` : '(none)'))).map(
      ([label, value]) => ({ label, value, color: statusPalette[label] ?? seriesColor(6) }),
    ),
    cacheSegments: countBy(logs.map((l) => l.cache_status ?? '(none)')).map(([label, value]) => ({
      label,
      value,
      color: cacheStatusColor(label),
    })),
    decisionSegments: countBy(logs.map((l) => l.blockReason)).map(([key, value]) => ({
      label: decisions[key]?.label ?? key,
      value,
      color: decisions[key]?.color ?? seriesColor(6),
    })),
    topDomains: countBy(logs.map((l) => l.domain ?? '(none)')).slice(0, 8),
    topClients: countBy(logs.map((l) => l.client_ip ?? '(none)')).slice(0, 8),
    topBlocked: countBy(logs.filter((l) => l.blockReason !== 'none').map((l) => l.domain ?? '(none)')).slice(0, 8),
  }
}

function countBy(values: string[]): [string, number][] {
  const map = new Map<string, number>()
  for (const v of values) map.set(v, (map.get(v) ?? 0) + 1)
  return [...map.entries()].sort((a, b) => b[1] - a[1])
}

function severitySegments(severities: string[]): Segment[] {
  const palette: Record<string, string> = {
    critical: STATUS_VARS.critical,
    high: STATUS_VARS.serious,
    medium: STATUS_VARS.warning,
    low: STATUS_VARS.good,
  }
  const order = ['critical', 'high', 'medium', 'low']
  return countBy(severities.map((s) => s.toLowerCase()))
    .sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]))
    .map(([label, value]) => ({ label, value, color: palette[label] ?? seriesColor(6) }))
}

function exportSummary(agg: Aggregates): void {
  const lines = ['section,key,value']
  const add = (section: string, entries: [string, number][] | Segment[]) => {
    for (const e of entries) {
      const [k, v] = Array.isArray(e) ? e : [e.label, e.value]
      lines.push(`${section},"${String(k).replace(/"/g, '""')}",${v}`)
    }
  }
  add('status', agg.statusSegments)
  add('cache', agg.cacheSegments)
  add('decision', agg.decisionSegments)
  add('top_domains', agg.topDomains)
  add('top_clients', agg.topClients)
  add('top_blocked', agg.topBlocked)
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `bsdm-analytics-${new Date().toISOString().slice(0, 19)}.csv`
  a.click()
  URL.revokeObjectURL(a.href)
}
