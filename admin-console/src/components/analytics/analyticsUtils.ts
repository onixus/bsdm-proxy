import type { EnrichedLog } from '../../api/search'
import type { Segment } from '../charts/SegmentBar'
import { cacheStatusColor, seriesColor, STATUS_VARS } from '../charts/common'
import type { TsPoint } from '../../lib/timeseries'

export interface AnalyticsLabels {
  allowed: string
  aclBlocked: string
  mlBlocked: string
  threatIntel: string
}

export interface AnalyticsAggregates {
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

export function aggregateAnalytics(logs: EnrichedLog[], labels: AnalyticsLabels): AnalyticsAggregates {
  const timestamps = logs.map((log) => log.ts)
  const tMin = timestamps.length ? Math.min(...timestamps) : 0
  const tMax = timestamps.length ? Math.max(...timestamps) : 1
  const bucketCount = 40
  const span = Math.max(tMax - tMin, 1)
  const bucketSize = span / bucketCount
  const all = new Array<number>(bucketCount).fill(0)
  const blocked = new Array<number>(bucketCount).fill(0)

  for (const log of logs) {
    const index = Math.min(Math.floor((log.ts - tMin) / bucketSize), bucketCount - 1)
    all[index] += 1
    if (log.blockReason !== 'none') blocked[index] += 1
  }

  const toPoints = (values: number[]): TsPoint[] =>
    values.map((value, index) => ({
      t: (tMin + (index + 0.5) * bucketSize) * 1000,
      v: value,
    }))

  const statusPalette: Record<string, string> = {
    '2xx': STATUS_VARS.good,
    '3xx': seriesColor(0),
    '4xx': STATUS_VARS.warning,
    '5xx': STATUS_VARS.critical,
  }
  const decisions: Record<string, { label: string; color: string }> = {
    none: { label: labels.allowed, color: STATUS_VARS.good },
    acl: { label: labels.aclBlocked, color: seriesColor(1) },
    ml: { label: labels.mlBlocked, color: STATUS_VARS.critical },
    threat: { label: labels.threatIntel, color: STATUS_VARS.serious },
  }

  return {
    tMin,
    tMax,
    overTime: { all: toPoints(all), blocked: toPoints(blocked) },
    statusSegments: countBy(logs.map((log) => (log.status ? `${String(log.status)[0]}xx` : '(none)'))).map(
      ([label, value]) => ({ label, value, color: statusPalette[label] ?? seriesColor(6) }),
    ),
    cacheSegments: countBy(logs.map((log) => log.cache_status ?? '(none)')).map(([label, value]) => ({
      label,
      value,
      color: cacheStatusColor(label),
    })),
    decisionSegments: countBy(logs.map((log) => log.blockReason)).map(([key, value]) => ({
      label: decisions[key]?.label ?? key,
      value,
      color: decisions[key]?.color ?? seriesColor(6),
    })),
    topDomains: countBy(logs.map((log) => log.domain ?? '(none)')).slice(0, 8),
    topClients: countBy(logs.map((log) => log.client_ip ?? '(none)')).slice(0, 8),
    topBlocked: countBy(
      logs.filter((log) => log.blockReason !== 'none').map((log) => log.domain ?? '(none)'),
    ).slice(0, 8),
  }
}

export function countBy(values: string[]): [string, number][] {
  const counts = new Map<string, number>()
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1)
  return [...counts.entries()].sort((a, b) => b[1] - a[1])
}

export function severitySegments(severities: string[]): Segment[] {
  const palette: Record<string, string> = {
    critical: STATUS_VARS.critical,
    high: STATUS_VARS.serious,
    medium: STATUS_VARS.warning,
    low: STATUS_VARS.good,
  }
  const order = ['critical', 'high', 'medium', 'low']

  return countBy(severities.map((severity) => severity.toLowerCase()))
    .sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]))
    .map(([label, value]) => ({ label, value, color: palette[label] ?? seriesColor(6) }))
}

export function exportAnalyticsSummary(aggregates: AnalyticsAggregates): void {
  const lines = ['section,key,value']
  const add = (section: string, entries: [string, number][] | Segment[]) => {
    for (const entry of entries) {
      const [key, value] = Array.isArray(entry) ? entry : [entry.label, entry.value]
      lines.push(`${section},"${String(key).replace(/"/g, '""')}",${value}`)
    }
  }

  add('status', aggregates.statusSegments)
  add('cache', aggregates.cacheSegments)
  add('decision', aggregates.decisionSegments)
  add('top_domains', aggregates.topDomains)
  add('top_clients', aggregates.topClients)
  add('top_blocked', aggregates.topBlocked)

  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `bsdm-analytics-${new Date().toISOString().slice(0, 19)}.csv`
  anchor.click()
  URL.revokeObjectURL(url)
}
