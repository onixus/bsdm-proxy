import { Activity, AlertTriangle, Clock, Database, ShieldCheck, Zap } from 'lucide-react'
import { formatUptime, type Telemetry } from '../../../api/metrics'
import { formatNumber, seriesColor } from '../../charts/common'
import { StatTile, WidgetGrid } from '../MetricWidget'
import { translations, type Language } from '../../../lib/i18n'

interface HealthOverviewProps {
  telemetry: Telemetry
  lang: Language
}

export function HealthOverview({ telemetry, lang }: HealthOverviewProps) {
  const tr = translations[lang]
  const errorShare = shareOf(telemetry.statusClasses, '5xx')
  const latency = telemetry.latency ? telemetry.latency.p95 * 1000 : null

  return (
    <WidgetGrid>
      <StatTile label="Интенсивность (Запросы/сек)" value={telemetry.reqRate.length ? formatNumber(telemetry.reqRate.at(-1)?.v ?? 0) : '—'} trend={telemetry.reqRate} trendColor={seriesColor(0)} hint={`Всего: ${telemetry.totalRequests.toLocaleString()}`} icon={Zap} />
      <StatTile label="Доля ошибок (5xx)" value={errorShare === null ? '—' : (errorShare * 100).toFixed(2)} unit="%" trend={telemetry.errRate} trendColor={seriesColor(7)} status={errorShare && errorShare > 0.05 ? 'error' : 'ok'} icon={AlertTriangle} />
      <StatTile label={tr.dashboard.cacheHitRatio} value={telemetry.stats ? (telemetry.stats.cache.hit_ratio * 100).toFixed(1) : '—'} unit="%" trend={telemetry.hitRatio} trendColor={seriesColor(2)} icon={Database} />
      <StatTile label="Latency p95" value={latency === null ? '—' : formatNumber(latency)} unit="мс" trend={telemetry.latP95} trendColor={seriesColor(3)} icon={Clock} />
      <StatTile label={tr.dashboard.activeConnections} value={telemetry.stats ? String(telemetry.stats.requests_in_flight) : '—'} trend={telemetry.inFlight} trendColor={seriesColor(4)} icon={Activity} />
      <StatTile label="Непрерывная работа" value={telemetry.stats ? formatUptime(telemetry.stats.uptime_secs) : '—'} icon={ShieldCheck} />
    </WidgetGrid>
  )
}

function shareOf(classes: Record<string, number>, key: string): number | null {
  const total = Object.values(classes).reduce((sum, value) => sum + value, 0)
  return total ? (classes[key] ?? 0) / total : null
}
