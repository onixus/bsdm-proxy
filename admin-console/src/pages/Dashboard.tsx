import { Link } from 'react-router-dom'
import { RefreshCw, Zap, AlertTriangle, Database, Clock, Activity, ShieldCheck, Flame, Brain, Network, BarChart3, Shield } from 'lucide-react'

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
import { useLanguage, translations } from '../lib/i18n'

const POLL_MS = 10_000

export function DashboardPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]

  const telemetry = useSourcedQuery(['telemetry'], fetchTelemetry, { refetchInterval: POLL_MS })
  const threats = useSourcedQuery(['threat-scores'], fetchThreatScores, { refetchInterval: 60_000 })
  const peers = useSourcedQuery(['hierarchy-peers'], fetchHierarchyPeers, { refetchInterval: 60_000 })

  const t = telemetry.data?.data

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-border/80 bg-surface-1/70 p-5 backdrop-blur-md">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-text-primary">{tr.dashboard.title}</h1>
            {telemetry.data && <SourceBadge source={telemetry.data.source} />}
          </div>
          <p className="mt-1 text-sm text-text-secondary">
            {tr.dashboard.subtitle} · авто-обновление каждые {POLL_MS / 1000} сек
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="secondary" onClick={() => telemetry.refetch()} disabled={telemetry.isFetching}>
            <RefreshCw className={`size-4 ${telemetry.isFetching ? 'animate-spin' : ''}`} />
            {tr.common.refresh}
          </Button>
        </div>
      </div>

      {telemetry.isPending && (
        <WidgetGrid>
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </WidgetGrid>
      )}

      {telemetry.isError && (
        <ErrorState
          title="API управления прокси недоступен (Control API Unreachable)"
          detail={telemetry.error.message}
          onRetry={() => telemetry.refetch()}
        />
      )}

      {t && <HealthRow t={t} lang={lang} />}

      {t && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Panel title="Интенсивность запросов (запросов/сек / Request Rate)" icon={Activity}>
            <LineChart
              series={[
                { name: 'Запросы (Requests)', points: t.reqRate, slot: 0 },
                { name: 'Блокировки ACL', points: t.denyRate, slot: 1 },
                { name: 'Ошибки 5xx', points: t.errRate, slot: 7 },
              ]}
              area={false}
            />
          </Panel>
          <Panel title="Эффективность попаданий в кэш (% Cache Hit Ratio)" icon={Database}>
            <LineChart series={[{ name: 'Hit ratio', points: t.hitRatio, slot: 2 }]} area yMax={100} unit="%" />
          </Panel>
        </div>
      )}

      {t && (
        <div className="grid gap-6 lg:grid-cols-3">
          <Panel title="Распределение HTTP статусов" icon={BarChart3}>
            <SegmentBar segments={statusSegments(t.statusClasses)} />
          </Panel>
          <Panel title="Статусы обработки кэша" icon={Database}>
            <SegmentBar segments={cacheSegments(t.cacheStatus)} />
          </Panel>
          <Panel title="Решения системы фильтрации (ACL)" icon={Shield}>
            <SegmentBar
              segments={[
                { label: 'Разрешено (allow)', value: t.aclDecisions.allow ?? 0, color: STATUS_VARS.good },
                { label: 'Заблокировано (deny)', value: (t.aclDecisions.deny ?? 0) + (t.aclDecisions.block ?? 0), color: STATUS_VARS.critical },
              ]}
            />
            {t.rateLimitRejected > 0 && (
              <p className="mt-3 text-xs text-text-secondary">
                Отклонено по лимиту (Rate-limit): <span className="tabular-nums text-warning">{formatNumber(t.rateLimitRejected)}</span>
              </p>
            )}
          </Panel>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        {t && (
          <Panel title="Топ целевых серверов (Upstream Hosts)" icon={Flame}>
            {t.topUpstreams.length === 0 ? (
              <EmptyState message="Метрики upstream отсутствуют — данные появятся при поступлении трафика." />
            ) : (
              <BarList
                items={t.topUpstreams.map((u) => ({
                  label: u.host,
                  value: u.requests,
                  extra: u.errors > 0 ? `${formatNumber(u.errors)} ошиб.` : undefined,
                }))}
              />
            )}
          </Panel>
        )}

        <Panel
          title="Обнаруженные аномалии ML (UEBA)"
          icon={Brain}
          action={threats.data && <SourceBadge source={threats.data.source} />}
        >
          {threats.isError && <EmptyState message="Модуль ml-worker недоступен — оценки аномалий отсутствуют." />}
          {threats.data && threats.data.data.scores.length === 0 && (
            <EmptyState message="Активные угрозы в текущем снапшоте не обнаружены." />
          )}
          {threats.data && threats.data.data.scores.length > 0 && (
            <ul className="space-y-3">
              {[...threats.data.data.scores]
                .sort((a, b) => b.score - a.score)
                .slice(0, 5)
                .map((row) => (
                  <li key={`${row.entity_type}-${row.entity_id}-${row.model}`} className="space-y-1.5 rounded-lg border border-border/60 bg-surface-0/50 p-2.5 hover:border-accent/30 transition-all">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Link
                        to={`/logs?q=${encodeURIComponent(entityQuery(row.entity_id))}`}
                        className="font-mono text-xs font-bold text-text-primary underline-offset-2 hover:underline hover:text-accent"
                        title="Просмотреть логи данного объекта"
                      >
                        {row.entity_id}
                      </Link>
                      <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase ${severityBadge(row.severity)}`}>
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
          title="Ноды иерархии кэша (ICP/HTCP)"
          icon={Network}
          action={peers.data && <SourceBadge source={peers.data.source} />}
        >
          {peers.isError && <EmptyState message="API иерархии недоступно или отключено." />}
          {peers.data && peers.data.data.length === 0 && <EmptyState message="Соседние ноды кэширования не настроены." />}
          {peers.data && peers.data.data.length > 0 && (
            <ul className="divide-y divide-border/50 text-sm">
              {peers.data.data.map((p, i) => (
                <li key={`${p.name ?? p.host ?? i}`} className="flex items-center justify-between gap-2 py-2.5">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-xs font-semibold text-text-primary">{String(p.name ?? p.host ?? '—')}</p>
                    <p className="text-xs text-text-secondary">
                      {String(p.peer_type ?? 'peer')} · {String(p.host ?? '')}:{String(p.http_port ?? '')}
                    </p>
                  </div>
                  <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded-full border ${p.state === 'dead' ? 'border-danger/40 bg-danger/10 text-danger' : 'border-success/40 bg-success/10 text-success'}`}>
                    <span className={`size-1.5 rounded-full ${p.state === 'dead' ? 'bg-danger' : 'bg-success animate-pulse'}`} />
                    {String(p.state ?? 'alive') === 'alive' ? 'Активен' : 'Недоступен'}
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

function HealthRow({ t, lang }: { t: Telemetry; lang: 'ru' | 'en' }) {
  const tr = translations[lang]
  const errShare = shareOf(t.statusClasses, '5xx')
  const latP95Ms = t.latency ? t.latency.p95 * 1000 : null

  return (
    <WidgetGrid>
      <StatTile
        label="Интенсивность (Запросы/сек)"
        value={t.reqRate.length ? formatNumber(t.reqRate[t.reqRate.length - 1].v) : '—'}
        trend={t.reqRate}
        trendColor={seriesColor(0)}
        hint={`Всего обработано: ${t.totalRequests.toLocaleString()}`}
        icon={Zap}
      />
      <StatTile
        label="Доля ошибок (5xx)"
        value={errShare === null ? '—' : (errShare * 100).toFixed(2)}
        unit="%"
        trend={t.errRate}
        trendColor={seriesColor(7)}
        status={errShare !== null && errShare > 0.05 ? 'error' : errShare !== null && errShare > 0.01 ? 'warn' : 'ok'}
        icon={AlertTriangle}
      />
      <StatTile
        label={tr.dashboard.cacheHitRatio}
        value={t.stats ? (t.stats.cache.hit_ratio * 100).toFixed(1) : '—'}
        unit="%"
        trend={t.hitRatio}
        trendColor={seriesColor(2)}
        hint={t.stats ? `${t.stats.cache.entries}/${t.stats.cache.capacity} L1 записей` : undefined}
        icon={Database}
      />
      <StatTile
        label="Задержка (Latency p95)"
        value={latP95Ms === null ? '—' : formatNumber(latP95Ms)}
        unit="мс"
        trend={t.latP95}
        trendColor={seriesColor(3)}
        hint={t.latency ? `p50 ${(t.latency.p50 * 1000).toFixed(1)}мс · p99 ${(t.latency.p99 * 1000).toFixed(0)}мс` : 'Гистограмма недоступна'}
        status={latP95Ms !== null && latP95Ms > 500 ? 'warn' : 'ok'}
        icon={Clock}
      />
      <StatTile
        label={tr.dashboard.activeConnections}
        value={t.stats ? String(t.stats.requests_in_flight) : '—'}
        trend={t.inFlight}
        trendColor={seriesColor(4)}
        icon={Activity}
      />
      <StatTile
        label="Непрерывная работа"
        value={t.stats ? formatUptime(t.stats.uptime_secs) : '—'}
        hint={t.stats?.service}
        icon={ShieldCheck}
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

function entityQuery(entityId: string): string {
  const parts = entityId.split('|')
  return parts[parts.length - 1]
}

