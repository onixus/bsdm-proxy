import { loadApiSettings } from './settings'
import { apiFetch } from './client'
import { fetchThreatScores } from './threatScores'

export interface DashboardMetric {
  id: string
  label: string
  value: string | number
  trend?: 'up' | 'down' | 'flat'
  unit?: string
  status?: 'ok' | 'warn' | 'error'
}

export interface MlScoreRow {
  entity_id: string
  entity_type: string
  score: number
  severity: string
  model: string
  scored_at: string
  features_json?: string
}

export interface ProxyStats {
  service: string
  uptime_secs: number
  requests_in_flight: number
  cache: {
    hits: number
    misses: number
    bypasses: number
    hit_ratio: number
    entries: number
    capacity: number
    shards: number
  }
}

export async function fetchProxyStats(): Promise<ProxyStats | null> {
  const settings = loadApiSettings()
  try {
    return await apiFetch<ProxyStats>('/api/stats', { baseUrl: settings.metricsBaseUrl })
  } catch {
    return null
  }
}

export async function purgeCache(body: { all?: boolean; url?: string; method?: string }): Promise<void> {
  const settings = loadApiSettings()
  await apiFetch('/api/cache/purge', {
    baseUrl: settings.metricsBaseUrl,
    method: 'POST',
    body,
  })
}

export async function fetchDashboardMetrics(): Promise<DashboardMetric[]> {
  const stats = await fetchProxyStats()
  if (stats) {
    return [
      {
        id: 'hit-rate',
        label: 'Cache hit rate',
        value: (stats.cache.hit_ratio * 100).toFixed(1),
        unit: '%',
        status: 'ok',
      },
      { id: 'hits', label: 'Cache hits', value: stats.cache.hits, status: 'ok' },
      { id: 'misses', label: 'Cache misses', value: stats.cache.misses, status: 'ok' },
      {
        id: 'entries',
        label: 'L1 entries',
        value: `${stats.cache.entries}/${stats.cache.capacity}`,
        status: 'ok',
      },
      {
        id: 'inflight',
        label: 'In flight',
        value: stats.requests_in_flight,
        status: 'ok',
      },
      {
        id: 'uptime',
        label: 'Uptime',
        value: formatUptime(stats.uptime_secs),
        status: 'ok',
      },
    ]
  }
  return mockMetrics()
}

export async function fetchTopMlScores(): Promise<MlScoreRow[]> {
  const snap = await fetchThreatScores()
  return snap.scores
    .slice()
    .sort((a, b) => b.score - a.score)
    .slice(0, 10)
    .map((s) => ({
      entity_id: s.entity_id,
      entity_type: s.entity_type,
      score: s.score,
      severity: s.severity,
      model: s.model,
      scored_at: s.scored_at,
    }))
}

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`
  if (secs < 3600) return `${Math.floor(secs / 60)}m`
  return `${(secs / 3600).toFixed(1)}h`
}

function mockMetrics(): DashboardMetric[] {
  return [
    { id: 'hit-rate', label: 'Cache hit rate', value: '87.2', unit: '%', trend: 'up', status: 'ok' },
    { id: 'hits', label: 'Cache hits', value: 11240, trend: 'up', status: 'ok' },
    { id: 'misses', label: 'Cache misses', value: 1640, trend: 'flat', status: 'ok' },
    { id: 'entries', label: 'L1 entries', value: '3200/10000', status: 'ok' },
  ]
}
