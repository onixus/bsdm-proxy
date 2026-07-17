import { loadApiSettings } from './settings'
import { apiFetch } from './client'

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

/** Parse Prometheus text exposition for a single metric sample (best-effort). */
function parsePrometheusValue(text: string, name: string): number | null {
  const re = new RegExp(`^${name}(?:\\{[^}]*\\})?\\s+([\\d.eE+-]+)`, 'm')
  const m = text.match(re)
  return m ? parseFloat(m[1]) : null
}

export async function fetchDashboardMetrics(): Promise<DashboardMetric[]> {
  const settings = loadApiSettings()
  const base = settings.metricsBaseUrl

  try {
    const text = await apiFetch<string>('/metrics', { baseUrl: base })
    if (typeof text !== 'string') throw new Error('not text')
    const requests = parsePrometheusValue(text, 'bsdm_proxy_requests_total') ?? 0
    const hits = parsePrometheusValue(text, 'bsdm_proxy_cache_hits_total') ?? 0
    const misses = parsePrometheusValue(text, 'bsdm_proxy_cache_misses_total') ?? 0
    const hitRate = requests > 0 ? ((hits / (hits + misses || 1)) * 100).toFixed(1) : '—'
    return [
      { id: 'requests', label: 'Total requests', value: requests, status: 'ok' },
      { id: 'hit-rate', label: 'Cache hit rate', value: hitRate, unit: '%', status: 'ok' },
      { id: 'hits', label: 'Cache hits', value: hits, status: 'ok' },
      { id: 'misses', label: 'Cache misses', value: misses, status: 'ok' },
    ]
  } catch {
    return mockMetrics()
  }
}

export async function fetchTopMlScores(): Promise<MlScoreRow[]> {
  const settings = loadApiSettings()
  try {
    return await apiFetch<MlScoreRow[]>('/api/ml/scores?limit=10', {
      baseUrl: settings.mlBaseUrl,
    })
  } catch {
    return mockMlScores()
  }
}

function mockMetrics(): DashboardMetric[] {
  return [
    { id: 'requests', label: 'Total requests', value: '128.4k', trend: 'up', status: 'ok' },
    { id: 'hit-rate', label: 'Cache hit rate', value: '87.2', unit: '%', trend: 'up', status: 'ok' },
    { id: 'denied', label: 'Denied (24h)', value: 342, trend: 'flat', status: 'warn' },
    { id: 'ml-alerts', label: 'ML anomalies', value: 7, trend: 'down', status: 'warn' },
  ]
}

function mockMlScores(): MlScoreRow[] {
  return [
    { entity_id: '10.0.1.42', entity_type: 'client_ip', score: 0.91, severity: 'critical', model: 'ueba_zscore_v0', scored_at: new Date().toISOString() },
    { entity_id: '10.0.1.88', entity_type: 'client_ip', score: 0.72, severity: 'high', model: 'ueba_zscore_v0', scored_at: new Date().toISOString() },
    { entity_id: 'jdoe', entity_type: 'username', score: 0.55, severity: 'medium', model: 'anomaly_stub_v0', scored_at: new Date().toISOString() },
  ]
}
