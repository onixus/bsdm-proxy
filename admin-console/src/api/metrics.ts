import { loadApiSettings } from './settings'
import { apiFetch } from './client'
import { demo, live, isDemoMode, type Sourced } from './source'
import { groupByLabel, histogram, histogramQuantile, scrapeMetrics, sumMetric, type PromSample } from './prometheus'
import { recordCounter, recordGauge, series, type TsPoint } from '../lib/timeseries'

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

export interface LatencyQuantiles {
  p50: number
  p95: number
  p99: number
}

/** Everything the monitoring dashboard needs from one poll cycle. */
export interface Telemetry {
  stats: ProxyStats | null
  /** Trailing-window series accumulated across polls (per-second rates / gauges). */
  reqRate: TsPoint[]
  errRate: TsPoint[]
  denyRate: TsPoint[]
  hitRatio: TsPoint[]
  inFlight: TsPoint[]
  latP95: TsPoint[]
  /** Request latency quantiles in seconds (from the Prometheus histogram). */
  latency: LatencyQuantiles | null
  /** Cumulative request counts grouped by HTTP status class ("2xx"…). */
  statusClasses: Record<string, number>
  /** Cumulative request counts grouped by cache disposition (HIT/MISS/…). */
  cacheStatus: Record<string, number>
  /** Cumulative ACL decisions by action. */
  aclDecisions: Record<string, number>
  /** Top upstream hosts by cumulative request count. */
  topUpstreams: { host: string; requests: number; errors: number }[]
  totalRequests: number
  cacheEvictions: number
  rateLimitRejected: number
  tlsHandshakeFailures: number
}

export async function fetchProxyStats(): Promise<ProxyStats | null> {
  const settings = loadApiSettings()
  try {
    return await apiFetch<ProxyStats>('/api/stats', { baseUrl: settings.metricsBaseUrl })
  } catch {
    return null
  }
}

export async function purgeCache(body: {
  all?: boolean
  url?: string
  method?: string
  tag?: string
  tags?: string[]
}): Promise<void> {
  const settings = loadApiSettings()
  await apiFetch('/api/cache/purge', {
    baseUrl: settings.metricsBaseUrl,
    method: 'POST',
    body,
  })
}

const WINDOW_MS = 30 * 60_000

/**
 * One dashboard poll: /api/stats + /metrics scrape, recorded into the
 * in-memory time-series store so charts build up history across refreshes.
 */
export async function fetchTelemetry(): Promise<Sourced<Telemetry>> {
  try {
    const settings = loadApiSettings()
    const [stats, snap] = await Promise.all([
      apiFetch<ProxyStats>('/api/stats', { baseUrl: settings.metricsBaseUrl }),
      scrapeMetrics().catch(() => null),
    ])

    const t = Date.now()
    recordGauge('cache.hitRatio', stats.cache.hit_ratio * 100, t)
    recordGauge('inflight', stats.requests_in_flight, t)
    recordCounter('cache.hits', stats.cache.hits, t)

    let latency: LatencyQuantiles | null = null
    let statusClasses: Record<string, number> = {}
    let cacheStatus: Record<string, number> = {}
    let aclDecisions: Record<string, number> = {}
    let topUpstreams: Telemetry['topUpstreams'] = []
    let totalRequests = stats.cache.hits + stats.cache.misses + stats.cache.bypasses
    let cacheEvictions = 0
    let rateLimitRejected = 0
    let tlsHandshakeFailures = 0

    if (snap) {
      const s = snap.samples
      totalRequests = sumMetric(s, 'bsdm_proxy_requests_total')
      recordCounter('req.rate', totalRequests, t)
      recordCounter(
        'req.err.rate',
        sumMetric(s, 'bsdm_proxy_requests_total', (l) => l.status?.startsWith('5') ?? false),
        t,
      )
      recordCounter(
        'acl.deny.rate',
        sumMetric(s, 'bsdm_proxy_acl_decisions_total', (l) => l.action !== 'allow'),
        t,
      )

      const h = histogram(s, 'bsdm_proxy_request_duration_seconds')
      if (h && h.count > 0) {
        latency = {
          p50: histogramQuantile(h, 0.5) ?? 0,
          p95: histogramQuantile(h, 0.95) ?? 0,
          p99: histogramQuantile(h, 0.99) ?? 0,
        }
        recordGauge('lat.p95', latency.p95 * 1000, t)
      }

      statusClasses = groupByStatusClass(s)
      cacheStatus = Object.fromEntries(groupByLabel(s, 'bsdm_proxy_requests_total', 'cache_status'))
      aclDecisions = Object.fromEntries(groupByLabel(s, 'bsdm_proxy_acl_decisions_total', 'action'))
      topUpstreams = upstreamTable(s)
      cacheEvictions = sumMetric(s, 'bsdm_proxy_cache_evictions_total')
      rateLimitRejected = sumMetric(s, 'bsdm_proxy_rate_limit_rejected_total')
      tlsHandshakeFailures = sumMetric(s, 'bsdm_proxy_tls_handshakes_total', (l) => l.status !== 'success')
    } else {
      // /metrics unreachable — still derive a request rate from cache counters.
      recordCounter('req.rate', totalRequests, t)
    }

    return live<Telemetry>({
      stats,
      reqRate: series('req.rate', WINDOW_MS),
      errRate: series('req.err.rate', WINDOW_MS),
      denyRate: series('acl.deny.rate', WINDOW_MS),
      hitRatio: series('cache.hitRatio', WINDOW_MS),
      inFlight: series('inflight', WINDOW_MS),
      latP95: series('lat.p95', WINDOW_MS),
      latency,
      statusClasses,
      cacheStatus,
      aclDecisions,
      topUpstreams,
      totalRequests,
      cacheEvictions,
      rateLimitRejected,
      tlsHandshakeFailures,
    })
  } catch (err) {
    if (isDemoMode()) return demo(demoTelemetry())
    throw err
  }
}

function groupByStatusClass(samples: PromSample[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const s of samples) {
    if (s.name !== 'bsdm_proxy_requests_total') continue
    const status = s.labels.status ?? ''
    const key = status ? `${status[0]}xx` : '(none)'
    out[key] = (out[key] ?? 0) + s.value
  }
  return out
}

function upstreamTable(samples: PromSample[]): Telemetry['topUpstreams'] {
  const requests = groupByLabel(samples, 'bsdm_proxy_upstream_requests_total', 'host')
  const errors = groupByLabel(samples, 'bsdm_proxy_upstream_errors_total', 'host')
  return [...requests.entries()]
    .map(([host, reqs]) => ({ host, requests: reqs, errors: errors.get(host) ?? 0 }))
    .sort((a, b) => b.requests - a.requests)
    .slice(0, 8)
}

/** Synthetic telemetry for explicit demo mode only. */
function demoTelemetry(): Telemetry {
  const now = Date.now()
  const mk = (base: number, jitter: number, n = 60): TsPoint[] =>
    Array.from({ length: n }, (_, i) => ({
      t: now - (n - 1 - i) * 10_000,
      v: Math.max(0, base + Math.sin(i / 6) * jitter + (Math.random() - 0.5) * jitter),
    }))
  return {
    stats: {
      service: 'bsdm-proxy (demo)',
      uptime_secs: 86_400 * 3 + 4_520,
      requests_in_flight: 12,
      cache: { hits: 112_400, misses: 16_400, bypasses: 2_100, hit_ratio: 0.872, entries: 8_204, capacity: 10_000, shards: 16 },
    },
    reqRate: mk(420, 60),
    errRate: mk(3, 2),
    denyRate: mk(8, 4),
    hitRatio: mk(87, 3),
    inFlight: mk(12, 6),
    latP95: mk(38, 10),
    latency: { p50: 0.006, p95: 0.038, p99: 0.121 },
    statusClasses: { '2xx': 118_204, '3xx': 6_120, '4xx': 4_890, '5xx': 386 },
    cacheStatus: { HIT: 112_400, MISS: 16_400, BYPASS: 2_100, DENIED: 3_400 },
    aclDecisions: { allow: 126_300, deny: 3_400 },
    topUpstreams: [
      { host: 'cdn.example.com', requests: 48_200, errors: 12 },
      { host: 'api.example.com', requests: 22_100, errors: 96 },
      { host: 'static.example.org', requests: 9_450, errors: 0 },
    ],
    totalRequests: 130_900,
    cacheEvictions: 1_240,
    rateLimitRejected: 86,
    tlsHandshakeFailures: 14,
  }
}

export function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`
  if (secs < 3600) return `${Math.floor(secs / 60)}m`
  if (secs < 86_400) return `${(secs / 3600).toFixed(1)}h`
  return `${Math.floor(secs / 86_400)}d ${Math.floor((secs % 86_400) / 3600)}h`
}
