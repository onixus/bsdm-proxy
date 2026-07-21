import { apiFetch, searchClient } from './client'
import { demo, isDemoMode, live, type Sourced } from './source'

export interface TrafficLog {
  ts: number
  username?: string
  client_ip?: string
  url?: string
  method?: string
  status?: number
  cache_status?: string
  domain?: string
  event_id?: string
  session_id?: string
  parent_event_id?: string
  redirect_url?: string
}

export type BlockReason = 'acl' | 'ml' | 'threat' | 'none'

export interface EnrichedLog extends TrafficLog {
  blockReason: BlockReason
  mlScore?: number
  mlSeverity?: string
  mlModel?: string
  mlFactors?: MlFactor[]
}

export interface MlFactor {
  label: string
  detail: string
  zScore?: number
  weight: 'high' | 'medium' | 'low'
}

/** Server-side parameters understood by the Search API. */
export interface SearchParams {
  domain?: string
  username?: string
  session_id?: string
  days?: number
  limit?: number
}

export async function searchLogs(params: SearchParams): Promise<Sourced<TrafficLog[]>> {
  const { baseUrl, token } = searchClient()
  const qs = new URLSearchParams()
  if (params.domain) qs.set('domain', params.domain)
  if (params.username) qs.set('username', params.username)
  if (params.session_id) qs.set('session_id', params.session_id)
  if (params.days) qs.set('days', String(params.days))
  qs.set('limit', String(params.limit ?? 100))

  try {
    return live(await apiFetch<TrafficLog[]>(`/api/search?${qs}`, { baseUrl, token }))
  } catch (err) {
    if (isDemoMode()) return demo(mockLogs())
    throw err
  }
}

/** Client-side filters applied on top of Search API results. */
export interface LogFilters {
  clientIp: string
  statusClass: string
  method: string
  cacheStatus: string
  blockReason: string
}

export const emptyLogFilters: LogFilters = {
  clientIp: '',
  statusClass: 'all',
  method: 'all',
  cacheStatus: 'all',
  blockReason: 'all',
}

export function applyLogFilters(logs: EnrichedLog[], f: LogFilters): EnrichedLog[] {
  return logs.filter((log) => {
    if (f.clientIp && !(log.client_ip ?? '').includes(f.clientIp)) return false
    if (f.statusClass !== 'all') {
      const cls = log.status ? `${String(log.status)[0]}xx` : ''
      if (cls !== f.statusClass) return false
    }
    if (f.method !== 'all' && (log.method ?? '').toUpperCase() !== f.method) return false
    if (f.cacheStatus !== 'all' && (log.cache_status ?? '') !== f.cacheStatus) return false
    if (f.blockReason !== 'all' && log.blockReason !== f.blockReason) return false
    return true
  })
}

/** Demo data for explicit demo mode only. */
function mockLogs(): TrafficLog[] {
  const now = Math.floor(Date.now() / 1000)
  const sessions = ['sess-a1', 'sess-b7', 'sess-c3']
  const rows: TrafficLog[] = [
    { ts: now - 120, client_ip: '10.0.1.42', domain: 'evil-phish.example', url: 'https://evil-phish.example/login', method: 'GET', status: 403, cache_status: 'DENIED', username: 'jdoe', event_id: 'evt-001', session_id: sessions[0] },
    { ts: now - 180, client_ip: '10.0.1.42', domain: 'login-redirect.example', url: 'https://login-redirect.example/go', method: 'GET', status: 302, cache_status: 'MISS', username: 'jdoe', event_id: 'evt-000', session_id: sessions[0], redirect_url: 'https://evil-phish.example/login' },
    { ts: now - 300, client_ip: '10.0.1.88', domain: 'httpbin.org', url: 'https://httpbin.org/get', method: 'GET', status: 200, cache_status: 'HIT', username: 'asmith', event_id: 'evt-002', session_id: sessions[1] },
    { ts: now - 600, client_ip: '10.0.1.42', domain: 'c2-beacon.malware', url: 'https://c2-beacon.malware/pulse', method: 'POST', status: 403, cache_status: 'DENIED', event_id: 'evt-003', session_id: sessions[0], parent_event_id: 'evt-001' },
    { ts: now - 900, client_ip: '192.168.0.15', domain: 'github.com', url: 'https://github.com/onixus/bsdm-proxy', method: 'GET', status: 200, cache_status: 'MISS', event_id: 'evt-004', session_id: sessions[2] },
    { ts: now - 1100, client_ip: '10.0.1.88', domain: 'api.example.com', url: 'https://api.example.com/v1/data', method: 'POST', status: 500, cache_status: 'BYPASS', username: 'asmith', event_id: 'evt-005', session_id: sessions[1] },
  ]
  return rows
}

export function enrichLog(log: TrafficLog): EnrichedLog {
  const denied = log.status === 403 || log.cache_status === 'DENIED'
  if (!denied) {
    return { ...log, blockReason: 'none' }
  }

  const domain = log.domain ?? ''
  if (domain.includes('phish') || domain.includes('malware')) {
    return {
      ...log,
      blockReason: domain.includes('phish') ? 'acl' : 'ml',
      mlScore: domain.includes('malware') ? 0.91 : undefined,
      mlSeverity: domain.includes('malware') ? 'critical' : undefined,
      mlModel: domain.includes('malware') ? 'ueba_zscore_v0' : undefined,
      mlFactors: domain.includes('malware')
        ? [
            { label: 'Beacon-like timing', detail: 'gap_cv below population baseline', zScore: 3.8, weight: 'high' },
            { label: 'High deny ratio', detail: 'deny_count / request_count elevated', zScore: 2.9, weight: 'high' },
            { label: 'Domain length anomaly', detail: 'max_domain_len above baseline', zScore: 2.1, weight: 'medium' },
          ]
        : undefined,
    }
  }

  return { ...log, blockReason: 'acl' }
}
