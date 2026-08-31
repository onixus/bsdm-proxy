import { loadApiSettings, resolveApiSettings } from './settings'

export interface SoarInvestigateResponse {
  query: string
  normalized: string
  kind: 'domain' | 'url' | 'ip'
  found: boolean
  indicator?: {
    raw: string
    normalized: string
    kind: string
    source: string
    confidence_score: number
    first_seen_unix: number
    last_seen_unix: number
    expires_at_unix: number
    hit_count: number
    tags: string[]
    description?: string
  }
}

export interface SoarBlockRequest {
  indicator: string
  kind: 'domain' | 'url' | 'ip'
  reason: string
  ttl_secs?: number
  operator?: string
  confidence_score?: number
}

export interface SoarBlockResponse {
  success: boolean
  indicator: string
  enforced: boolean
  mode: string
  expires_at_unix: number
  confidence_score: number
  message: string
}

export interface SoarUnblockRequest {
  indicator: string
  reason: string
  operator?: string
}

export interface SoarUnblockResponse {
  success: boolean
  indicator: string
  purged_count: number
  message: string
}

export interface DomainReputationScore {
  domain: string
  normalized_domain: string
  has_homoglyphs: boolean
  is_suspicious: boolean
  risk_score: number
  target_brand?: string
  damerau_distance?: number
  reasons: string[]
}

export interface DomainAnomalyReport {
  domain: string
  shannon_entropy: number
  subdomain_depth: number
  digit_count: number
  hyphen_count: number
  is_anomalous: boolean
  reasons: string[]
}

export interface CampaignCluster {
  target_brand: string
  domains: string[]
  cluster_size: number
}

export interface RpzStatusReport {
  zone_path: string
  exists: boolean
  file_size_bytes: number
  modified_at?: string
  soa_serial?: number
  domain_count: number
  is_shadow: boolean
  has_backup: boolean
  backup_soa_serial?: number
}

function getClientConfig() {
  const settings = loadApiSettings()
  const resolved = resolveApiSettings(settings)
  const baseUrl = resolved.threatIntelBaseUrl.replace(/\/+$/, '')
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (resolved.threatIntelToken) {
    headers['Authorization'] = `Bearer ${resolved.threatIntelToken}`
  }
  return { baseUrl, headers }
}

export async function investigateIndicator(query: string): Promise<SoarInvestigateResponse> {
  const { baseUrl, headers } = getClientConfig()
  const res = await fetch(`${baseUrl}/api/v1/soar/investigate?query=${encodeURIComponent(query)}`, {
    headers,
  })
  if (!res.ok) {
    throw new Error(`Investigation failed: HTTP ${res.status} ${res.statusText}`)
  }
  return res.json()
}

export async function blockIndicator(req: SoarBlockRequest): Promise<SoarBlockResponse> {
  const { baseUrl, headers } = getClientConfig()
  const res = await fetch(`${baseUrl}/api/v1/soar/block`, {
    method: 'POST',
    headers,
    body: JSON.stringify(req),
  })
  if (!res.ok && res.status !== 202) {
    const text = await res.text()
    throw new Error(`Block action failed (${res.status}): ${text}`)
  }
  return res.json()
}

export async function unblockIndicator(req: SoarUnblockRequest): Promise<SoarUnblockResponse> {
  const { baseUrl, headers } = getClientConfig()
  const res = await fetch(`${baseUrl}/api/v1/soar/unblock`, {
    method: 'POST',
    headers,
    body: JSON.stringify(req),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Unblock action failed (${res.status}): ${text}`)
  }
  return res.json()
}

export async function fetchDomainReputation(domain: string): Promise<DomainReputationScore> {
  const { baseUrl, headers } = getClientConfig()
  const res = await fetch(`${baseUrl}/api/v1/ml/reputation?domain=${encodeURIComponent(domain)}`, {
    headers,
  })
  if (!res.ok) {
    throw new Error(`ML reputation lookup failed: HTTP ${res.status}`)
  }
  return res.json()
}

export async function fetchDomainAnomaly(domain: string): Promise<DomainAnomalyReport> {
  const { baseUrl, headers } = getClientConfig()
  const res = await fetch(`${baseUrl}/api/v1/ml/anomaly?domain=${encodeURIComponent(domain)}`, {
    headers,
  })
  if (!res.ok) {
    throw new Error(`ML anomaly lookup failed: HTTP ${res.status}`)
  }
  return res.json()
}

export async function clusterCampaigns(domains: string[]): Promise<CampaignCluster[]> {
  const { baseUrl, headers } = getClientConfig()
  const res = await fetch(`${baseUrl}/api/v1/ml/cluster`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ domains }),
  })
  if (!res.ok) {
    throw new Error(`Campaign clustering failed: HTTP ${res.status}`)
  }
  return res.json()
}

export async function fetchRpzStatus(): Promise<RpzStatusReport> {
  const { baseUrl, headers } = getClientConfig()
  const res = await fetch(`${baseUrl}/api/v1/rpz/status`, {
    headers,
  })
  if (!res.ok) {
    throw new Error(`RPZ status fetch failed: HTTP ${res.status}`)
  }
  return res.json()
}

export async function rollbackRpzZone(): Promise<{ rolled_back: boolean; status: RpzStatusReport }> {
  const { baseUrl, headers } = getClientConfig()
  const res = await fetch(`${baseUrl}/api/v1/rpz/rollback`, {
    method: 'POST',
    headers,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`RPZ rollback failed (${res.status}): ${text}`)
  }
  return res.json()
}
