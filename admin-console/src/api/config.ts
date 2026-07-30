import { apiFetch, controlClient } from './client'
import { isDemoMode } from './source'

export interface ConfigSnapshot {
  env_path: string
  env: Record<string, string>
}

export interface ConfigApplyPayload {
  env: Record<string, string>
  acl_rules?: Record<string, unknown> | null
  restart?: boolean
}

export interface ConfigApplyResult {
  status: string
  env_path: string
  hot_reload: string[]
  restart: 'scheduled' | 'skipped' | 'unavailable'
  message: string
}

export async function fetchNodeConfig(): Promise<ConfigSnapshot> {
  if (isDemoMode()) {
    return {
      env_path: '/etc/bsdm-proxy/bsdm-proxy.env',
      env: { HTTP_PORT: '3128', METRICS_PORT: '9090' },
    }
  }
  const { baseUrl, token } = controlClient()
  return apiFetch<ConfigSnapshot>('/api/config', { baseUrl, token })
}

export async function applyNodeConfig(payload: ConfigApplyPayload): Promise<ConfigApplyResult> {
  if (isDemoMode()) {
    return {
      status: 'applied',
      env_path: '/etc/bsdm-proxy/bsdm-proxy.env',
      hot_reload: ['acl:4', 'upstream_tls'],
      restart: 'scheduled',
      message: 'Demo: configuration would be applied and proxy restarted.',
    }
  }
  const { baseUrl, token } = controlClient()
  return apiFetch<ConfigApplyResult>('/api/config/apply', {
    baseUrl,
    token,
    method: 'POST',
    body: payload,
  })
}
