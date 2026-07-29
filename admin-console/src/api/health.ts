import { ApiError, apiFetch } from './client'
import { resolveApiSettings, type ApiSettings } from './settings'

export type ApiServiceId = 'control' | 'acl' | 'search' | 'ml'
export type ApiHealthStatus = 'healthy' | 'unauthorized' | 'unreachable'

export interface ApiHealthResult {
  id: ApiServiceId
  name: string
  endpoint: string
  status: ApiHealthStatus
  detail: string
}

interface Probe {
  id: ApiServiceId
  name: string
  path: string
  baseUrl: string
  token: string
}

const HEALTH_TIMEOUT_MS = 5_000

/** Read-only probes for every service consumed by Admin Console. */
export async function checkApiHealth(settings: ApiSettings): Promise<ApiHealthResult[]> {
  const resolved = resolveApiSettings(settings)
  const probes: Probe[] = [
    {
      id: 'control',
      name: 'Control / Metrics',
      path: '/api/stats',
      baseUrl: resolved.metricsBaseUrl,
      token: resolved.controlToken,
    },
    {
      id: 'acl',
      name: 'ACL',
      path: '/api/acl/rules',
      baseUrl: resolved.aclBaseUrl,
      token: resolved.aclToken,
    },
    {
      id: 'search',
      name: 'Search',
      path: '/api/search?limit=1',
      baseUrl: resolved.searchBaseUrl,
      token: resolved.searchToken,
    },
    {
      id: 'ml',
      name: 'ML worker',
      path: '/api/threat-scores',
      baseUrl: resolved.mlBaseUrl,
      token: resolved.mlToken,
    },
  ]

  return Promise.all(probes.map(runProbe))
}

async function runProbe(probe: Probe): Promise<ApiHealthResult> {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS)
  const endpoint = `${probe.baseUrl || window.location.origin}${probe.path}`

  try {
    await apiFetch<unknown>(probe.path, {
      baseUrl: probe.baseUrl,
      token: probe.token,
      signal: controller.signal,
    })
    return {
      id: probe.id,
      name: probe.name,
      endpoint,
      status: 'healthy',
      detail: 'Connected',
    }
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
      return {
        id: probe.id,
        name: probe.name,
        endpoint,
        status: 'unauthorized',
        detail: `HTTP ${error.status} — credentials rejected`,
      }
    }

    const detail =
      error instanceof ApiError
        ? `HTTP ${error.status}`
        : error instanceof DOMException && error.name === 'AbortError'
          ? `Timed out after ${HEALTH_TIMEOUT_MS / 1000}s`
          : error instanceof Error
            ? error.message
            : 'Connection failed'

    return {
      id: probe.id,
      name: probe.name,
      endpoint,
      status: 'unreachable',
      detail,
    }
  } finally {
    window.clearTimeout(timeout)
  }
}
