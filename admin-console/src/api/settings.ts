/** Runtime API endpoint configuration (localStorage). */

export type ApiConnectionMode = 'single' | 'advanced'

export interface ApiSettings {
  connectionMode: ApiConnectionMode
  controlPlaneBaseUrl: string
  controlPlaneToken: string
  searchBaseUrl: string
  aclBaseUrl: string
  mlBaseUrl: string
  metricsBaseUrl: string
  searchToken: string
  aclToken: string
  controlToken: string
}

export interface ResolvedApiSettings {
  searchBaseUrl: string
  aclBaseUrl: string
  mlBaseUrl: string
  metricsBaseUrl: string
  searchToken: string
  aclToken: string
  mlToken: string
  controlToken: string
}

const STORAGE_KEY = 'bsdm-admin-api-settings'

const defaults: ApiSettings = {
  connectionMode: 'single',
  controlPlaneBaseUrl: '',
  controlPlaneToken: '',
  searchBaseUrl: '',
  aclBaseUrl: '',
  mlBaseUrl: '',
  metricsBaseUrl: '',
  searchToken: '',
  aclToken: '',
  controlToken: '',
}

type SensitiveApiKey = 'controlPlaneToken' | 'searchToken' | 'aclToken' | 'controlToken'

let runtimeTokens: Pick<ApiSettings, SensitiveApiKey> = {
  controlPlaneToken: '',
  searchToken: '',
  aclToken: '',
  controlToken: '',
}

export function loadApiSettings(): ApiSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...defaults, ...runtimeTokens }
    const parsed = JSON.parse(raw) as Partial<ApiSettings>
    const legacyHasSplitConfiguration = [
      parsed.searchBaseUrl,
      parsed.aclBaseUrl,
      parsed.mlBaseUrl,
      parsed.metricsBaseUrl,
    ].some((value) => Boolean(value?.trim()))
    return {
      ...defaults,
      ...parsed,
      connectionMode: parsed.connectionMode ?? (legacyHasSplitConfiguration ? 'advanced' : 'single'),
      ...runtimeTokens,
    }
  } catch {
    return { ...defaults, ...runtimeTokens }
  }
}

const SENSITIVE_API_KEYS = [
  'controlPlaneToken',
  'searchToken',
  'aclToken',
  'controlToken',
] as const satisfies readonly SensitiveApiKey[]

function apiSettingsForStorage(settings: ApiSettings): Omit<ApiSettings, (typeof SENSITIVE_API_KEYS)[number]> {
  const stored = { ...settings }
  for (const key of SENSITIVE_API_KEYS) {
    delete (stored as Partial<ApiSettings>)[key]
  }
  return stored as Omit<ApiSettings, (typeof SENSITIVE_API_KEYS)[number]>
}

export function saveApiSettings(settings: ApiSettings): void {
  runtimeTokens = {
    controlPlaneToken: settings.controlPlaneToken,
    searchToken: settings.searchToken,
    aclToken: settings.aclToken,
    controlToken: settings.controlToken,
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(apiSettingsForStorage(settings)))
}

/**
 * Resolve the operator-facing connection model into the service-specific
 * endpoints consumed by API clients.
 *
 * In single-endpoint mode the deployment gateway must expose all `/api/*`
 * routes and `/metrics` on one origin. Empty URLs keep using same-origin paths
 * (including Vite's development proxies).
 */
export function resolveApiSettings(settings: ApiSettings = loadApiSettings()): ResolvedApiSettings {
  if (settings.connectionMode === 'single') {
    const baseUrl = resolveBaseUrl(settings.controlPlaneBaseUrl)
    const token = settings.controlPlaneToken
    return {
      searchBaseUrl: baseUrl,
      aclBaseUrl: baseUrl,
      mlBaseUrl: baseUrl,
      metricsBaseUrl: baseUrl,
      searchToken: token,
      aclToken: token,
      mlToken: token,
      controlToken: token,
    }
  }

  return {
    searchBaseUrl: resolveBaseUrl(settings.searchBaseUrl),
    aclBaseUrl: resolveBaseUrl(settings.aclBaseUrl),
    mlBaseUrl: resolveBaseUrl(settings.mlBaseUrl),
    metricsBaseUrl: resolveBaseUrl(settings.metricsBaseUrl),
    searchToken: settings.searchToken,
    aclToken: settings.aclToken,
    mlToken: '',
    controlToken: settings.controlToken,
  }
}

export function resolveBaseUrl(configured: string, fallback = ''): string {
  return configured.trim() || fallback
}
