/** Runtime API endpoint configuration (localStorage). */

export type ApiConnectionMode = 'single' | 'advanced'

export interface ApiSettings {
  connectionMode: ApiConnectionMode
  controlPlaneBaseUrl: string
  controlPlaneToken: string
  searchBaseUrl: string
  aclBaseUrl: string
  mlBaseUrl: string
  threatIntelBaseUrl: string
  metricsBaseUrl: string
  searchToken: string
  aclToken: string
  threatIntelToken: string
  controlToken: string
}

export interface ResolvedApiSettings {
  searchBaseUrl: string
  aclBaseUrl: string
  mlBaseUrl: string
  threatIntelBaseUrl: string
  metricsBaseUrl: string
  searchToken: string
  aclToken: string
  threatIntelToken: string
  mlToken: string
  controlToken: string
}

const STORAGE_KEY = 'bsdm-admin-api-settings'

declare global {
  interface Window {
    __BSDM_CONSOLE_API__?: Partial<ApiSettings>
  }
}

function bootstrapFromWindow(): Partial<ApiSettings> {
  try {
    return window.__BSDM_CONSOLE_API__ ?? {}
  } catch {
    return {}
  }
}

export const API_CREDENTIALS_CHANGED_EVENT = 'bsdm-api-credentials-changed'

const defaults: ApiSettings = {
  connectionMode: 'single',
  controlPlaneBaseUrl: '',
  controlPlaneToken: '',
  searchBaseUrl: '',
  aclBaseUrl: '',
  mlBaseUrl: '',
  threatIntelBaseUrl: '',
  metricsBaseUrl: '',
  searchToken: '',
  aclToken: '',
  threatIntelToken: '',
  controlToken: '',
}

type SensitiveApiKey = 'controlPlaneToken' | 'searchToken' | 'aclToken' | 'threatIntelToken' | 'controlToken'

let runtimeTokens: Pick<ApiSettings, SensitiveApiKey> = {
  controlPlaneToken: '',
  searchToken: '',
  aclToken: '',
  threatIntelToken: '',
  controlToken: '',
}

function filledTokens(source: Partial<ApiSettings>): Partial<ApiSettings> {
  const out: Partial<ApiSettings> = {}
  for (const key of ['controlPlaneToken', 'searchToken', 'aclToken', 'threatIntelToken', 'controlToken'] as const) {
    const value = source[key]
    if (typeof value === 'string' && value.trim()) {
      out[key] = value
    }
  }
  return out
}

export function loadApiSettings(): ApiSettings {
  const boot = filledTokens(bootstrapFromWindow())
  const session = filledTokens(runtimeTokens)
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...defaults, ...boot, ...session }
    const parsed = JSON.parse(raw) as Partial<ApiSettings>
    const legacyHasSplitConfiguration = [
      parsed.searchBaseUrl,
      parsed.aclBaseUrl,
      parsed.mlBaseUrl,
      parsed.threatIntelBaseUrl,
      parsed.metricsBaseUrl,
    ].some((value) => Boolean(value?.trim()))
    return {
      ...defaults,
      ...parsed,
      connectionMode: parsed.connectionMode ?? (legacyHasSplitConfiguration ? 'advanced' : 'single'),
      ...boot,
      ...session,
    }
  } catch {
    return { ...defaults, ...boot, ...session }
  }
}

const SENSITIVE_API_KEYS = [
  'controlPlaneToken',
  'searchToken',
  'aclToken',
  'threatIntelToken',
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
    threatIntelToken: settings.threatIntelToken,
    controlToken: settings.controlToken,
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(apiSettingsForStorage(settings)))
  window.dispatchEvent(new CustomEvent(API_CREDENTIALS_CHANGED_EVENT))
}

export function hasApiCredentials(settings: ApiSettings = loadApiSettings()): boolean {
  const resolved = resolveApiSettings(settings)
  return [resolved.searchToken, resolved.aclToken, resolved.threatIntelToken, resolved.mlToken, resolved.controlToken]
    .some((token) => token.trim().length > 0)
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
      threatIntelBaseUrl: baseUrl,
      metricsBaseUrl: baseUrl,
      searchToken: token,
      aclToken: token,
      threatIntelToken: token,
      mlToken: token,
      controlToken: token,
    }
  }

  return {
    searchBaseUrl: resolveBaseUrl(settings.searchBaseUrl),
    aclBaseUrl: resolveBaseUrl(settings.aclBaseUrl),
    mlBaseUrl: resolveBaseUrl(settings.mlBaseUrl),
    threatIntelBaseUrl: resolveBaseUrl(settings.threatIntelBaseUrl),
    metricsBaseUrl: resolveBaseUrl(settings.metricsBaseUrl),
    searchToken: settings.searchToken,
    aclToken: settings.aclToken,
    threatIntelToken: settings.threatIntelToken,
    mlToken: '',
    controlToken: settings.controlToken,
  }
}

export function resolveBaseUrl(configured: string, fallback = ''): string {
  return configured.trim() || fallback
}
