/** Runtime API endpoint configuration (localStorage). */

export interface ApiSettings {
  searchBaseUrl: string
  aclBaseUrl: string
  mlBaseUrl: string
  metricsBaseUrl: string
  searchToken: string
  aclToken: string
}

const STORAGE_KEY = 'bsdm-admin-api-settings'

const defaults: ApiSettings = {
  searchBaseUrl: '',
  aclBaseUrl: '',
  mlBaseUrl: '',
  metricsBaseUrl: '',
  searchToken: '',
  aclToken: '',
}

export function loadApiSettings(): ApiSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...defaults }
    return { ...defaults, ...JSON.parse(raw) }
  } catch {
    return { ...defaults }
  }
}

const SENSITIVE_API_KEYS = ['searchToken', 'aclToken'] as const satisfies readonly (keyof ApiSettings)[]

function apiSettingsForStorage(settings: ApiSettings): Omit<ApiSettings, (typeof SENSITIVE_API_KEYS)[number]> {
  const stored = { ...settings }
  for (const key of SENSITIVE_API_KEYS) {
    delete (stored as Partial<ApiSettings>)[key]
  }
  return stored as Omit<ApiSettings, (typeof SENSITIVE_API_KEYS)[number]>
}

export function saveApiSettings(settings: ApiSettings): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(apiSettingsForStorage(settings)))
}

export function resolveBaseUrl(configured: string, fallback = ''): string {
  return configured.trim() || fallback
}
