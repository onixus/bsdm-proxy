import { resolveApiSettings } from './settings'
import { mutationRequiresCredentials } from './mutationGuard'

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export interface RequestOptions {
  baseUrl?: string
  token?: string
  signal?: AbortSignal
}

export const MUTATION_CREDENTIALS_REQUIRED_MESSAGE =
  'API credentials are required for mutating requests. Open Settings → Console API and attach a token for this browser tab.'

export function requireMutationCredentials(method: string, token: string): void {
  if (mutationRequiresCredentials(method, token)) {
    throw new ApiError(MUTATION_CREDENTIALS_REQUIRED_MESSAGE, 401)
  }
}

export async function apiFetch<T>(
  path: string,
  options: RequestOptions & { method?: string; body?: unknown } = {},
): Promise<T> {
  const base = options.baseUrl ?? ''
  const url = `${base}${path}`
  const method = options.method ?? 'GET'
  const token = options.token ?? ''
  requireMutationCredentials(method, token)
  const headers: Record<string, string> = {
    Accept: 'application/json',
  }
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  const res = await fetch(url, {
    method,
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    signal: options.signal,
  })

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new ApiError(text || `HTTP ${res.status}`, res.status)
  }

  const ct = res.headers.get('content-type') ?? ''
  if (ct.includes('application/json')) {
    return res.json() as Promise<T>
  }
  return (await res.text()) as T
}

export function searchClient() {
  const s = resolveApiSettings()
  return {
    baseUrl: s.searchBaseUrl,
    token: s.searchToken,
  }
}

export function aclClient() {
  const s = resolveApiSettings()
  return {
    baseUrl: s.aclBaseUrl,
    token: s.aclToken,
  }
}

export function controlClient() {
  const s = resolveApiSettings()
  return {
    baseUrl: s.metricsBaseUrl,
    token: s.controlToken,
  }
}
