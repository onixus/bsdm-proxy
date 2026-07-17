import { loadApiSettings } from './settings'

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

export async function apiFetch<T>(
  path: string,
  options: RequestOptions & { method?: string; body?: unknown } = {},
): Promise<T> {
  const base = options.baseUrl ?? ''
  const url = `${base}${path}`
  const headers: Record<string, string> = {
    Accept: 'application/json',
  }
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  const token = options.token ?? ''
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  const res = await fetch(url, {
    method: options.method ?? 'GET',
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
  const s = loadApiSettings()
  return {
    baseUrl: s.searchBaseUrl,
    token: s.searchToken,
  }
}

export function aclClient() {
  const s = loadApiSettings()
  return {
    baseUrl: s.aclBaseUrl,
    token: s.aclToken,
  }
}
