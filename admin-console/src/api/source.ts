/**
 * Data-source provenance. Every fetcher returns its payload wrapped in
 * `Sourced<T>` so the UI can always tell live backend data from demo data.
 * Demo data is served ONLY when the user has explicitly enabled demo mode —
 * a failed request otherwise surfaces as an error state, never as fake numbers.
 */

export type DataSource = 'live' | 'demo'

export interface Sourced<T> {
  data: T
  source: DataSource
  fetchedAt: number
}

const DEMO_KEY = 'bsdm-admin-demo-mode'

export function isDemoMode(): boolean {
  try {
    return localStorage.getItem(DEMO_KEY) === 'true'
  } catch {
    return false
  }
}

export function setDemoMode(enabled: boolean): void {
  try {
    localStorage.setItem(DEMO_KEY, String(enabled))
  } catch {
    /* localStorage unavailable */
  }
  window.dispatchEvent(new CustomEvent('bsdm-demo-mode', { detail: enabled }))
}

export function live<T>(data: T): Sourced<T> {
  return { data, source: 'live', fetchedAt: Date.now() }
}

export function demo<T>(data: T): Sourced<T> {
  return { data, source: 'demo', fetchedAt: Date.now() }
}

/**
 * Wrap a live fetch: on failure, either serve demo data (when demo mode is
 * explicitly on) or rethrow so the query layer shows a real error state.
 */
export async function sourced<T>(liveFetch: () => Promise<T>, demoData: () => T): Promise<Sourced<T>> {
  try {
    return live(await liveFetch())
  } catch (err) {
    if (isDemoMode()) return demo(demoData())
    throw err
  }
}
