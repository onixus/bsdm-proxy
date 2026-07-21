import { loadApiSettings } from './settings'

/** One sample from the Prometheus text exposition format. */
export interface PromSample {
  name: string
  labels: Record<string, string>
  value: number
}

export interface HistogramSummary {
  count: number
  sum: number
  /** Cumulative bucket counts keyed by upper bound (le). */
  buckets: { le: number; count: number }[]
}

export interface PromSnapshot {
  scrapedAt: number
  samples: PromSample[]
}

export async function scrapeMetrics(): Promise<PromSnapshot> {
  const settings = loadApiSettings()
  const base = settings.metricsBaseUrl.trim()
  const res = await fetch(`${base}/metrics`, { headers: { Accept: 'text/plain' } })
  if (!res.ok) throw new Error(`GET /metrics → HTTP ${res.status}`)
  const text = await res.text()
  return { scrapedAt: Date.now(), samples: parsePrometheusText(text) }
}

export function parsePrometheusText(text: string): PromSample[] {
  const samples: PromSample[] = []
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+([^\s]+)/)
    if (!match) continue
    const value = Number(match[4])
    if (!Number.isFinite(value)) continue
    samples.push({ name: match[1], labels: parseLabels(match[3] ?? ''), value })
  }
  return samples
}

function parseLabels(raw: string): Record<string, string> {
  const labels: Record<string, string> = {}
  const re = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g
  let m: RegExpExecArray | null
  while ((m = re.exec(raw)) !== null) {
    labels[m[1]] = m[2].replace(/\\([\\n"])/g, (_match, ch: string) => {
      if (ch === 'n') return '\n'
      if (ch === '"') return '"'
      if (ch === '\\') return '\\'
      return `\\${ch}`
    })
  }
  return labels
}

/** Sum all samples of a metric, optionally filtered by label predicate. */
export function sumMetric(
  samples: PromSample[],
  name: string,
  predicate?: (labels: Record<string, string>) => boolean,
): number {
  let total = 0
  for (const s of samples) {
    if (s.name !== name) continue
    if (predicate && !predicate(s.labels)) continue
    total += s.value
  }
  return total
}

/** Group a counter by one label, summing over the others. */
export function groupByLabel(samples: PromSample[], name: string, label: string): Map<string, number> {
  const out = new Map<string, number>()
  for (const s of samples) {
    if (s.name !== name) continue
    const key = s.labels[label] ?? '(none)'
    out.set(key, (out.get(key) ?? 0) + s.value)
  }
  return out
}

export function histogram(samples: PromSample[], name: string): HistogramSummary | null {
  const buckets = new Map<number, number>()
  let count = 0
  let sum = 0
  let seen = false
  for (const s of samples) {
    if (s.name === `${name}_bucket`) {
      const le = s.labels.le === '+Inf' ? Infinity : Number(s.labels.le)
      buckets.set(le, (buckets.get(le) ?? 0) + s.value)
      seen = true
    } else if (s.name === `${name}_count`) {
      count += s.value
      seen = true
    } else if (s.name === `${name}_sum`) {
      sum += s.value
      seen = true
    }
  }
  if (!seen) return null
  const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]).map(([le, c]) => ({ le, count: c }))
  return { count, sum, buckets: sorted }
}

/** Estimate a quantile from cumulative histogram buckets (linear interpolation). */
export function histogramQuantile(h: HistogramSummary, q: number): number | null {
  if (h.count === 0 || h.buckets.length === 0) return null
  const target = q * h.count
  let prevLe = 0
  let prevCount = 0
  for (const { le, count } of h.buckets) {
    if (count >= target) {
      if (!Number.isFinite(le)) return prevLe
      const bucketCount = count - prevCount
      if (bucketCount <= 0) return le
      return prevLe + ((target - prevCount) / bucketCount) * (le - prevLe)
    }
    prevLe = Number.isFinite(le) ? le : prevLe
    prevCount = count
  }
  return prevLe
}
