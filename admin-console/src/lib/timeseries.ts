/**
 * In-memory time-series accumulator. The console has no TSDB to query, so it
 * builds short-horizon trends by recording each poll of /api/stats and
 * /metrics. Counters are converted to per-second rates from consecutive
 * samples; gauges are stored as-is. Survives route changes (module singleton),
 * resets on full page reload.
 */

export interface TsPoint {
  t: number
  v: number
}

const MAX_POINTS = 720

const gauges = new Map<string, TsPoint[]>()
const counterLast = new Map<string, { t: number; v: number }>()

function push(key: string, point: TsPoint): void {
  let arr = gauges.get(key)
  if (!arr) {
    arr = []
    gauges.set(key, arr)
  }
  arr.push(point)
  if (arr.length > MAX_POINTS) arr.splice(0, arr.length - MAX_POINTS)
}

/** Record an instantaneous value (gauge, ratio, quantile). */
export function recordGauge(key: string, value: number, t = Date.now()): void {
  if (!Number.isFinite(value)) return
  push(key, { t, v: value })
}

/**
 * Record a cumulative counter; stores the derived per-second rate.
 * Counter resets (process restart) yield a skipped interval, not a negative spike.
 */
export function recordCounter(key: string, cumulative: number, t = Date.now()): void {
  if (!Number.isFinite(cumulative)) return
  const last = counterLast.get(key)
  counterLast.set(key, { t, v: cumulative })
  if (!last || t <= last.t) return
  const delta = cumulative - last.v
  if (delta < 0) return
  push(key, { t, v: delta / ((t - last.t) / 1000) })
}

/** Points within the trailing window (ms). */
export function series(key: string, windowMs = 30 * 60_000): TsPoint[] {
  const arr = gauges.get(key) ?? []
  const cutoff = Date.now() - windowMs
  return arr.filter((p) => p.t >= cutoff)
}

export function lastValue(key: string): number | null {
  const arr = gauges.get(key)
  return arr && arr.length > 0 ? arr[arr.length - 1].v : null
}
