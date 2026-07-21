import { useEffect, useRef, useState } from 'react'

/** Fixed categorical slot order — assigned by entity, never cycled. */
export const SERIES_VARS = [
  'var(--viz-1)',
  'var(--viz-2)',
  'var(--viz-3)',
  'var(--viz-4)',
  'var(--viz-5)',
  'var(--viz-6)',
  'var(--viz-7)',
  'var(--viz-8)',
] as const

export function seriesColor(slot: number): string {
  return SERIES_VARS[Math.min(slot, SERIES_VARS.length - 1)]
}

/** Status colors are reserved for state (good/warn/serious/critical), never series. */
export const STATUS_VARS = {
  good: 'var(--viz-good)',
  warning: 'var(--viz-warning)',
  serious: 'var(--viz-serious)',
  critical: 'var(--viz-critical)',
} as const

/** Fixed color per cache disposition — color follows the entity, never its rank. */
const CACHE_STATUS_SLOTS: Record<string, number> = {
  HIT: 2,
  MISS: 1,
  BYPASS: 3,
  DENIED: 7,
  COALESCED: 6,
}

export function cacheStatusColor(label: string): string {
  return seriesColor(CACHE_STATUS_SLOTS[label.toUpperCase()] ?? 4)
}

export function formatNumber(v: number): string {
  if (!Number.isFinite(v)) return '—'
  if (Math.abs(v) >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
  if (Math.abs(v) >= 10_000) return `${(v / 1000).toFixed(0)}k`
  if (Math.abs(v) >= 1000) return `${(v / 1000).toFixed(1)}k`
  if (Math.abs(v) >= 100) return v.toFixed(0)
  if (Math.abs(v) >= 1) return v % 1 === 0 ? String(v) : v.toFixed(1)
  return v.toFixed(2)
}

export function formatTime(t: number): string {
  return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

/** Container width tracking for responsive SVG charts. */
export function useMeasuredWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T | null>(null)
  const [width, setWidth] = useState(0)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) setWidth(entry.contentRect.width)
    })
    ro.observe(el)
    setWidth(el.getBoundingClientRect().width)
    return () => ro.disconnect()
  }, [])
  return [ref, width]
}

export function niceTicks(min: number, max: number, count = 4): number[] {
  if (!Number.isFinite(min) || !Number.isFinite(max) || max <= min) return [0]
  const span = max - min
  const step = 10 ** Math.floor(Math.log10(span / count))
  const err = span / count / step
  const mult = err >= 7.5 ? 10 : err >= 3.5 ? 5 : err >= 1.5 ? 2 : 1
  const s = step * mult
  const ticks: number[] = []
  for (let v = Math.ceil(min / s) * s; v <= max + 1e-9; v += s) ticks.push(v)
  return ticks
}
