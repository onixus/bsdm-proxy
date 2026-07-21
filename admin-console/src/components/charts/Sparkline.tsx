import type { TsPoint } from '../../lib/timeseries'

interface SparklineProps {
  points: TsPoint[]
  width?: number
  height?: number
  color?: string
}

/** Minimal trend line for stat tiles — no axes, no labels, decorative summary. */
export function Sparkline({ points, width = 96, height = 28, color = 'var(--viz-1)' }: SparklineProps) {
  if (points.length < 2) return <div style={{ width, height }} aria-hidden />

  const vs = points.map((p) => p.v)
  const min = Math.min(...vs)
  const max = Math.max(...vs)
  const span = max - min || 1
  const x = (i: number) => (i / (points.length - 1)) * (width - 4) + 2
  const y = (v: number) => height - 3 - ((v - min) / span) * (height - 6)
  const d = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ')

  return (
    <svg width={width} height={height} aria-hidden className="shrink-0">
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" opacity={0.9} />
    </svg>
  )
}
