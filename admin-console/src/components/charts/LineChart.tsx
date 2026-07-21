import { useMemo, useState } from 'react'
import type { TsPoint } from '../../lib/timeseries'
import { formatNumber, formatTime, niceTicks, seriesColor, useMeasuredWidth } from './common'

export interface LineSeries {
  name: string
  points: TsPoint[]
  /** Fixed categorical slot (color follows the entity, not the rank). */
  slot: number
}

interface LineChartProps {
  series: LineSeries[]
  height?: number
  unit?: string
  /** Fill the area under a single series. */
  area?: boolean
  yMax?: number
}

const PAD = { top: 8, right: 12, bottom: 20, left: 42 }

/**
 * Time-series line chart: hairline grid, 2px lines, crosshair + tooltip.
 * Legend renders for ≥2 series; a single series is named by the panel title.
 */
export function LineChart({ series, height = 180, unit = '', area = false, yMax }: LineChartProps) {
  const [wrapRef, width] = useMeasuredWidth<HTMLDivElement>()
  const [hoverX, setHoverX] = useState<number | null>(null)

  const visible = series.filter((s) => s.points.length > 0)
  const allPoints = visible.flatMap((s) => s.points)

  const { tMin, tMax, vMax, ticks } = useMemo(() => {
    const ts = allPoints.map((p) => p.t)
    const vs = allPoints.map((p) => p.v)
    const tMin = ts.length ? Math.min(...ts) : 0
    const tMax = ts.length ? Math.max(...ts) : 1
    const rawMax = yMax ?? (vs.length ? Math.max(...vs) : 1)
    const vMax = rawMax > 0 ? rawMax * 1.1 : 1
    return { tMin, tMax, vMax, ticks: niceTicks(0, vMax, 4) }
  }, [allPoints, yMax])

  if (visible.length === 0 || allPoints.length < 2) {
    return (
      <div className="flex items-center justify-center rounded-md border border-border bg-surface-0/40 text-xs text-text-secondary" style={{ height }}>
        Collecting samples… charts fill in as the console polls.
      </div>
    )
  }

  const plotW = Math.max(0, width - PAD.left - PAD.right)
  const plotH = height - PAD.top - PAD.bottom
  const x = (t: number) => PAD.left + (tMax === tMin ? 0 : ((t - tMin) / (tMax - tMin)) * plotW)
  const y = (v: number) => PAD.top + plotH - (v / vMax) * plotH

  const hover = hoverX === null ? null : nearest(visible, tMin + ((hoverX - PAD.left) / Math.max(plotW, 1)) * (tMax - tMin))

  return (
    <div ref={wrapRef} className="relative w-full">
      {width > 0 && (
        <svg
          width={width}
          height={height}
          role="img"
          aria-label={`Line chart: ${visible.map((s) => s.name).join(', ')}`}
          onMouseMove={(e) => {
            const rect = e.currentTarget.getBoundingClientRect()
            setHoverX(Math.min(Math.max(e.clientX - rect.left, PAD.left), width - PAD.right))
          }}
          onMouseLeave={() => setHoverX(null)}
        >
          {ticks.map((tick) => (
            <g key={tick}>
              <line x1={PAD.left} x2={width - PAD.right} y1={y(tick)} y2={y(tick)} stroke="var(--viz-grid)" strokeWidth={1} />
              <text x={PAD.left - 6} y={y(tick) + 3} textAnchor="end" fontSize={10} fill="var(--viz-muted)">
                {formatNumber(tick)}
              </text>
            </g>
          ))}
          <line x1={PAD.left} x2={width - PAD.right} y1={PAD.top + plotH} y2={PAD.top + plotH} stroke="var(--viz-axis)" strokeWidth={1} />
          <text x={PAD.left} y={height - 5} fontSize={10} fill="var(--viz-muted)">
            {formatTime(tMin)}
          </text>
          <text x={width - PAD.right} y={height - 5} textAnchor="end" fontSize={10} fill="var(--viz-muted)">
            {formatTime(tMax)}
          </text>

          {visible.map((s) => {
            const color = seriesColor(s.slot)
            const d = s.points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ')
            return (
              <g key={s.name}>
                {area && visible.length === 1 && (
                  <path
                    d={`${d} L${x(s.points[s.points.length - 1].t).toFixed(1)},${PAD.top + plotH} L${x(s.points[0].t).toFixed(1)},${PAD.top + plotH} Z`}
                    fill={color}
                    opacity={0.12}
                  />
                )}
                <path d={d} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              </g>
            )
          })}

          {hover && (
            <g>
              <line x1={x(hover.t)} x2={x(hover.t)} y1={PAD.top} y2={PAD.top + plotH} stroke="var(--viz-axis)" strokeWidth={1} strokeDasharray="3 3" />
              {hover.values.map(({ series: s, point }) => (
                <circle key={s.name} cx={x(point.t)} cy={y(point.v)} r={4} fill={seriesColor(s.slot)} stroke="var(--color-surface-1)" strokeWidth={2} />
              ))}
            </g>
          )}
        </svg>
      )}

      {hover && (
        <div
          className="pointer-events-none absolute z-10 rounded-md border border-border bg-surface-1 px-3 py-2 text-xs shadow-lg"
          style={{
            left: Math.min(Math.max(x(hover.t) + 10, 0), Math.max(width - 150, 0)),
            top: 4,
          }}
        >
          <p className="font-medium text-text-secondary">{formatTime(hover.t)}</p>
          {hover.values.map(({ series: s, point }) => (
            <p key={s.name} className="mt-0.5 flex items-center gap-1.5 text-text-primary">
              <span className="inline-block size-2 rounded-full" style={{ background: seriesColor(s.slot) }} />
              {s.name}: <span className="font-semibold tabular-nums">{formatNumber(point.v)}{unit}</span>
            </p>
          ))}
        </div>
      )}

      {visible.length >= 2 && (
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-secondary">
          {visible.map((s) => (
            <span key={s.name} className="inline-flex items-center gap-1.5">
              <span className="inline-block h-0.5 w-4 rounded" style={{ background: seriesColor(s.slot) }} />
              {s.name}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function nearest(series: LineSeries[], t: number) {
  const values = series
    .map((s) => {
      let best = s.points[0]
      for (const p of s.points) if (Math.abs(p.t - t) < Math.abs(best.t - t)) best = p
      return { series: s, point: best }
    })
    .filter((v) => v.point !== undefined)
  if (values.length === 0) return null
  return { t: values[0].point.t, values }
}
