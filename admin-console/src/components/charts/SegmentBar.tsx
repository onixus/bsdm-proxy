import { useState } from 'react'
import { formatNumber } from './common'

export interface Segment {
  label: string
  value: number
  color: string
}

/**
 * Single 100% stacked bar for a categorical distribution, with 2px surface
 * gaps between segments and an always-present legend with values.
 */
export function SegmentBar({ segments }: { segments: Segment[] }) {
  const [hover, setHover] = useState<string | null>(null)
  const shown = segments.filter((s) => s.value > 0)
  const total = shown.reduce((sum, s) => sum + s.value, 0)
  if (total === 0) return <p className="text-sm text-text-secondary">No data yet.</p>

  return (
    <div>
      <div className="flex h-4 w-full gap-[2px] overflow-hidden rounded-full">
        {shown.map((s) => (
          <div
            key={s.label}
            className="h-full transition-opacity"
            style={{
              width: `${(s.value / total) * 100}%`,
              minWidth: 3,
              background: s.color,
              opacity: hover && hover !== s.label ? 0.35 : 1,
            }}
            onMouseEnter={() => setHover(s.label)}
            onMouseLeave={() => setHover(null)}
            title={`${s.label}: ${s.value.toLocaleString()} (${((s.value / total) * 100).toFixed(1)}%)`}
          />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {shown.map((s) => (
          <span
            key={s.label}
            className="inline-flex items-center gap-1.5 text-text-secondary"
            onMouseEnter={() => setHover(s.label)}
            onMouseLeave={() => setHover(null)}
          >
            <span className="inline-block size-2.5 rounded-sm" style={{ background: s.color }} />
            {s.label}
            <span className="tabular-nums text-text-primary">{formatNumber(s.value)}</span>
            <span className="tabular-nums">({((s.value / total) * 100).toFixed(1)}%)</span>
          </span>
        ))}
      </div>
    </div>
  )
}
