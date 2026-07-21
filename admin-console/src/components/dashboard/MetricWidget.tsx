import type { ReactNode } from 'react'
import type { TsPoint } from '../../lib/timeseries'
import { Sparkline } from '../charts/Sparkline'

export interface StatTileProps {
  label: string
  value: string
  unit?: string
  trend?: TsPoint[]
  trendColor?: string
  status?: 'ok' | 'warn' | 'error'
  hint?: string
}

const statusRing: Record<string, string> = {
  ok: 'border-border',
  warn: 'border-warning/50',
  error: 'border-danger/50',
}

/** Stat tile: label, hero number, optional sparkline trend. */
export function StatTile({ label, value, unit, trend, trendColor, status = 'ok', hint }: StatTileProps) {
  return (
    <article className={`rounded-lg border bg-surface-1 p-4 ${statusRing[status]}`} title={hint}>
      <p className="text-xs font-medium uppercase tracking-wide text-text-secondary">{label}</p>
      <div className="mt-2 flex items-end justify-between gap-2">
        <p className="text-2xl font-bold text-text-primary">
          {value}
          {unit && <span className="ml-1 text-sm font-normal text-text-secondary">{unit}</span>}
        </p>
        {trend && trend.length > 1 && <Sparkline points={trend} color={trendColor} />}
      </div>
    </article>
  )
}

export function WidgetGrid({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-1 gap-4 min-[420px]:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">{children}</div>
}

export function Panel({
  title,
  children,
  action,
}: {
  title: string
  children: ReactNode
  action?: ReactNode
}) {
  return (
    <section className="rounded-lg border border-border bg-surface-1">
      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
        {action}
      </div>
      <div className="p-4">{children}</div>
    </section>
  )
}
