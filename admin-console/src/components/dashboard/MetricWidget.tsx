import type { ComponentType, ReactNode } from 'react'
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
  icon?: ComponentType<{ className?: string }>
}

const statusRing: Record<string, string> = {
  ok: 'border-border/80 hover:border-accent/40',
  warn: 'border-warning/50 bg-warning/5',
  error: 'border-danger/60 bg-danger/5 shadow-glow-danger',
}

/** Stat tile: label, hero number, optional icon & sparkline trend. */
export function StatTile({ label, value, unit, trend, trendColor, status = 'ok', hint, icon: Icon }: StatTileProps) {
  return (
    <article
      className={`group relative overflow-hidden rounded-xl border bg-surface-1/90 p-4 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md ${statusRing[status]}`}
      title={hint}
    >
      <div className="flex items-start justify-between gap-2">
        <p
          className="line-clamp-2 min-h-[2.25rem] min-w-0 flex-1 break-words text-xs font-semibold leading-snug text-text-secondary"
          title={label}
        >
          {label}
        </p>
        {Icon && (
          <div className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-text-secondary transition-colors group-hover:bg-accent/15 group-hover:text-accent">
            <Icon className="size-4" />
          </div>
        )}
      </div>

      <div className="mt-3 flex items-end justify-between gap-2">
        <div className="min-w-0">
          <p className="text-xl font-bold tracking-tight text-text-primary sm:text-2xl">
            {value}
            {unit && <span className="ml-1 text-sm font-normal text-text-secondary">{unit}</span>}
          </p>
          {hint && <p className="mt-1 truncate text-[11px] text-text-secondary">{hint}</p>}
        </div>
        {trend && trend.length > 1 && (
          <div className="pb-1">
            <Sparkline points={trend} color={trendColor} />
          </div>
        )}
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
  icon: Icon,
}: {
  title: string
  children: ReactNode
  action?: ReactNode
  icon?: ComponentType<{ className?: string }>
}) {
  return (
    <section className="rounded-xl border border-border/80 bg-surface-1/90 shadow-sm backdrop-blur-sm transition-all hover:border-border">
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 rounded-t-xl border-b border-border/80 bg-surface-1/50 px-5 py-3.5">
        <div className="flex min-w-0 items-center gap-2.5">
          {Icon && <Icon className="size-4 shrink-0 text-accent" />}
          <h2 className="text-sm font-bold leading-snug tracking-tight text-text-primary">{title}</h2>
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
      <div className="p-5">{children}</div>
    </section>
  )
}

