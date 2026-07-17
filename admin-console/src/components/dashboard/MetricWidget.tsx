import type { ReactNode } from 'react'
import { TrendingDown, TrendingUp, Minus } from 'lucide-react'
import type { DashboardMetric } from '../../api/metrics'

interface MetricWidgetProps {
  metric: DashboardMetric
}

const statusRing: Record<string, string> = {
  ok: 'border-success/30',
  warn: 'border-warning/30',
  error: 'border-danger/30',
}

export function MetricWidget({ metric }: MetricWidgetProps) {
  const TrendIcon =
    metric.trend === 'up' ? TrendingUp : metric.trend === 'down' ? TrendingDown : Minus

  return (
    <article
      className={`rounded-lg border bg-surface-1 p-4 ${statusRing[metric.status ?? 'ok']}`}
    >
      <p className="text-xs font-medium uppercase tracking-wide text-text-secondary">
        {metric.label}
      </p>
      <div className="mt-2 flex items-end justify-between gap-2">
        <p className="text-2xl font-bold text-text-primary sm:text-3xl">
          {metric.value}
          {metric.unit && (
            <span className="ml-1 text-base font-normal text-text-secondary">{metric.unit}</span>
          )}
        </p>
        {metric.trend && (
          <TrendIcon className="size-4 shrink-0 text-text-secondary" aria-hidden />
        )}
      </div>
    </article>
  )
}

export function WidgetGrid({ children }: { children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-4 min-[400px]:grid-cols-2 lg:grid-cols-4">{children}</div>
  )
}

export function Panel({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-surface-1">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
        {action}
      </div>
      <div className="p-4">{children}</div>
    </section>
  )
}
