import type { ComponentType, ReactNode } from 'react'
import { AlertTriangle, FlaskConical, RefreshCw, WifiOff, Inbox } from 'lucide-react'
import type { DataSource } from '../../api/source'
import { fmt, useT } from '../../lib/i18n'
import { Button } from './Button'

/** Small pill telling the operator where a panel's numbers come from. */
export function SourceBadge({ source }: { source: DataSource }) {
  const t = useT()

  if (source === 'live') {
    return (
      <span
        className="inline-flex items-center gap-1.5 rounded-full border border-success/40 bg-success/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-success shadow-xs"
        title={t.ui.liveHint}
      >
        <span className="relative flex size-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75"></span>
          <span className="relative inline-flex size-2 rounded-full bg-success"></span>
        </span>
        {t.ui.live}
      </span>
    )
  }
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-warning/40 bg-warning/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-warning shadow-xs"
      title={t.ui.demoHint}
    >
      <FlaskConical className="size-3" />
      {t.ui.demo}
    </span>
  )
}

export function ErrorState({
  title,
  detail,
  onRetry,
}: {
  title?: string
  detail?: string
  onRetry?: () => void
}) {
  const t = useT()

  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-danger/30 bg-danger/5 p-6 text-center shadow-xs">
      <div className="flex size-12 shrink-0 items-center justify-center rounded-full border border-danger/20 bg-danger/10 text-danger">
        <WifiOff className="size-6" />
      </div>
      <div className="min-w-0 max-w-full">
        <p className="text-base font-semibold text-text-primary">{title ?? t.ui.errorTitle}</p>
        {detail && (
          <p className="mt-1 max-w-full overflow-x-auto rounded-md border border-border bg-surface-0/60 p-2 font-mono text-xs break-words text-text-secondary">
            {detail}
          </p>
        )}
        <p className="mx-auto mt-2 max-w-md text-xs leading-relaxed text-text-secondary">
          {t.ui.errorHint}
        </p>
      </div>
      {onRetry && (
        <Button variant="secondary" onClick={onRetry} className="mt-1">
          <RefreshCw className="size-4" /> {t.ui.retry}
        </Button>
      )}
    </div>
  )
}

export function EmptyState({ message, icon: Icon = Inbox }: { message: string; icon?: ComponentType<{ className?: string }> }) {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-10 text-center">
      <div className="mb-3 flex size-12 items-center justify-center rounded-full border border-border bg-surface-2 text-text-secondary">
        <Icon className="size-6 opacity-60" />
      </div>
      <p className="max-w-prose text-sm font-medium leading-relaxed text-text-secondary">{message}</p>
    </div>
  )
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-surface-2/80 ${className}`} aria-hidden />
}

export function SkeletonRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  )
}

/**
 * Banner for pages whose backend endpoints do not exist yet. These pages
 * render illustrative data by design and must never be mistaken for telemetry.
 */
export function PreviewBanner({ feature, children }: { feature: string; children?: ReactNode }) {
  const t = useT()

  return (
    <div className="flex items-start gap-3.5 rounded-xl border border-warning/40 bg-warning/10 p-4 shadow-xs">
      <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-warning/20 text-warning">
        <AlertTriangle className="size-4" />
      </div>
      <div className="min-w-0 text-sm">
        <p className="text-base font-semibold text-warning">{t.ui.previewTitle}</p>
        <p className="mt-0.5 leading-relaxed text-text-secondary">
          {fmt(t.ui.previewBody, { feature })}
          {children}
        </p>
      </div>
    </div>
  )
}

/**
 * Stronger banner for scope-frozen experimental modules (Hybrid pilot honesty).
 * Deep links stay available for developers; primary nav never advertises these.
 */
export function FrozenModuleBanner({
  feature,
  note,
  children,
}: {
  feature: string
  note?: string
  children?: ReactNode
}) {
  const t = useT()

  return (
    <div
      className="flex items-start gap-3.5 rounded-xl border border-danger/35 bg-danger/5 p-4 shadow-xs"
      role="status"
      data-testid="frozen-module-banner"
    >
      <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-danger/15 text-danger">
        <AlertTriangle className="size-4" />
      </div>
      <div className="min-w-0 text-sm">
        <p className="text-base font-semibold text-danger">{t.ui.frozenTitle}</p>
        <p className="mt-0.5 leading-relaxed text-text-secondary">
          {fmt(t.ui.frozenBody, { feature })}
          {note ? <> {note}</> : null}
          {children}
        </p>
        <p className="mt-2 text-xs leading-relaxed text-text-secondary">{t.ui.frozenFooter}</p>
      </div>
    </div>
  )
}
