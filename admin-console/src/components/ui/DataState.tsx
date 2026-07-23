import type { ComponentType, ReactNode } from 'react'
import { AlertTriangle, FlaskConical, RefreshCw, WifiOff, Inbox } from 'lucide-react'
import type { DataSource } from '../../api/source'
import { Button } from './Button'

/** Small pill telling the operator where a panel's numbers come from. */
export function SourceBadge({ source }: { source: DataSource }) {
  if (source === 'live') {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-success/40 bg-success/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-success shadow-xs">
        <span className="relative flex size-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75"></span>
          <span className="relative inline-flex size-2 rounded-full bg-success"></span>
        </span>
        Live
      </span>
    )
  }
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-warning/40 bg-warning/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-warning shadow-xs"
      title="Demo mode is on and the backend is unreachable — these numbers are illustrative, not real."
    >
      <FlaskConical className="size-3" />
      Demo
    </span>
  )
}

export function ErrorState({
  title = 'Failed to load data',
  detail,
  onRetry,
}: {
  title?: string
  detail?: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-danger/30 bg-danger/5 p-6 text-center shadow-xs">
      <div className="flex size-12 items-center justify-center rounded-full bg-danger/10 text-danger border border-danger/20">
        <WifiOff className="size-6" />
      </div>
      <div>
        <p className="font-semibold text-text-primary text-base">{title}</p>
        {detail && <p className="mt-1 break-all font-mono text-xs text-text-secondary bg-surface-0/60 p-2 rounded-md border border-border">{detail}</p>}
        <p className="mt-2 text-xs text-text-secondary max-w-md">
          Check API endpoints in Settings → API, or enable demo mode to explore the UI offline.
        </p>
      </div>
      {onRetry && (
        <Button variant="secondary" onClick={onRetry} className="mt-1">
          <RefreshCw className="size-4" /> Retry
        </Button>
      )}
    </div>
  )
}

export function EmptyState({ message, icon: Icon = Inbox }: { message: string; icon?: ComponentType<{ className?: string }> }) {

  return (
    <div className="flex flex-col items-center justify-center py-10 px-4 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-surface-2 text-text-secondary mb-3 border border-border">
        <Icon className="size-6 opacity-60" />
      </div>
      <p className="text-sm font-medium text-text-secondary">{message}</p>
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
  return (
    <div className="flex items-start gap-3.5 rounded-xl border border-warning/40 bg-warning/10 p-4 shadow-xs">
      <div className="flex size-8 items-center justify-center rounded-lg bg-warning/20 text-warning shrink-0">
        <AlertTriangle className="size-4" />
      </div>
      <div className="text-sm min-w-0">
        <p className="font-semibold text-warning text-base">Preview — no backend endpoint yet</p>
        <p className="mt-0.5 text-text-secondary leading-relaxed">
          {feature} has no REST API in the proxy yet, so everything below is illustrative demo data.
          {children}
        </p>
      </div>
    </div>
  )
}

