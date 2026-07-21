import type { ReactNode } from 'react'
import { AlertTriangle, FlaskConical, RefreshCw, WifiOff } from 'lucide-react'
import type { DataSource } from '../../api/source'
import { Button } from './Button'

/** Small pill telling the operator where a panel's numbers come from. */
export function SourceBadge({ source }: { source: DataSource }) {
  if (source === 'live') {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-success/40 bg-success/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-success">
        <span className="size-1.5 rounded-full bg-success" />
        Live
      </span>
    )
  }
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-warning/40 bg-warning/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-warning"
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
    <div className="flex flex-col items-center gap-3 rounded-lg border border-danger/30 bg-danger/5 p-6 text-center">
      <WifiOff className="size-8 text-danger" />
      <div>
        <p className="font-semibold text-text-primary">{title}</p>
        {detail && <p className="mt-1 break-all font-mono text-xs text-text-secondary">{detail}</p>}
        <p className="mt-1 text-xs text-text-secondary">
          Check API endpoints in Settings → API, or enable demo mode to explore the UI offline.
        </p>
      </div>
      {onRetry && (
        <Button variant="secondary" onClick={onRetry}>
          <RefreshCw className="size-4" /> Retry
        </Button>
      )}
    </div>
  )
}

export function EmptyState({ message }: { message: string }) {
  return <p className="py-6 text-center text-sm text-text-secondary">{message}</p>
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-surface-2 ${className}`} aria-hidden />
}

export function SkeletonRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
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
    <div className="flex items-start gap-3 rounded-lg border border-warning/40 bg-warning/10 p-4">
      <AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" />
      <div className="text-sm">
        <p className="font-semibold text-warning">Preview — no backend endpoint yet</p>
        <p className="mt-0.5 text-text-secondary">
          {feature} has no REST API in the proxy yet, so everything below is illustrative demo data.
          {children}
        </p>
      </div>
    </div>
  )
}
