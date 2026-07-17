import { threatColor } from '../../theme/tokens'
import type { MlFactor } from '../../api/search'

interface ThreatIndicatorProps {
  /** Confidence score 0–1 (displayed as 0–100%). */
  score: number
  label?: string
  size?: 'sm' | 'md' | 'lg'
}

const sizes = {
  sm: { bar: 'h-2', text: 'text-xs' },
  md: { bar: 'h-3', text: 'text-sm' },
  lg: { bar: 'h-4', text: 'text-base' },
}

export function ThreatIndicator({ score, label = 'ML confidence', size = 'md' }: ThreatIndicatorProps) {
  const pct = Math.round(Math.max(0, Math.min(1, score)) * 100)
  const color = threatColor(score)

  return (
    <div className="space-y-2">
      <div className={`flex items-center justify-between ${sizes[size].text}`}>
        <span className="font-medium text-text-secondary">{label}</span>
        <span className="font-bold tabular-nums" style={{ color }}>
          {pct}%
        </span>
      </div>
      <div className={`w-full overflow-hidden rounded-full bg-surface-0 ${sizes[size].bar}`}>
        <div
          className={`${sizes[size].bar} rounded-full transition-all duration-500`}
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, var(--color-success) 0%, ${color} 100%)`,
          }}
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={label}
        />
      </div>
    </div>
  )
}

interface InsightPanelProps {
  factors: MlFactor[]
  model?: string
}

const weightStyles: Record<MlFactor['weight'], string> = {
  high: 'border-danger/40 bg-danger/10 text-danger',
  medium: 'border-warning/40 bg-warning/10 text-warning',
  low: 'border-success/40 bg-success/10 text-success',
}

export function InsightPanel({ factors, model }: InsightPanelProps) {
  if (factors.length === 0) {
    return (
      <p className="text-sm text-text-secondary">No contributing factors available.</p>
    )
  }

  return (
    <div className="space-y-3">
      {model && (
        <p className="text-xs text-text-secondary">
          Model: <span className="font-mono text-text-primary">{model}</span>
        </p>
      )}
      <ul className="space-y-2">
        {factors.map((f) => (
          <li
            key={f.label}
            className={`rounded-md border px-3 py-2 ${weightStyles[f.weight]}`}
          >
            <div className="flex items-start justify-between gap-2">
              <span className="text-sm font-semibold">{f.label}</span>
              {f.zScore !== undefined && (
                <span className="shrink-0 font-mono text-xs">z={f.zScore.toFixed(1)}</span>
              )}
            </div>
            <p className="mt-1 text-xs opacity-90">{f.detail}</p>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function BlockReasonBadge({ reason }: { reason: 'acl' | 'ml' | 'threat' | 'none' }) {
  const styles: Record<string, string> = {
    acl: 'bg-surface-3 text-text-primary border-border',
    ml: 'bg-accent/20 text-accent border-accent/40',
    threat: 'bg-warning/20 text-warning border-warning/40',
    none: 'bg-success/20 text-success border-success/40',
  }
  const labels: Record<string, string> = {
    acl: 'ACL rule',
    ml: 'ML / UEBA',
    threat: 'Threat intel',
    none: 'Allowed',
  }
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${styles[reason]}`}>
      {labels[reason]}
    </span>
  )
}
