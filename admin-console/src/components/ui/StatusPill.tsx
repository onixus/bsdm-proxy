import type { ReactNode } from 'react'

type StatusTone = 'neutral' | 'success' | 'warning' | 'danger'

interface StatusPillProps {
  tone?: StatusTone
  icon?: ReactNode
  children: ReactNode
  className?: string
}

const toneClasses: Record<StatusTone, string> = {
  neutral: 'border-border bg-surface-2 text-text-secondary',
  success: 'border-success/30 bg-success/10 text-success',
  warning: 'border-warning/35 bg-warning/10 text-warning',
  danger: 'border-danger/35 bg-danger/10 text-danger',
}

export function StatusPill({
  tone = 'neutral',
  icon,
  children,
  className = '',
}: StatusPillProps) {
  return (
    <span
      className={`inline-flex max-w-full items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold whitespace-nowrap ${toneClasses[tone]} ${className}`}
    >
      {icon}
      <span className="truncate">{children}</span>
    </span>
  )
}
