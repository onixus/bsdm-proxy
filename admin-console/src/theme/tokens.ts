/** Central design system tokens — consumed via Tailwind @theme and JS helpers. */
export const theme = {
  colors: {
    surface: {
      0: 'var(--color-surface-0)',
      1: 'var(--color-surface-1)',
      2: 'var(--color-surface-2)',
      3: 'var(--color-surface-3)',
    },
    accent: 'var(--color-accent)',
    success: 'var(--color-success)',
    warning: 'var(--color-warning)',
    danger: 'var(--color-danger)',
    text: {
      primary: 'var(--color-text-primary)',
      secondary: 'var(--color-text-secondary)',
    },
  },
  spacing: {
    touch: 'var(--touch-min)',
  },
} as const

/** Map ML confidence 0–1 to a green→red CSS color. */
export function threatColor(score: number): string {
  const s = Math.max(0, Math.min(1, score))
  const r = Math.round(78 + s * 177)
  const g = Math.round(204 - s * 140)
  const b = Math.round(163 - s * 100)
  return `rgb(${r}, ${g}, ${b})`
}

export function severityBadge(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'bg-danger/20 text-danger border-danger/40'
    case 'medium':
      return 'bg-warning/20 text-warning border-warning/40'
    case 'low':
      return 'bg-success/20 text-success border-success/40'
    default:
      return 'bg-surface-3 text-text-secondary border-border'
  }
}
