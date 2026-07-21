import { formatNumber } from './common'

export interface BarListItem {
  label: string
  value: number
  /** Optional secondary count shown after the value (e.g. errors). */
  extra?: string
  color?: string
}

/** Horizontal top-N bars with direct labels — magnitude + identity in one glance. */
export function BarList({ items, unit = '' }: { items: BarListItem[]; unit?: string }) {
  const max = Math.max(...items.map((i) => i.value), 1)
  return (
    <ul className="space-y-2">
      {items.map((item) => (
        <li key={item.label} title={`${item.label}: ${item.value.toLocaleString()}${unit}`}>
          <div className="flex items-baseline justify-between gap-2 text-xs">
            <span className="truncate font-mono text-text-primary">{item.label}</span>
            <span className="shrink-0 tabular-nums text-text-secondary">
              {formatNumber(item.value)}
              {unit}
              {item.extra && <span className="ml-1.5 text-danger">{item.extra}</span>}
            </span>
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-surface-0">
            <div
              className="h-full rounded-full"
              style={{ width: `${(item.value / max) * 100}%`, background: item.color ?? 'var(--viz-1)' }}
            />
          </div>
        </li>
      ))}
    </ul>
  )
}
