import type { ReactNode } from 'react'
import { Download, RefreshCw } from 'lucide-react'
import { Button } from '../ui/Button'
import { Select } from '../ui/Form'
import { PageHeader } from '../ui/PageHeader'

interface AnalyticsToolbarProps {
  title: string
  subtitle: string
  source?: ReactNode
  days: string
  limit: string
  labels: {
    window: string
    last24h: string
    last7d: string
    last30d: string
    sample: string
    events500: string
    events1000: string
    events5000: string
    summaryCsv: string
  }
  isRefreshing: boolean
  canExport: boolean
  onDaysChange: (value: string) => void
  onLimitChange: (value: string) => void
  onRefresh: () => void
  onExport: () => void
}

export function AnalyticsToolbar({
  title,
  subtitle,
  source,
  days,
  limit,
  labels,
  isRefreshing,
  canExport,
  onDaysChange,
  onLimitChange,
  onRefresh,
  onExport,
}: AnalyticsToolbarProps) {
  return (
    <div className="surface-panel rounded-2xl p-5">
      <PageHeader
        title={title}
        subtitle={subtitle}
        badge={source}
        actions={
          <div className="flex flex-wrap items-end gap-2">
            <Select
              label={labels.window}
              value={days}
              onChange={(event) => onDaysChange(event.target.value)}
              options={[
                { value: '1', label: labels.last24h },
                { value: '7', label: labels.last7d },
                { value: '30', label: labels.last30d },
              ]}
            />
            <Select
              label={labels.sample}
              value={limit}
              onChange={(event) => onLimitChange(event.target.value)}
              options={[
                { value: '500', label: labels.events500 },
                { value: '1000', label: labels.events1000 },
                { value: '5000', label: labels.events5000 },
              ]}
            />
            <Button variant="secondary" onClick={onRefresh} disabled={isRefreshing} aria-label="Refresh analytics">
              <RefreshCw className={`size-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </Button>
            <Button variant="secondary" onClick={onExport} disabled={!canExport}>
              <Download className="size-4" /> {labels.summaryCsv}
            </Button>
          </div>
        }
      />
    </div>
  )
}
