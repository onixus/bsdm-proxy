import type { ReactNode } from 'react'
import { Download, Pause, Play } from 'lucide-react'
import { Button } from '../ui/Button'
import { PageHeader } from '../ui/PageHeader'

interface LogToolbarProps {
  title: string
  subtitle: string
  source?: ReactNode
  tail: boolean
  tailLabel: string
  liveLabel: string
  exportLabel: string
  canExport: boolean
  onToggleTail: () => void
  onExport: () => void
}

export function LogToolbar({
  title,
  subtitle,
  source,
  tail,
  tailLabel,
  liveLabel,
  exportLabel,
  canExport,
  onToggleTail,
  onExport,
}: LogToolbarProps) {
  return (
    <div className="surface-panel rounded-2xl p-5">
      <PageHeader
        title={title}
        subtitle={subtitle}
        badge={source}
        actions={
          <>
            <Button variant={tail ? 'primary' : 'secondary'} onClick={onToggleTail}>
              {tail ? <Pause className="size-4" /> : <Play className="size-4" />}
              {tail ? tailLabel : liveLabel}
            </Button>
            <Button variant="secondary" onClick={onExport} disabled={!canExport}>
              <Download className="size-4" /> {exportLabel}
            </Button>
          </>
        }
      />
    </div>
  )
}
