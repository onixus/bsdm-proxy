import { Brain } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { ThreatScoreSnapshot } from '../../../api/threatScores'
import { ThreatIndicator } from '../../xai/ThreatIndicator'
import { severityBadge } from '../../../theme/tokens'
import { useT } from '../../../lib/i18n'
import { EmptyState, SourceBadge } from '../../ui/DataState'
import { Panel } from '../MetricWidget'
import type { DataSource } from '../../../api/source'

interface ThreatOverviewProps {
  snapshot?: ThreatScoreSnapshot
  source?: DataSource
  error?: boolean
}

export function ThreatOverview({ snapshot, source, error }: ThreatOverviewProps) {
  const t = useT()

  return (
    <Panel title={t.widgets.threats} icon={Brain} action={source && <SourceBadge source={source} />}>
      {error && <EmptyState message={t.widgets.threatsError} />}
      {snapshot && snapshot.scores.length === 0 && <EmptyState message={t.widgets.threatsEmpty} />}
      {snapshot && snapshot.scores.length > 0 && (
        <ul className="space-y-3">
          {[...snapshot.scores]
            .sort((a, b) => b.score - a.score)
            .slice(0, 5)
            .map((row) => (
              <li key={`${row.entity_type}-${row.entity_id}-${row.model}`} className="space-y-1.5 rounded-lg border border-border/60 bg-surface-0/50 p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <Link to={`/logs?q=${encodeURIComponent(row.entity_id)}`} className="font-mono text-xs font-bold text-text-primary hover:text-accent">
                    {row.entity_id}
                  </Link>
                  <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase ${severityBadge(row.severity)}`}>
                    {row.severity}
                  </span>
                </div>
                <ThreatIndicator score={row.score} size="sm" label={row.model} />
              </li>
            ))}
        </ul>
      )}
    </Panel>
  )
}
