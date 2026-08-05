import type { DataSource } from '../../api/source'
import type { ThreatScoreSnapshot } from '../../api/threatScores'
import { BarList } from '../charts/BarList'
import { seriesColor } from '../charts/common'
import { SegmentBar } from '../charts/SegmentBar'
import { Panel } from '../dashboard/MetricWidget'
import { EmptyState, SourceBadge } from '../ui/DataState'
import { countBy, severitySegments } from './analyticsUtils'

interface ThreatAnalyticsProps {
  labels: {
    threatSeverity: string
    threatByModel: string
    mlUnreachable: string
    noActiveScores: string
  }
  snapshot?: ThreatScoreSnapshot
  source?: DataSource
  error?: boolean
}

export function ThreatAnalytics({ labels, snapshot, source, error }: ThreatAnalyticsProps) {
  const scores = snapshot?.scores ?? []

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel
        title={labels.threatSeverity}
        action={source ? <SourceBadge source={source} /> : undefined}
      >
        {error && <EmptyState message={labels.mlUnreachable} />}
        {!error && scores.length === 0 && <EmptyState message={labels.noActiveScores} />}
        {!error && scores.length > 0 && (
          <SegmentBar segments={severitySegments(scores.map((score) => score.severity))} />
        )}
      </Panel>

      <Panel title={labels.threatByModel}>
        {scores.length === 0 ? (
          <EmptyState message={labels.noActiveScores} />
        ) : (
          <BarList
            items={countBy(scores.map((score) => score.model))
              .slice(0, 8)
              .map(([label, value], index) => ({
                label,
                value,
                color: seriesColor(index),
              }))}
          />
        )}
      </Panel>
    </div>
  )
}
