import type { ThreatScoreSnapshot } from '../../api/threatScores'
import { severitySegments } from './analyticsUtils'
import { SegmentBar } from '../charts/SegmentBar'
import { BarList } from '../charts/BarList'
import { Panel } from '../dashboard/MetricWidget'
import { EmptyState } from '../ui/DataState'

interface ThreatAnalyticsProps {
  title: string
  severityTitle: string
  entitiesTitle: string
  snapshot?: ThreatScoreSnapshot
}

export function ThreatAnalytics({ title, severityTitle, entitiesTitle, snapshot }: ThreatAnalyticsProps) {
  const scores = snapshot?.scores ?? []

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel title={`${title}: ${severityTitle}`}>
        {scores.length === 0 ? (
          <EmptyState message="No threat scores available" />
        ) : (
          <SegmentBar segments={severitySegments(scores.map((score) => score.severity))} />
        )}
      </Panel>

      <Panel title={entitiesTitle}>
        {scores.length === 0 ? (
          <EmptyState message="No threat entities available" />
        ) : (
          <BarList
            items={scores
              .slice()
              .sort((a, b) => b.score - a.score)
              .slice(0, 10)
              .map((score) => ({
                label: `${score.entity_type}: ${score.entity_id}`,
                value: Math.round(score.score * 100),
              }))}
          />
        )}
      </Panel>
    </div>
  )
}
