import { BarList } from '../charts/BarList'
import { seriesColor, STATUS_VARS } from '../charts/common'
import { SegmentBar, type Segment } from '../charts/SegmentBar'
import { Panel } from '../dashboard/MetricWidget'
import { EmptyState } from '../ui/DataState'

interface DistributionAnalyticsProps {
  labels: {
    httpMix: string
    cacheMix: string
    decisionMix: string
    topDomains: string
    topClients: string
    topBlockedDomains: string
    noBlockedRequests: string
  }
  statusSegments: Segment[]
  cacheSegments: Segment[]
  decisionSegments: Segment[]
  topDomains: [string, number][]
  topClients: [string, number][]
  topBlocked: [string, number][]
}

export function DistributionAnalytics({
  labels,
  statusSegments,
  cacheSegments,
  decisionSegments,
  topDomains,
  topClients,
  topBlocked,
}: DistributionAnalyticsProps) {
  return (
    <>
      <div className="grid gap-6 lg:grid-cols-3">
        <Panel title={labels.httpMix}><SegmentBar segments={statusSegments} /></Panel>
        <Panel title={labels.cacheMix}><SegmentBar segments={cacheSegments} /></Panel>
        <Panel title={labels.decisionMix}><SegmentBar segments={decisionSegments} /></Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Panel title={labels.topDomains}>
          <BarList items={topDomains.map(([label, value]) => ({ label, value }))} />
        </Panel>
        <Panel title={labels.topClients}>
          <BarList items={topClients.map(([label, value]) => ({ label, value, color: seriesColor(1) }))} />
        </Panel>
        <Panel title={labels.topBlockedDomains}>
          {topBlocked.length === 0 ? (
            <EmptyState message={labels.noBlockedRequests} />
          ) : (
            <BarList
              items={topBlocked.map(([label, value]) => ({
                label,
                value,
                color: STATUS_VARS.critical,
              }))}
            />
          )}
        </Panel>
      </div>
    </>
  )
}
