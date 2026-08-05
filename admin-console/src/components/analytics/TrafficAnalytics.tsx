import type { TsPoint } from '../../lib/timeseries'
import { LineChart } from '../charts/LineChart'
import { Panel } from '../dashboard/MetricWidget'

interface TrafficAnalyticsProps {
  title: string
  allLabel: string
  blockedLabel: string
  all: TsPoint[]
  blocked: TsPoint[]
}

export function TrafficAnalytics({ title, allLabel, blockedLabel, all, blocked }: TrafficAnalyticsProps) {
  return (
    <Panel title={title}>
      <LineChart
        series={[
          { name: allLabel, points: all, slot: 0 },
          { name: blockedLabel, points: blocked, slot: 7 },
        ]}
        height={220}
      />
    </Panel>
  )
}
