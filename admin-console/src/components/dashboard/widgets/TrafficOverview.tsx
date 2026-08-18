import { Activity, Database } from 'lucide-react'
import type { Telemetry } from '../../../api/metrics'
import { LineChart } from '../../charts/LineChart'
import { useT } from '../../../lib/i18n'
import { Panel } from '../MetricWidget'

interface TrafficOverviewProps {
  telemetry: Telemetry
}

export function TrafficOverview({ telemetry }: TrafficOverviewProps) {
  const t = useT()

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel title={t.widgets.requestRate} icon={Activity}>
        <LineChart
          series={[
            { name: t.widgets.seriesRequests, points: telemetry.reqRate, slot: 0 },
            { name: t.widgets.seriesAclDeny, points: telemetry.denyRate, slot: 1 },
            { name: t.widgets.seriesErrors, points: telemetry.errRate, slot: 7 },
          ]}
          area={false}
        />
      </Panel>

      <Panel title={t.widgets.hitRatioChart} icon={Database}>
        <LineChart
          series={[{ name: t.widgets.seriesHitRatio, points: telemetry.hitRatio, slot: 2 }]}
          area
          yMax={100}
          unit="%"
        />
      </Panel>
    </div>
  )
}
