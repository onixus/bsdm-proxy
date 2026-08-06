import { Activity, Database } from 'lucide-react'
import type { Telemetry } from '../../../api/metrics'
import { LineChart } from '../../charts/LineChart'
import { Panel } from '../MetricWidget'

interface TrafficOverviewProps {
  telemetry: Telemetry
}

export function TrafficOverview({ telemetry }: TrafficOverviewProps) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel title="Интенсивность запросов (запросов/сек / Request Rate)" icon={Activity}>
        <LineChart
          series={[
            { name: 'Запросы (Requests)', points: telemetry.reqRate, slot: 0 },
            { name: 'Блокировки ACL', points: telemetry.denyRate, slot: 1 },
            { name: 'Ошибки 5xx', points: telemetry.errRate, slot: 7 },
          ]}
          area={false}
        />
      </Panel>

      <Panel title="Эффективность попаданий в кэш (% Cache Hit Ratio)" icon={Database}>
        <LineChart
          series={[{ name: 'Hit ratio', points: telemetry.hitRatio, slot: 2 }]}
          area
          yMax={100}
          unit="%"
        />
      </Panel>
    </div>
  )
}
