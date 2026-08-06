import { Flame } from 'lucide-react'
import type { Telemetry } from '../../../api/metrics'
import { BarList } from '../../charts/BarList'
import { formatNumber } from '../../charts/common'
import { EmptyState } from '../../ui/DataState'
import { Panel } from '../MetricWidget'

interface UpstreamOverviewProps {
  telemetry: Telemetry
}

export function UpstreamOverview({ telemetry }: UpstreamOverviewProps) {
  return (
    <Panel title="Топ целевых серверов (Upstream Hosts)" icon={Flame}>
      {telemetry.topUpstreams.length === 0 ? (
        <EmptyState message="Метрики upstream отсутствуют — данные появятся при поступлении трафика." />
      ) : (
        <BarList
          items={telemetry.topUpstreams.map((upstream) => ({
            label: upstream.host,
            value: upstream.requests,
            extra: upstream.errors > 0 ? `${formatNumber(upstream.errors)} ошиб.` : undefined,
          }))}
        />
      )}
    </Panel>
  )
}
