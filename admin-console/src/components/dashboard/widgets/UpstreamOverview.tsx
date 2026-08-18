import { Flame } from 'lucide-react'
import type { Telemetry } from '../../../api/metrics'
import { BarList } from '../../charts/BarList'
import { formatNumber } from '../../charts/common'
import { fmt, useT } from '../../../lib/i18n'
import { EmptyState } from '../../ui/DataState'
import { Panel } from '../MetricWidget'

interface UpstreamOverviewProps {
  telemetry: Telemetry
}

export function UpstreamOverview({ telemetry }: UpstreamOverviewProps) {
  const t = useT()

  return (
    <Panel title={t.widgets.upstreams} icon={Flame}>
      {telemetry.topUpstreams.length === 0 ? (
        <EmptyState message={t.widgets.upstreamsEmpty} />
      ) : (
        <BarList
          items={telemetry.topUpstreams.map((upstream) => ({
            label: upstream.host,
            value: upstream.requests,
            extra:
              upstream.errors > 0
                ? fmt(t.widgets.upstreamErrors, { count: formatNumber(upstream.errors) })
                : undefined,
          }))}
        />
      )}
    </Panel>
  )
}
