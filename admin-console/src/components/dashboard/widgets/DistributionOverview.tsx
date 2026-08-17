import { BarChart3, Database, Shield } from 'lucide-react'
import type { Telemetry } from '../../../api/metrics'
import { SegmentBar } from '../../charts/SegmentBar'
import { Panel } from '../MetricWidget'
import { STATUS_VARS, cacheStatusColor, seriesColor } from '../../charts/common'
import { useT } from '../../../lib/i18n'

interface DistributionOverviewProps {
  telemetry: Telemetry
}

export function DistributionOverview({ telemetry }: DistributionOverviewProps) {
  const t = useT()

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <Panel title={t.widgets.httpStatuses} icon={BarChart3}>
        <SegmentBar segments={statusSegments(telemetry.statusClasses)} />
      </Panel>

      <Panel title={t.widgets.cacheStatuses} icon={Database}>
        <SegmentBar segments={cacheSegments(telemetry.cacheStatus)} />
      </Panel>

      <Panel title={t.widgets.aclDecisions} icon={Shield}>
        <SegmentBar
          segments={[
            { label: t.widgets.aclAllow, value: telemetry.aclDecisions.allow ?? 0, color: STATUS_VARS.good },
            {
              label: t.widgets.aclDeny,
              value: (telemetry.aclDecisions.deny ?? 0) + (telemetry.aclDecisions.block ?? 0),
              color: STATUS_VARS.critical,
            },
          ]}
        />
      </Panel>
    </div>
  )
}

function statusSegments(classes: Record<string, number>) {
  const palette: Record<string, string> = {
    '2xx': STATUS_VARS.good,
    '3xx': seriesColor(0),
    '4xx': STATUS_VARS.warning,
    '5xx': STATUS_VARS.critical,
  }

  return Object.entries(classes).map(([label, value]) => ({
    label,
    value,
    color: palette[label] ?? seriesColor(6),
  }))
}

function cacheSegments(cache: Record<string, number>) {
  return Object.entries(cache).map(([label, value]) => ({
    label,
    value,
    color: cacheStatusColor(label),
  }))
}
