import { ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { Telemetry } from '../../../api/metrics'
import { seriesColor, STATUS_VARS } from '../../charts/common'
import { SegmentBar, type Segment } from '../../charts/SegmentBar'
import { EmptyState } from '../../ui/DataState'
import { Panel } from '../MetricWidget'

interface DecisionSourcePanelProps {
  telemetry: Telemetry
}

export function DecisionSourcePanel({ telemetry }: DecisionSourcePanelProps) {
  return (
    <Panel
      title="Hybrid decision_source (dns / sni / mitm / pin)"
      icon={ShieldCheck}
      action={
        <Link to="/logs" className="text-xs font-semibold text-accent hover:underline">
          Open logs
        </Link>
      }
    >
      {Object.keys(telemetry.decisionSources).length === 0 ? (
        <EmptyState message="Счётчики decision_source появятся после HTTPS/DNS трафика через proxy (bsdm_proxy_policy_decision_source_total)." />
      ) : (
        <>
          <SegmentBar segments={decisionSourceSegments(telemetry.decisionSources)} />
          <p className="mt-3 text-xs text-text-secondary">
            Grafana: panel «Policy Decision Sources» · metric{' '}
            <code className="font-mono">bsdm_proxy_policy_decision_source_total</code>
          </p>
        </>
      )}
    </Panel>
  )
}

function decisionSourceSegments(sources: Record<string, number>): Segment[] {
  const palette: Record<string, string> = {
    dns: seriesColor(3),
    sni: seriesColor(0),
    mitm: seriesColor(1),
    'pinning-bypass': seriesColor(5),
    'auth-deny': STATUS_VARS.critical,
    bypass: seriesColor(6),
  }
  const order = ['dns', 'sni', 'mitm', 'pinning-bypass', 'auth-deny', 'bypass']

  return Object.entries(sources)
    .sort((a, b) => (order.indexOf(a[0]) + 99) - (order.indexOf(b[0]) + 99) || b[1] - a[1])
    .map(([label, value]) => ({
      label,
      value,
      color: palette[label] ?? seriesColor(4),
    }))
}
