import { useQuery } from '@tanstack/react-query'
import { Panel } from '../../../components/dashboard/MetricWidget'
import { fetchProxyStats, formatUptime } from '../../../api/metrics'
import { fetchUpstreamTls } from '../../../api/node'
import { useSourcedQuery } from '../../../hooks/useSourced'
import { translations, type Language } from '../../../lib/i18n'

function summarizeTls(tls: Record<string, unknown>): string {
  const entries = Object.entries(tls).slice(0, 3)
  if (entries.length === 0) return 'default'
  return entries.map(([k, v]) => `${k}=${String(v)}`).join(' · ')
}

type Copy = (typeof translations)[Language]

export function LiveNodePanel({ tr }: { tr: Copy }) {
  const stats = useQuery({
    queryKey: ['settings-stats'],
    queryFn: fetchProxyStats,
    refetchInterval: 30_000,
  })
  const tls = useSourcedQuery(['upstream-tls'], fetchUpstreamTls)
  const s = stats.data

  return (
    <Panel title={tr.settings.liveNodePanel}>
      {!s && (
        <p className="text-sm text-text-secondary">
          Control API unreachable — the generator below still works offline, but values shown here
          would confirm what the node actually runs with.
        </p>
      )}
      {s && (
        <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-xs text-text-secondary">{tr.settings.service}</dt>
            <dd className="font-mono text-xs text-text-primary">{s.service}</dd>
          </div>
          <div>
            <dt className="text-xs text-text-secondary">{tr.settings.uptime}</dt>
            <dd className="text-text-primary">{formatUptime(s.uptime_secs)}</dd>
          </div>
          <div>
            <dt className="text-xs text-text-secondary">{tr.settings.l1Cache}</dt>
            <dd className="tabular-nums text-text-primary">
              {s.cache.entries.toLocaleString()}/{s.cache.capacity.toLocaleString()} · {s.cache.shards}{' '}
              {tr.settings.shards}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-text-secondary">Upstream TLS</dt>
            <dd
              className="truncate font-mono text-xs text-text-primary"
              title={tls.data ? JSON.stringify(tls.data.data) : ''}
            >
              {tls.data ? summarizeTls(tls.data.data) : tls.isError ? 'unavailable' : '…'}
            </dd>
          </div>
        </dl>
      )}
    </Panel>
  )
}
