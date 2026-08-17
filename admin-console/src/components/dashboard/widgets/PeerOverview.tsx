import { Network } from 'lucide-react'
import type { HierarchyPeer } from '../../../api/node'
import { useT } from '../../../lib/i18n'
import { StatusPill } from '../../ui/StatusPill'
import { EmptyState, SourceBadge } from '../../ui/DataState'
import { Panel } from '../MetricWidget'
import type { DataSource } from '../../../api/source'

interface PeerOverviewProps {
  peers?: HierarchyPeer[]
  source?: DataSource
  error?: boolean
}

export function PeerOverview({ peers, source, error }: PeerOverviewProps) {
  const t = useT()

  return (
    <Panel title={t.widgets.peers} icon={Network} action={source && <SourceBadge source={source} />}>
      {error && <EmptyState message={t.widgets.peersError} />}
      {peers && peers.length === 0 && <EmptyState message={t.widgets.peersEmpty} />}
      {peers && peers.length > 0 && (
        <ul className="divide-y divide-border/50 text-sm">
          {peers.map((peer, index) => (
            <li key={`${peer.name ?? peer.host ?? index}`} className="flex items-center justify-between gap-2 py-2.5">
              <div className="min-w-0">
                <p className="truncate font-mono text-xs font-semibold text-text-primary">{peer.name ?? peer.host ?? '—'}</p>
                <p className="truncate text-xs text-text-secondary">
                  {peer.peer_type ?? 'peer'} · {peer.host ?? ''}:{peer.http_port ?? ''}
                </p>
              </div>
              <StatusPill tone={peerTone(peer.state)} className="shrink-0">
                {peer.state ?? 'alive'}
              </StatusPill>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

/** A peer reported as down must not render in the healthy colour. */
function peerTone(state?: string) {
  const value = (state ?? 'alive').toLowerCase()
  if (value === 'down' || value === 'dead') return 'danger' as const
  if (value === 'alive' || value === 'up') return 'success' as const
  return 'neutral' as const
}
