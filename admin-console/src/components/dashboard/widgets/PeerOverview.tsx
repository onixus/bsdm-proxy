import { Network } from 'lucide-react'
import type { HierarchyPeer } from '../../../api/node'
import { EmptyState, SourceBadge } from '../../ui/DataState'
import { Panel } from '../MetricWidget'
import type { DataSource } from '../../../api/source'

interface PeerOverviewProps {
  peers?: HierarchyPeer[]
  source?: DataSource
  error?: boolean
}

export function PeerOverview({ peers, source, error }: PeerOverviewProps) {
  return (
    <Panel title="Ноды иерархии кэша (ICP/HTCP)" icon={Network} action={source && <SourceBadge source={source} />}>
      {error && <EmptyState message="API иерархии недоступно или отключено." />}
      {peers && peers.length === 0 && <EmptyState message="Соседние ноды кэширования не настроены." />}
      {peers && peers.length > 0 && (
        <ul className="divide-y divide-border/50 text-sm">
          {peers.map((peer, index) => (
            <li key={`${peer.name ?? peer.host ?? index}`} className="flex items-center justify-between gap-2 py-2.5">
              <div className="min-w-0">
                <p className="truncate font-mono text-xs font-semibold text-text-primary">{peer.name ?? peer.host ?? '—'}</p>
                <p className="text-xs text-text-secondary">{peer.peer_type ?? 'peer'} · {peer.host ?? ''}:{peer.http_port ?? ''}</p>
              </div>
              <span className="rounded-full border border-success/40 bg-success/10 px-2 py-0.5 text-xs font-semibold text-success">
                {peer.state ?? 'alive'}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
