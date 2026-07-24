import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, Search } from 'lucide-react'
import {
  factorsForThreatScore,
  fetchThreatScores,
  type ThreatScoreEntry,
} from '../api/threatScores'
import { useSourcedQuery } from '../hooks/useSourced'
import { useLanguage, translations } from '../lib/i18n'
import { Button } from '../components/ui/Button'
import { Panel } from '../components/dashboard/MetricWidget'
import { ErrorState, SourceBadge } from '../components/ui/DataState'
import { InsightPanel, ThreatIndicator } from '../components/xai/ThreatIndicator'
import { Modal } from '../components/ui/Modal'
import { severityBadge } from '../theme/tokens'

export function ThreatScoresPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]

  const result = useSourcedQuery(['threat-scores'], fetchThreatScores, { refetchInterval: 60_000 })
  const snapshot = result.data?.data ?? { scores: [] as ThreatScoreEntry[] }
  const loading = result.isFetching
  const [selected, setSelected] = useState<ThreatScoreEntry | null>(null)
  const [modelFilter, setModelFilter] = useState<string>('all')

  const models = useMemo(() => {
    const set = new Set(snapshot.scores.map((s) => s.model))
    return ['all', ...Array.from(set).sort()]
  }, [snapshot.scores])

  const rows = useMemo(() => {
    const filtered =
      modelFilter === 'all'
        ? snapshot.scores
        : snapshot.scores.filter((s) => s.model === modelFilter)
    return [...filtered].sort((a, b) => b.score - a.score)
  }, [snapshot.scores, modelFilter])

  const syncResult = useSourcedQuery(['threat-sync-peers'], () => import('../api/cluster').then(m => m.fetchThreatSyncPeers()), { refetchInterval: 15_000 })
  const syncData = syncResult.data?.data

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">{tr.threatScores.title}</h1>
            {result.data && <SourceBadge source={result.data.source} />}
          </div>
          <p className="text-sm text-text-secondary">
            {tr.threatScores.subtitle}
          </p>
          {'generated_at' in snapshot && snapshot.generated_at && (
            <p className="mt-1 font-mono text-xs text-text-secondary">
              {tr.threatScores.generated} {new Date(snapshot.generated_at).toLocaleString()}
            </p>
          )}
        </div>
        <Button variant="secondary" onClick={() => { result.refetch(); syncResult.refetch(); }} disabled={loading}>
          <RefreshCw className={`size-4 ${loading ? 'animate-spin' : ''}`} />
          {tr.threatScores.refresh}
        </Button>
      </div>

      <Panel title="Real-Time Threat Sync (P2P Cluster)">
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
            <div>
              <span className="text-text-secondary">Node ID: </span>
              <span className="font-mono font-semibold text-text-primary">{syncData?.node_id ?? 'local'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-text-secondary">Sync Bus: </span>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold ${syncData?.sync_enabled ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}`}>
                {syncData?.sync_enabled ? 'Redis Pub/Sub Active' : 'Standalone / Local'}
              </span>
            </div>
          </div>

          <div>
            <p className="text-xs font-medium text-text-secondary uppercase mb-2">Connected Cluster Peers</p>
            <div className="flex flex-wrap gap-2">
              {syncData?.peers.map((peer) => (
                <span key={peer} className="rounded border border-border-default bg-surface-hover/50 px-2.5 py-1 font-mono text-xs text-text-primary">
                  {peer}
                </span>
              ))}
            </div>
          </div>

          {syncData?.recent_events && syncData.recent_events.length > 0 && (
            <div>
              <p className="text-xs font-medium text-text-secondary uppercase mb-2">Recent Synchronized IoCs</p>
              <div className="space-y-2">
                {syncData.recent_events.map((evt) => (
                  <div key={evt.id} className="flex items-center justify-between p-2 rounded bg-surface-hover/30 border border-border-default/50 text-xs">
                    <div className="flex items-center gap-2 font-mono">
                      <span className="px-1.5 py-0.5 rounded bg-accent/10 text-accent font-semibold uppercase">{evt.ioc_type}</span>
                      <span className="text-text-primary">{evt.value}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-text-secondary">Action: <strong className="text-rose-400 font-mono">{evt.action}</strong></span>
                      <span className="text-text-secondary font-mono">Score: {(evt.threat_score * 100).toFixed(0)}%</span>
                      <span className="text-text-secondary font-mono text-[10px]">{evt.origin_node}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </Panel>

      {result.isError && (
        <ErrorState
          title={tr.threatScores.mlUnreachable}
          detail={result.error.message}
          onRetry={() => result.refetch()}
        />
      )}

      <div className="flex flex-wrap gap-2">
        {models.map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setModelFilter(m)}
            className={`touch-target rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
              modelFilter === m
                ? 'border-accent bg-accent/15 text-accent'
                : 'border-border text-text-secondary hover:bg-surface-2'
            }`}
          >
            {m === 'all' ? tr.threatScores.allModels : m}
          </button>
        ))}
      </div>

      <Panel title={`${tr.threatScores.activeScores} (${rows.length})`}>
        {rows.length === 0 ? (
          <p className="text-sm text-text-secondary">
            {tr.threatScores.noScores}
          </p>
        ) : (
          <>
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead className="border-b border-border text-xs uppercase text-text-secondary">
                  <tr>
                    <th className="px-3 py-2">{tr.threatScores.entity}</th>
                    <th className="px-3 py-2">{tr.threatScores.type}</th>
                    <th className="px-3 py-2">{tr.threatScores.score}</th>
                    <th className="px-3 py-2">{tr.threatScores.severity}</th>
                    <th className="px-3 py-2">{tr.threatScores.model}</th>
                    <th className="px-3 py-2">{tr.threatScores.expires}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr
                      key={`${row.entity_type}:${row.entity_id}:${row.model}`}
                      className="cursor-pointer border-b border-border/50 hover:bg-surface-2/50"
                      onClick={() => setSelected(row)}
                    >
                      <td className="max-w-[240px] truncate px-3 py-3 font-mono text-xs">{row.entity_id}</td>
                      <td className="px-3 py-3 text-xs text-text-secondary">{row.entity_type}</td>
                      <td className="px-3 py-3">
                        <ThreatIndicator score={row.score} size="sm" label="" />
                      </td>
                      <td className="px-3 py-3">
                        <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${severityBadge(row.severity)}`}>
                          {row.severity}
                        </span>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs">{row.model}</td>
                      <td className="px-3 py-3 font-mono text-xs text-text-secondary">{row.expires_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="space-y-3 md:hidden">
              {rows.map((row) => (
                <button
                  key={`${row.entity_type}:${row.entity_id}:${row.model}`}
                  type="button"
                  className="w-full rounded-lg border border-border bg-surface-1 p-4 text-left"
                  onClick={() => setSelected(row)}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-mono text-sm">{row.entity_id}</span>
                    <span className={`rounded-full border px-2 py-0.5 text-xs ${severityBadge(row.severity)}`}>
                      {row.severity}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-text-secondary">
                    {row.entity_type} · {row.model}
                  </p>
                  <div className="mt-2">
                    <ThreatIndicator score={row.score} size="sm" />
                  </div>
                </button>
              ))}
            </div>
          </>
        )}
      </Panel>

      <ScoreDetailModal tr={tr} entry={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

function ScoreDetailModal({
  tr,

  entry,
  onClose,
}: {
  tr: any
  entry: ThreatScoreEntry | null
  onClose: () => void
}) {
  if (!entry) return null
  const factors = factorsForThreatScore(entry)

  return (
    <Modal open onClose={onClose} title={tr.threatScores.explainabilityTitle} wide>
      <div className="space-y-4">
        <div className="grid gap-2 text-sm sm:grid-cols-2">
          <div>
            <span className="text-text-secondary">{tr.threatScores.entity}</span>
            <p className="font-mono font-medium text-text-primary">{entry.entity_id}</p>
          </div>
          <div>
            <span className="text-text-secondary">{tr.threatScores.type}</span>
            <p className="font-medium text-text-primary">{entry.entity_type}</p>
          </div>
        </div>
        <ThreatIndicator score={entry.score} size="lg" />
        <InsightPanel factors={factors} model={entry.model} />
        <Link
          to={`/logs?q=${encodeURIComponent(entry.entity_id.split('|').pop() ?? entry.entity_id)}`}
          className="inline-flex items-center gap-2 rounded-md border border-accent/40 bg-accent/10 px-3 py-2 text-sm font-medium text-accent hover:bg-accent/20"
        >
          <Search className="size-4" /> {tr.threatScores.investigateTraffic}
        </Link>
        <p className="text-xs text-text-secondary">
          {tr.threatScores.scoredAt} {entry.scored_at} · {tr.threatScores.expiresAt} {entry.expires_at}. Proxy enriches{' '}
          <code className="rounded bg-surface-0 px-1 font-mono">threat_sources</code> when{' '}
          <code className="rounded bg-surface-0 px-1 font-mono">THREAT_SCORE_ENABLED=true</code>.
        </p>
      </div>
    </Modal>
  )
}
