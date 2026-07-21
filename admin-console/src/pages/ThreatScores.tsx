import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, Search } from 'lucide-react'
import {
  factorsForThreatScore,
  fetchThreatScores,
  type ThreatScoreEntry,
} from '../api/threatScores'
import { useSourcedQuery } from '../hooks/useSourced'
import { Button } from '../components/ui/Button'
import { Panel } from '../components/dashboard/MetricWidget'
import { ErrorState, SourceBadge } from '../components/ui/DataState'
import { InsightPanel, ThreatIndicator } from '../components/xai/ThreatIndicator'
import { Modal } from '../components/ui/Modal'
import { severityBadge } from '../theme/tokens'

export function ThreatScoresPage() {
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

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">Threat scores</h1>
            {result.data && <SourceBadge source={result.data.source} />}
          </div>
          <p className="text-sm text-text-secondary">
            M5.5 write-back snapshot from ml-worker — proxy polls this async (O(1) hot path)
          </p>
          {'generated_at' in snapshot && snapshot.generated_at && (
            <p className="mt-1 font-mono text-xs text-text-secondary">
              Generated {new Date(snapshot.generated_at).toLocaleString()}
            </p>
          )}
        </div>
        <Button variant="secondary" onClick={() => result.refetch()} disabled={loading}>
          <RefreshCw className={`size-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {result.isError && (
        <ErrorState
          title="ML worker unreachable"
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
            {m === 'all' ? 'All models' : m}
          </button>
        ))}
      </div>

      <Panel title={`Active scores (${rows.length})`}>
        {rows.length === 0 ? (
          <p className="text-sm text-text-secondary">
            No scores in snapshot. Configure ml-worker with write-back enabled and ensure scoring cycles run.
          </p>
        ) : (
          <>
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead className="border-b border-border text-xs uppercase text-text-secondary">
                  <tr>
                    <th className="px-3 py-2">Entity</th>
                    <th className="px-3 py-2">Type</th>
                    <th className="px-3 py-2">Score</th>
                    <th className="px-3 py-2">Severity</th>
                    <th className="px-3 py-2">Model</th>
                    <th className="px-3 py-2">Expires</th>
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

      <ScoreDetailModal entry={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

function ScoreDetailModal({
  entry,
  onClose,
}: {
  entry: ThreatScoreEntry | null
  onClose: () => void
}) {
  if (!entry) return null
  const factors = factorsForThreatScore(entry)

  return (
    <Modal open onClose={onClose} title="Threat score explainability" wide>
      <div className="space-y-4">
        <div className="grid gap-2 text-sm sm:grid-cols-2">
          <div>
            <span className="text-text-secondary">Entity</span>
            <p className="font-mono font-medium text-text-primary">{entry.entity_id}</p>
          </div>
          <div>
            <span className="text-text-secondary">Type</span>
            <p className="font-medium text-text-primary">{entry.entity_type}</p>
          </div>
        </div>
        <ThreatIndicator score={entry.score} size="lg" />
        <InsightPanel factors={factors} model={entry.model} />
        <Link
          to={`/logs?q=${encodeURIComponent(entry.entity_id.split('|').pop() ?? entry.entity_id)}`}
          className="inline-flex items-center gap-2 rounded-md border border-accent/40 bg-accent/10 px-3 py-2 text-sm font-medium text-accent hover:bg-accent/20"
        >
          <Search className="size-4" /> Investigate related traffic
        </Link>
        <p className="text-xs text-text-secondary">
          Scored {entry.scored_at} · expires {entry.expires_at}. Proxy enriches{' '}
          <code className="rounded bg-surface-0 px-1 font-mono">threat_sources</code> when{' '}
          <code className="rounded bg-surface-0 px-1 font-mono">THREAT_SCORE_ENABLED=true</code>.
        </p>
      </div>
    </Modal>
  )
}
