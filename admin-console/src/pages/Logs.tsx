import { useCallback, useEffect, useState } from 'react'
import { RefreshCw, Search } from 'lucide-react'
import { searchLogs, enrichLog, type EnrichedLog } from '../api/search'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Form'
import { Modal } from '../components/ui/Modal'
import { BlockReasonBadge, InsightPanel, ThreatIndicator } from '../components/xai/ThreatIndicator'

export function LogsPage() {
  const [domain, setDomain] = useState('')
  const [logs, setLogs] = useState<EnrichedLog[]>([])
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<EnrichedLog | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    const raw = await searchLogs({ domain: domain || undefined, limit: 50 })
    setLogs(raw.map(enrichLog))
    setLoading(false)
  }, [domain])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Traffic logs</h1>
        <p className="text-sm text-text-secondary">
          Retro-search via Search API — click a denied row for ML explainability
        </p>
      </div>

      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="flex-1">
          <Input
            label="Domain filter"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
        </div>
        <div className="flex items-end">
          <Button onClick={load} disabled={loading} className="w-full sm:w-auto">
            <Search className="size-4" />
            Search
          </Button>
        </div>
      </div>

      {/* Desktop table */}
      <div className="hidden overflow-x-auto rounded-lg border border-border md:block">
        <table className="w-full min-w-[640px] text-left text-sm">
          <thead className="border-b border-border bg-surface-2 text-xs uppercase text-text-secondary">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Client</th>
              <th className="px-4 py-3">Domain</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Block</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr
                key={log.event_id ?? `${log.ts}-${log.url}`}
                className={`border-b border-border/50 hover:bg-surface-2/50 ${log.blockReason !== 'none' ? 'cursor-pointer' : ''}`}
                onClick={() => log.blockReason !== 'none' && setSelected(log)}
              >
                <td className="px-4 py-3 font-mono text-xs text-text-secondary">
                  {new Date(log.ts * 1000).toLocaleString()}
                </td>
                <td className="px-4 py-3 font-mono text-xs">{log.client_ip ?? '—'}</td>
                <td className="max-w-[200px] truncate px-4 py-3">{log.domain}</td>
                <td className="px-4 py-3">{log.status}</td>
                <td className="px-4 py-3">
                  <BlockReasonBadge reason={log.blockReason} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Mobile card list */}
      <div className="space-y-3 md:hidden">
        {logs.map((log) => (
          <button
            key={log.event_id ?? `${log.ts}-${log.url}`}
            type="button"
            className="w-full rounded-lg border border-border bg-surface-1 p-4 text-left"
            onClick={() => log.blockReason !== 'none' && setSelected(log)}
            disabled={log.blockReason === 'none'}
          >
            <div className="flex items-start justify-between gap-2">
              <span className="font-medium text-text-primary">{log.domain}</span>
              <BlockReasonBadge reason={log.blockReason} />
            </div>
            <p className="mt-1 font-mono text-xs text-text-secondary">{log.client_ip}</p>
            <p className="mt-1 text-xs text-text-secondary">
              {new Date(log.ts * 1000).toLocaleString()} · HTTP {log.status}
            </p>
          </button>
        ))}
      </div>

      {loading && (
        <div className="flex justify-center py-8">
          <RefreshCw className="size-6 animate-spin text-text-secondary" />
        </div>
      )}

      <LogDetailModal log={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

function LogDetailModal({ log, onClose }: { log: EnrichedLog | null; onClose: () => void }) {
  const isMl = log?.blockReason === 'ml'

  return (
    <Modal
      open={!!log}
      onClose={onClose}
      title="Request decision details"
      wide
    >
      {log && (
        <div className="space-y-6">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-text-secondary">URL</dt>
              <dd className="break-all font-mono text-xs text-text-primary">{log.url}</dd>
            </div>
            <div>
              <dt className="text-text-secondary">Client IP</dt>
              <dd className="font-mono">{log.client_ip}</dd>
            </div>
            <div>
              <dt className="text-text-secondary">Decision source</dt>
              <dd className="mt-1">
                <BlockReasonBadge reason={log.blockReason} />
              </dd>
            </div>
            <div>
              <dt className="text-text-secondary">HTTP status</dt>
              <dd>{log.status}</dd>
            </div>
          </dl>

          {isMl && log.mlScore !== undefined && (
            <>
              <ThreatIndicator score={log.mlScore} size="lg" />
              <div>
                <h3 className="mb-3 text-sm font-semibold text-text-primary">
                  Contributing factors
                </h3>
                <InsightPanel factors={log.mlFactors ?? []} model={log.mlModel} />
              </div>
            </>
          )}

          {log.blockReason === 'acl' && (
            <p className="rounded-md border border-border bg-surface-0 p-3 text-sm text-text-secondary">
              This request was blocked by an ACL category or domain rule. No ML scoring was applied.
            </p>
          )}
        </div>
      )}
    </Modal>
  )
}
