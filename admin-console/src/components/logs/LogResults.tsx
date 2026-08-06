import { RefreshCw } from 'lucide-react'
import type { EnrichedLog } from '../../api/search'
import { BlockReasonBadge } from '../xai/ThreatIndicator'
import { Button } from '../ui/Button'
import { getStatusBadgeStyle } from './logUtils'

interface LogResultsProps {
  rows: EnrichedLog[]
  filteredCount: number
  fetchedCount: number
  page: number
  pages: number
  isFetching: boolean
  onPageChange: (page: number) => void
  onSelect: (log: EnrichedLog) => void
  onOpenSession: (sessionId: string) => void
}

export function LogResults({
  rows,
  filteredCount,
  fetchedCount,
  page,
  pages,
  isFetching,
  onPageChange,
  onSelect,
  onOpenSession,
}: LogResultsProps) {
  return (
    <>
      <div className="hidden overflow-x-auto rounded-xl border border-border/80 bg-surface-1/90 md:block">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="border-b border-border bg-surface-2/70 text-xs font-bold uppercase text-text-secondary">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Client</th>
              <th className="px-4 py-3">User</th>
              <th className="px-4 py-3">Method</th>
              <th className="px-4 py-3">Domain</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Cache</th>
              <th className="px-4 py-3">Decision</th>
              <th className="px-4 py-3">Session</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((log) => (
              <tr
                key={log.event_id ?? `${log.ts}-${log.url}`}
                className="cursor-pointer border-b border-border/40 transition-colors hover:bg-surface-2/60"
                onClick={() => onSelect(log)}
              >
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-text-secondary">
                  {new Date(log.ts * 1000).toLocaleString()}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs font-medium text-text-primary">{log.client_ip ?? '—'}</td>
                <td className="px-4 py-2.5 text-xs">{log.username ?? '—'}</td>
                <td className="px-4 py-2.5 font-mono text-xs font-semibold text-text-primary">{log.method ?? '—'}</td>
                <td className="max-w-[220px] truncate px-4 py-2.5 font-medium" title={log.url}>
                  {log.domain}
                </td>
                <td className="px-4 py-2.5">
                  <span className={`inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-xs font-bold ${getStatusBadgeStyle(log.status)}`}>
                    {log.status ?? '—'}
                  </span>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">{log.cache_status ?? '—'}</td>
                <td className="px-4 py-2.5"><BlockReasonBadge reason={log.blockReason} /></td>
                <td className="px-4 py-2.5">
                  {log.session_id ? (
                    <button
                      type="button"
                      className="font-mono text-xs text-accent underline-offset-2 hover:underline"
                      onClick={(event) => {
                        event.stopPropagation()
                        onOpenSession(log.session_id!)
                      }}
                    >
                      {log.session_id.slice(0, 10)}
                    </button>
                  ) : (
                    <span className="text-xs text-text-secondary">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="space-y-3 md:hidden">
        {rows.map((log) => (
          <button
            key={log.event_id ?? `${log.ts}-${log.url}`}
            type="button"
            className="w-full rounded-lg border border-border bg-surface-1 p-4 text-left"
            onClick={() => onSelect(log)}
          >
            <div className="flex items-start justify-between gap-2">
              <span className="font-medium text-text-primary">{log.domain}</span>
              <BlockReasonBadge reason={log.blockReason} />
            </div>
            <p className="mt-1 font-mono text-xs text-text-secondary">
              {log.client_ip ?? '—'} · {log.method ?? '—'} · HTTP {log.status ?? '—'} · {log.cache_status ?? '—'}
            </p>
            <p className="mt-1 text-xs text-text-secondary">{new Date(log.ts * 1000).toLocaleString()}</p>
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-text-secondary">
        <span>
          {filteredCount} rows{filteredCount !== fetchedCount ? ` (of ${fetchedCount} fetched)` : ''}
          {isFetching && <RefreshCw className="ml-2 inline size-3.5 animate-spin" />}
        </span>
        <div className="flex items-center gap-2">
          <Button variant="ghost" disabled={page === 0} onClick={() => onPageChange(page - 1)}>← Prev</Button>
          <span className="tabular-nums">{page + 1} / {pages}</span>
          <Button variant="ghost" disabled={page >= pages - 1} onClick={() => onPageChange(page + 1)}>Next →</Button>
        </div>
      </div>
    </>
  )
}
