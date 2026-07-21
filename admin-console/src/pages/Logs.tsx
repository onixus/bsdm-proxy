import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Download, Play, Pause, RefreshCw, Search } from 'lucide-react'
import {
  applyLogFilters,
  emptyLogFilters,
  enrichLog,
  searchLogs,
  type EnrichedLog,
  type LogFilters,
} from '../api/search'
import { useSourcedQuery } from '../hooks/useSourced'
import { Button } from '../components/ui/Button'
import { Input, Select } from '../components/ui/Form'
import { Modal } from '../components/ui/Modal'
import { ErrorState, EmptyState, SkeletonRows, SourceBadge } from '../components/ui/DataState'
import { BlockReasonBadge, InsightPanel, ThreatIndicator } from '../components/xai/ThreatIndicator'

const PAGE_SIZE = 25
const TAIL_MS = 5_000

export function LogsPage() {
  const [searchParams, setSearchParams] = useSearchParams()

  // Server-side query (submitted on Search).
  const [domain, setDomain] = useState(searchParams.get('q') ?? '')
  const [username, setUsername] = useState('')
  const [days, setDays] = useState('7')
  const [limit, setLimit] = useState('200')
  const [query, setQuery] = useState({ domain: searchParams.get('q') ?? '', username: '', days: 7, limit: 200 })

  // Client-side filters (instant).
  const [filters, setFilters] = useState<LogFilters>(emptyLogFilters)
  const [tail, setTail] = useState(false)
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<EnrichedLog | null>(null)
  const [sessionFilter, setSessionFilter] = useState<string | null>(null)

  const result = useSourcedQuery(
    ['logs', query, sessionFilter],
    () =>
      searchLogs({
        domain: query.domain || undefined,
        username: query.username || undefined,
        session_id: sessionFilter ?? undefined,
        days: query.days,
        limit: query.limit,
      }),
    { refetchInterval: tail ? TAIL_MS : false },
  )

  const enriched = useMemo(
    () => (result.data?.data ?? []).map(enrichLog).sort((a, b) => b.ts - a.ts),
    [result.data],
  )
  const filtered = useMemo(() => applyLogFilters(enriched, filters), [enriched, filters])

  const methods = useMemo(() => distinct(enriched.map((l) => l.method?.toUpperCase())), [enriched])
  const cacheStatuses = useMemo(() => distinct(enriched.map((l) => l.cache_status)), [enriched])

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  const submit = () => {
    setPage(0)
    setSessionFilter(null)
    setQuery({ domain, username, days: Number(days) || 7, limit: Number(limit) || 200 })
    setSearchParams(domain ? { q: domain } : {})
  }

  const updateFilter = <K extends keyof LogFilters>(key: K, value: LogFilters[K]) => {
    setPage(0)
    setFilters((prev) => ({ ...prev, [key]: value }))
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">Traffic logs</h1>
            {result.data && <SourceBadge source={result.data.source} />}
          </div>
          <p className="text-sm text-text-secondary">
            Retro-search with client-side drill-down · click a row for decision details and session timeline
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant={tail ? 'primary' : 'secondary'} onClick={() => setTail((v) => !v)}>
            {tail ? <Pause className="size-4" /> : <Play className="size-4" />}
            {tail ? 'Tailing 5s' : 'Live tail'}
          </Button>
          <Button variant="secondary" onClick={() => exportCsv(filtered)} disabled={filtered.length === 0}>
            <Download className="size-4" /> CSV
          </Button>
        </div>
      </div>

      {/* Server-side query row */}
      <form
        className="grid gap-3 rounded-lg border border-border bg-surface-1 p-4 sm:grid-cols-2 lg:grid-cols-5"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <Input label="Domain" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <Input label="Username" placeholder="jdoe" value={username} onChange={(e) => setUsername(e.target.value)} />
        <Select
          label="Window"
          value={days}
          onChange={(e) => setDays(e.target.value)}
          options={[
            { value: '1', label: 'Last 24h' },
            { value: '7', label: 'Last 7 days' },
            { value: '30', label: 'Last 30 days' },
            { value: '90', label: 'Last 90 days' },
          ]}
        />
        <Select
          label="Fetch limit"
          value={limit}
          onChange={(e) => setLimit(e.target.value)}
          options={[
            { value: '100', label: '100 rows' },
            { value: '200', label: '200 rows' },
            { value: '500', label: '500 rows' },
            { value: '1000', label: '1000 rows' },
          ]}
        />
        <div className="flex items-end">
          <Button type="submit" disabled={result.isFetching} className="w-full">
            <Search className="size-4" /> Search
          </Button>
        </div>
      </form>

      {/* Client-side filter row */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Input
          label="Client IP contains"
          placeholder="10.0.1."
          value={filters.clientIp}
          onChange={(e) => updateFilter('clientIp', e.target.value)}
        />
        <Select
          label="Status class"
          value={filters.statusClass}
          onChange={(e) => updateFilter('statusClass', e.target.value)}
          options={[
            { value: 'all', label: 'All statuses' },
            { value: '2xx', label: '2xx success' },
            { value: '3xx', label: '3xx redirect' },
            { value: '4xx', label: '4xx client error' },
            { value: '5xx', label: '5xx server error' },
          ]}
        />
        <Select
          label="Method"
          value={filters.method}
          onChange={(e) => updateFilter('method', e.target.value)}
          options={[{ value: 'all', label: 'All methods' }, ...methods.map((m) => ({ value: m, label: m }))]}
        />
        <Select
          label="Cache status"
          value={filters.cacheStatus}
          onChange={(e) => updateFilter('cacheStatus', e.target.value)}
          options={[{ value: 'all', label: 'All' }, ...cacheStatuses.map((c) => ({ value: c, label: c }))]}
        />
        <Select
          label="Decision"
          value={filters.blockReason}
          onChange={(e) => updateFilter('blockReason', e.target.value)}
          options={[
            { value: 'all', label: 'All decisions' },
            { value: 'none', label: 'Allowed' },
            { value: 'acl', label: 'ACL blocked' },
            { value: 'ml', label: 'ML / UEBA blocked' },
            { value: 'threat', label: 'Threat intel blocked' },
          ]}
        />
      </div>

      {sessionFilter && (
        <div className="flex items-center gap-3 rounded-md border border-accent/40 bg-accent/10 px-4 py-2 text-sm">
          <span className="text-text-primary">
            Session <code className="font-mono text-accent">{sessionFilter}</code>
          </span>
          <button type="button" className="text-xs text-text-secondary underline" onClick={() => setSessionFilter(null)}>
            clear
          </button>
        </div>
      )}

      {result.isPending && <SkeletonRows rows={8} />}
      {result.isError && (
        <ErrorState title="Search API unreachable" detail={result.error.message} onRetry={() => result.refetch()} />
      )}
      {result.data && filtered.length === 0 && <EmptyState message="No log rows match the current query and filters." />}

      {filtered.length > 0 && (
        <>
          <div className="hidden overflow-x-auto rounded-lg border border-border md:block">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="border-b border-border bg-surface-2 text-xs uppercase text-text-secondary">
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
                {pageRows.map((log) => (
                  <tr
                    key={log.event_id ?? `${log.ts}-${log.url}`}
                    className="cursor-pointer border-b border-border/50 hover:bg-surface-2/50"
                    onClick={() => setSelected(log)}
                  >
                    <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-text-secondary">
                      {new Date(log.ts * 1000).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs">{log.client_ip ?? '—'}</td>
                    <td className="px-4 py-2.5 text-xs">{log.username ?? '—'}</td>
                    <td className="px-4 py-2.5 font-mono text-xs">{log.method ?? '—'}</td>
                    <td className="max-w-[220px] truncate px-4 py-2.5" title={log.url}>
                      {log.domain}
                    </td>
                    <td className="px-4 py-2.5 tabular-nums">{log.status ?? '—'}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">{log.cache_status ?? '—'}</td>
                    <td className="px-4 py-2.5">
                      <BlockReasonBadge reason={log.blockReason} />
                    </td>
                    <td className="px-4 py-2.5">
                      {log.session_id ? (
                        <button
                          type="button"
                          className="font-mono text-xs text-accent underline-offset-2 hover:underline"
                          onClick={(e) => {
                            e.stopPropagation()
                            setSessionFilter(log.session_id!)
                            setPage(0)
                          }}
                          title="Filter to this session"
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
            {pageRows.map((log) => (
              <button
                key={log.event_id ?? `${log.ts}-${log.url}`}
                type="button"
                className="w-full rounded-lg border border-border bg-surface-1 p-4 text-left"
                onClick={() => setSelected(log)}
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="font-medium text-text-primary">{log.domain}</span>
                  <BlockReasonBadge reason={log.blockReason} />
                </div>
                <p className="mt-1 font-mono text-xs text-text-secondary">
                  {log.client_ip} · {log.method} · HTTP {log.status} · {log.cache_status}
                </p>
                <p className="mt-1 text-xs text-text-secondary">{new Date(log.ts * 1000).toLocaleString()}</p>
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-text-secondary">
            <span>
              {filtered.length} rows{filtered.length !== enriched.length && ` (of ${enriched.length} fetched)`}
              {result.isFetching && <RefreshCw className="ml-2 inline size-3.5 animate-spin" />}
            </span>
            <div className="flex items-center gap-2">
              <Button variant="ghost" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                ← Prev
              </Button>
              <span className="tabular-nums">
                {page + 1} / {pages}
              </span>
              <Button variant="ghost" disabled={page >= pages - 1} onClick={() => setPage((p) => p + 1)}>
                Next →
              </Button>
            </div>
          </div>
        </>
      )}

      <LogDetailModal
        log={selected}
        related={selected?.session_id ? enriched.filter((l) => l.session_id === selected.session_id) : []}
        onClose={() => setSelected(null)}
        onOpenSession={(sid) => {
          setSelected(null)
          setSessionFilter(sid)
          setPage(0)
        }}
      />
    </div>
  )
}

function distinct(values: (string | undefined)[]): string[] {
  return [...new Set(values.filter((v): v is string => !!v))].sort()
}

function exportCsv(rows: EnrichedLog[]): void {
  const header = ['ts', 'time', 'client_ip', 'username', 'method', 'domain', 'url', 'status', 'cache_status', 'decision', 'session_id', 'event_id']
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...rows.map((l) =>
      [l.ts, new Date(l.ts * 1000).toISOString(), l.client_ip, l.username, l.method, l.domain, l.url, l.status, l.cache_status, l.blockReason, l.session_id, l.event_id]
        .map(esc)
        .join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `bsdm-logs-${new Date().toISOString().slice(0, 19)}.csv`
  a.click()
  URL.revokeObjectURL(a.href)
}

function LogDetailModal({
  log,
  related,
  onClose,
  onOpenSession,
}: {
  log: EnrichedLog | null
  related: EnrichedLog[]
  onClose: () => void
  onOpenSession: (sessionId: string) => void
}) {
  const isMl = log?.blockReason === 'ml'
  const timeline = [...related].sort((a, b) => a.ts - b.ts)

  return (
    <Modal open={!!log} onClose={onClose} title="Request decision details" wide>
      {log && (
        <div className="space-y-6">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <Field label="URL" mono breakAll>{log.url ?? '—'}</Field>
            <Field label="Client IP / user" mono>{`${log.client_ip ?? '—'}${log.username ? ` · ${log.username}` : ''}`}</Field>
            <Field label="Method / HTTP status">{`${log.method ?? '—'} · ${log.status ?? '—'}`}</Field>
            <Field label="Cache status" mono>{log.cache_status ?? '—'}</Field>
            <div>
              <dt className="text-text-secondary">Decision source</dt>
              <dd className="mt-1">
                <BlockReasonBadge reason={log.blockReason} />
              </dd>
            </div>
            <Field label="Event / parent" mono>
              {`${log.event_id ?? '—'}${log.parent_event_id ? ` ← ${log.parent_event_id}` : ''}`}
            </Field>
          </dl>

          {log.redirect_url && (
            <p className="rounded-md border border-warning/40 bg-warning/10 p-3 text-xs text-text-primary">
              Redirected to <code className="break-all font-mono">{log.redirect_url}</code>
            </p>
          )}

          {isMl && log.mlScore !== undefined && (
            <>
              <ThreatIndicator score={log.mlScore} size="lg" />
              <div>
                <h3 className="mb-3 text-sm font-semibold text-text-primary">Contributing factors</h3>
                <InsightPanel factors={log.mlFactors ?? []} model={log.mlModel} />
              </div>
            </>
          )}

          {log.blockReason === 'acl' && (
            <p className="rounded-md border border-border bg-surface-0 p-3 text-sm text-text-secondary">
              This request was blocked by an ACL category or domain rule. No ML scoring was applied.
            </p>
          )}

          {log.session_id && (
            <div>
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-text-primary">
                  Session timeline <code className="ml-1 font-mono text-xs text-text-secondary">{log.session_id}</code>
                </h3>
                <button
                  type="button"
                  className="text-xs text-accent underline-offset-2 hover:underline"
                  onClick={() => onOpenSession(log.session_id!)}
                >
                  Query full session
                </button>
              </div>
              {timeline.length <= 1 ? (
                <p className="text-xs text-text-secondary">
                  No other events for this session in the current result set — use “Query full session” to fetch it server-side.
                </p>
              ) : (
                <ol className="space-y-1.5 border-l border-border pl-4">
                  {timeline.map((ev) => (
                    <li key={ev.event_id ?? `${ev.ts}-${ev.url}`} className="relative text-xs">
                      <span
                        className={`absolute -left-[21px] top-1 size-2.5 rounded-full ${ev.event_id === log.event_id ? 'bg-accent' : 'bg-surface-3'}`}
                      />
                      <span className="font-mono text-text-secondary">
                        {new Date(ev.ts * 1000).toLocaleTimeString()}
                      </span>{' '}
                      <span className="text-text-primary">{ev.domain}</span>{' '}
                      <span className="text-text-secondary">
                        {ev.method} {ev.status}
                      </span>{' '}
                      {ev.blockReason !== 'none' && <BlockReasonBadge reason={ev.blockReason} />}
                      {ev.parent_event_id && (
                        <span className="ml-1 text-text-secondary">← {ev.parent_event_id}</span>
                      )}
                    </li>
                  ))}
                </ol>
              )}
            </div>
          )}
        </div>
      )}
    </Modal>
  )
}

function Field({
  label,
  children,
  mono,
  breakAll,
}: {
  label: string
  children: React.ReactNode
  mono?: boolean
  breakAll?: boolean
}) {
  return (
    <div>
      <dt className="text-text-secondary">{label}</dt>
      <dd className={`${mono ? 'font-mono text-xs' : ''} ${breakAll ? 'break-all' : ''} text-text-primary`}>
        {children}
      </dd>
    </div>
  )
}
