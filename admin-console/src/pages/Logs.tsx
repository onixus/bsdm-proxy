import { useEffect, useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { useSearchParams } from 'react-router-dom'

import {
  applyLogFilters,
  emptyLogFilters,
  enrichLog,
  searchLogs,
  type EnrichedLog,
  type LogFilters,
} from '../api/search'
import { LogDetailModal } from '../components/logs/LogDetailModal'
import { LogFilters as LogFilterPanel } from '../components/logs/LogFilters'
import { LogResults } from '../components/logs/LogResults'
import { LogToolbar } from '../components/logs/LogToolbar'
import { distinct, exportLogsCsv } from '../components/logs/logUtils'
import { Button } from '../components/ui/Button'
import { EmptyState, ErrorState, SkeletonRows, SourceBadge } from '../components/ui/DataState'
import { Input, Select } from '../components/ui/Form'
import { useSourcedQuery } from '../hooks/useSourced'
import { translations, useLanguage } from '../lib/i18n'

const PAGE_SIZE = 25
const TAIL_MS = 5_000

export function LogsPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]
  const [searchParams, setSearchParams] = useSearchParams()
  const initialDecisionSource = searchParams.get('decision_source') ?? 'all'

  const [domain, setDomain] = useState(searchParams.get('q') ?? '')
  const [username, setUsername] = useState('')
  const [days, setDays] = useState('7')
  const [limit, setLimit] = useState('200')
  const [query, setQuery] = useState({
    domain: searchParams.get('q') ?? '',
    username: '',
    days: 7,
    limit: 200,
    decisionSource: initialDecisionSource === 'all' ? '' : initialDecisionSource,
  })
  const [filters, setFilters] = useState<LogFilters>({
    ...emptyLogFilters,
    decisionSource: initialDecisionSource,
  })
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
        decision_source: query.decisionSource || undefined,
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
  const methods = useMemo(() => distinct(enriched.map((log) => log.method?.toUpperCase())), [enriched])
  const cacheStatuses = useMemo(() => distinct(enriched.map((log) => log.cache_status)), [enriched])
  const decisionSources = useMemo(
    () =>
      distinct([
        'dns',
        'sni',
        'mitm',
        'pinning-bypass',
        ...enriched.map((log) => log.decision_source),
      ]),
    [enriched],
  )

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  useEffect(() => {
    if (page >= pages) setPage(pages - 1)
  }, [page, pages])

  const submit = () => {
    const decisionSource = filters.decisionSource === 'all' ? '' : filters.decisionSource
    setPage(0)
    setSessionFilter(null)
    setQuery({
      domain,
      username,
      days: Number(days) || 7,
      limit: Number(limit) || 200,
      decisionSource,
    })

    const next: Record<string, string> = {}
    if (domain) next.q = domain
    if (decisionSource) next.decision_source = decisionSource
    setSearchParams(next)
  }

  const updateFilter = <K extends keyof LogFilters>(key: K, value: LogFilters[K]) => {
    setPage(0)
    setFilters((previous) => ({ ...previous, [key]: value }))
  }

  const openSession = (sessionId: string) => {
    setSelected(null)
    setSessionFilter(sessionId)
    setPage(0)
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <LogToolbar
        title={tr.logs.title}
        subtitle={tr.logs.subtitle}
        source={result.data ? <SourceBadge source={result.data.source} /> : undefined}
        tail={tail}
        tailLabel={tr.logs.tailing}
        liveLabel={tr.logs.liveTail}
        exportLabel="CSV"
        canExport={filtered.length > 0}
        onToggleTail={() => setTail((value) => !value)}
        onExport={() => exportLogsCsv(filtered)}
      />

      <form
        className="grid gap-3 rounded-xl border border-border/80 bg-surface-1/90 p-4 backdrop-blur-sm sm:grid-cols-2 lg:grid-cols-5"
        onSubmit={(event) => {
          event.preventDefault()
          submit()
        }}
      >
        <Input
          label={tr.logs.domain}
          placeholder="example.com"
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
        />
        <Input
          label={tr.logs.username}
          placeholder="jdoe"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
        />
        <Select
          label={tr.logs.window}
          value={days}
          onChange={(event) => setDays(event.target.value)}
          options={[
            { value: '1', label: tr.logs.last24h },
            { value: '7', label: tr.logs.last7d },
            { value: '30', label: tr.logs.last30d },
            { value: '90', label: tr.logs.last90d },
          ]}
        />
        <Select
          label={tr.logs.fetchLimit}
          value={limit}
          onChange={(event) => setLimit(event.target.value)}
          options={[
            { value: '100', label: tr.logs.rows100 },
            { value: '200', label: tr.logs.rows200 },
            { value: '500', label: tr.logs.rows500 },
            { value: '1000', label: tr.logs.rows1000 },
          ]}
        />
        <div className="flex items-end">
          <Button type="submit" disabled={result.isFetching} className="w-full">
            <Search className="size-4" /> {tr.common.search.replace('...', '')}
          </Button>
        </div>
      </form>

      <LogFilterPanel
        filters={filters}
        methods={methods}
        cacheStatuses={cacheStatuses}
        decisionSources={decisionSources}
        labels={{
          quick: tr.logs.quickFilter,
          allEvents: tr.logs.allEvents,
          serverErrors: tr.logs.serverErrors,
          aclBlocked: tr.logs.aclBlocked,
          mlBlocked: tr.logs.mlBlocked,
          cacheMiss: 'Cache MISS',
          clientIp: tr.logs.clientIp,
          statusClass: tr.logs.statusClass,
          allStatuses: tr.logs.allStatuses,
          success2xx: tr.logs.success2xx,
          redirect3xx: tr.logs.redirect3xx,
          clientErr4xx: tr.logs.clientErr4xx,
          serverErr5xx: tr.logs.serverErr5xx,
          method: tr.logs.method,
          allMethods: tr.logs.allMethods,
          cacheStatus: tr.logs.cacheStatus,
          all: tr.logs.all,
          decision: tr.logs.decision,
          allDecisions: tr.logs.allDecisions,
          allowed: tr.logs.allowed,
          threatBlocked: tr.logs.threatBlocked,
          decisionSource: 'decision_source',
        }}
        onChange={updateFilter}
        onReset={() => {
          setPage(0)
          setFilters(emptyLogFilters)
        }}
      />

      {sessionFilter && (
        <div className="flex items-center gap-3 rounded-md border border-accent/40 bg-accent/10 px-4 py-2 text-sm">
          <span className="text-text-primary">
            {tr.logs.session} <code className="font-mono text-accent">{sessionFilter}</code>
          </span>
          <button
            type="button"
            className="text-xs text-text-secondary underline"
            onClick={() => setSessionFilter(null)}
          >
            {tr.logs.clear}
          </button>
        </div>
      )}

      {result.isPending && <SkeletonRows rows={8} />}
      {result.isError && (
        <ErrorState title={tr.logs.apiErrorTitle} detail={result.error.message} onRetry={() => result.refetch()} />
      )}
      {result.data && filtered.length === 0 && <EmptyState message={tr.logs.emptyMessage} />}

      {filtered.length > 0 && (
        <LogResults
          rows={pageRows}
          filteredCount={filtered.length}
          fetchedCount={enriched.length}
          page={page}
          pages={pages}
          isFetching={result.isFetching}
          onPageChange={setPage}
          onSelect={setSelected}
          onOpenSession={openSession}
        />
      )}

      <LogDetailModal
        log={selected}
        related={selected?.session_id ? enriched.filter((log) => log.session_id === selected.session_id) : []}
        onClose={() => setSelected(null)}
        onOpenSession={openSession}
      />
    </div>
  )
}
