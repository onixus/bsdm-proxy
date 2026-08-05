import type { LogFilters as Filters } from '../../api/search'
import { Input, Select } from '../ui/Form'

interface LogFilterLabels {
  quick: string
  allEvents: string
  serverErrors: string
  aclBlocked: string
  mlBlocked: string
  cacheMiss: string
  clientIp: string
  statusClass: string
  allStatuses: string
  success2xx: string
  redirect3xx: string
  clientErr4xx: string
  serverErr5xx: string
  method: string
  allMethods: string
  cacheStatus: string
  all: string
  decision: string
  allDecisions: string
  allowed: string
  threatBlocked: string
  decisionSource: string
}

interface LogFiltersProps {
  filters: Filters
  methods: string[]
  cacheStatuses: string[]
  decisionSources: string[]
  labels: LogFilterLabels
  onChange: <K extends keyof Filters>(key: K, value: Filters[K]) => void
  onReset: () => void
}

export function LogFilters({
  filters,
  methods,
  cacheStatuses,
  decisionSources,
  labels,
  onChange,
  onReset,
}: LogFiltersProps) {
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border/80 bg-surface-1/60 p-3">
        <span className="mr-1 text-xs font-bold uppercase tracking-wider text-text-secondary">{labels.quick}</span>
        <QuickFilter active={isDefault(filters)} onClick={onReset}>{labels.allEvents}</QuickFilter>
        <QuickFilter active={filters.statusClass === '5xx'} tone="danger" onClick={() => onChange('statusClass', '5xx')}>
          {labels.serverErrors}
        </QuickFilter>
        <QuickFilter active={filters.blockReason === 'acl'} tone="warning" onClick={() => onChange('blockReason', 'acl')}>
          {labels.aclBlocked}
        </QuickFilter>
        <QuickFilter active={filters.blockReason === 'ml'} tone="accent" onClick={() => onChange('blockReason', 'ml')}>
          {labels.mlBlocked}
        </QuickFilter>
        <QuickFilter active={filters.cacheStatus === 'MISS'} tone="accent" onClick={() => onChange('cacheStatus', 'MISS')}>
          {labels.cacheMiss}
        </QuickFilter>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
        <Input
          label={labels.clientIp}
          placeholder="10.0.1."
          value={filters.clientIp}
          onChange={(event) => onChange('clientIp', event.target.value)}
        />
        <Select
          label={labels.statusClass}
          value={filters.statusClass}
          onChange={(event) => onChange('statusClass', event.target.value)}
          options={[
            { value: 'all', label: labels.allStatuses },
            { value: '2xx', label: labels.success2xx },
            { value: '3xx', label: labels.redirect3xx },
            { value: '4xx', label: labels.clientErr4xx },
            { value: '5xx', label: labels.serverErr5xx },
          ]}
        />
        <Select
          label={labels.method}
          value={filters.method}
          onChange={(event) => onChange('method', event.target.value)}
          options={[{ value: 'all', label: labels.allMethods }, ...methods.map((value) => ({ value, label: value }))]}
        />
        <Select
          label={labels.cacheStatus}
          value={filters.cacheStatus}
          onChange={(event) => onChange('cacheStatus', event.target.value)}
          options={[{ value: 'all', label: labels.all }, ...cacheStatuses.map((value) => ({ value, label: value }))]}
        />
        <Select
          label={labels.decision}
          value={filters.blockReason}
          onChange={(event) => onChange('blockReason', event.target.value)}
          options={[
            { value: 'all', label: labels.allDecisions },
            { value: 'none', label: labels.allowed },
            { value: 'acl', label: labels.aclBlocked },
            { value: 'ml', label: labels.mlBlocked },
            { value: 'threat', label: labels.threatBlocked },
          ]}
        />
        <Select
          label={labels.decisionSource}
          value={filters.decisionSource}
          onChange={(event) => onChange('decisionSource', event.target.value)}
          options={[
            { value: 'all', label: labels.all },
            ...decisionSources.map((value) => ({ value, label: value })),
          ]}
        />
      </div>
    </section>
  )
}

function isDefault(filters: Filters): boolean {
  return (
    filters.clientIp === '' &&
    filters.statusClass === 'all' &&
    filters.method === 'all' &&
    filters.cacheStatus === 'all' &&
    filters.blockReason === 'all' &&
    filters.decisionSource === 'all'
  )
}

function QuickFilter({
  active,
  tone = 'default',
  onClick,
  children,
}: {
  active: boolean
  tone?: 'default' | 'danger' | 'warning' | 'accent'
  onClick: () => void
  children: string
}) {
  const activeClass = {
    default: 'border-accent bg-accent/20 text-accent',
    danger: 'border-danger bg-danger/20 text-danger',
    warning: 'border-warning bg-warning/20 text-warning',
    accent: 'border-accent bg-accent/20 text-accent',
  }[tone]

  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-lg border px-3 py-1 text-xs font-semibold transition-colors ${
        active
          ? activeClass
          : 'border-border bg-surface-0 text-text-secondary hover:bg-surface-2 hover:text-text-primary'
      }`}
    >
      {children}
    </button>
  )
}
