import { Input, Select } from '../ui/Form'
import type { LogFilters as Filters } from '../../api/search'

interface LogFiltersProps {
  filters: Filters
  methods: string[]
  cacheStatuses: string[]
  decisionSources: string[]
  onChange: <K extends keyof Filters>(key: K, value: Filters[K]) => void
  decisionSource: string
  onDecisionSourceChange: (value: string) => void
}

export function LogFilters({
  filters,
  methods,
  cacheStatuses,
  decisionSources,
  onChange,
  decisionSource,
  onDecisionSourceChange,
}: LogFiltersProps) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      <Input label="Client IP" value={filters.clientIp} onChange={(e) => onChange('clientIp', e.target.value)} />
      <Select
        label="Status"
        value={filters.statusClass}
        onChange={(e) => onChange('statusClass', e.target.value)}
        options={['all', '2xx', '3xx', '4xx', '5xx'].map((value) => ({ value, label: value }))}
      />
      <Select
        label="Method"
        value={filters.method}
        onChange={(e) => onChange('method', e.target.value)}
        options={[{ value: 'all', label: 'all' }, ...methods.map((value) => ({ value, label: value }))]}
      />
      <Select
        label="Cache"
        value={filters.cacheStatus}
        onChange={(e) => onChange('cacheStatus', e.target.value)}
        options={[{ value: 'all', label: 'all' }, ...cacheStatuses.map((value) => ({ value, label: value }))]}
      />
      <Select
        label="Decision source"
        value={decisionSource}
        onChange={(e) => onDecisionSourceChange(e.target.value)}
        options={[{ value: 'all', label: 'all' }, ...decisionSources.map((value) => ({ value, label: value }))]}
      />
    </div>
  )
}
