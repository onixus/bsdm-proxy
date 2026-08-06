import type { EnrichedLog } from '../../api/search'

export function getStatusBadgeStyle(status?: number | string): string {
  if (!status) return 'border-border bg-surface-2 text-text-secondary'

  const code = Number(status)
  if (code >= 200 && code < 300) return 'border-success/30 bg-success/15 text-success'
  if (code >= 300 && code < 400) return 'border-blue-500/30 bg-blue-500/15 text-blue-400'
  if (code >= 400 && code < 500) return 'border-warning/30 bg-warning/15 text-warning'
  if (code >= 500) return 'border-danger/30 bg-danger/15 text-danger shadow-glow-danger'
  return 'border-border bg-surface-2 text-text-secondary'
}

export function distinct(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))].sort()
}

export function exportLogsCsv(rows: EnrichedLog[]): void {
  const header = [
    'ts',
    'time',
    'client_ip',
    'username',
    'method',
    'domain',
    'url',
    'status',
    'cache_status',
    'decision',
    'session_id',
    'event_id',
  ]
  const escapeCell = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...rows.map((log) =>
      [
        log.ts,
        new Date(log.ts * 1000).toISOString(),
        log.client_ip,
        log.username,
        log.method,
        log.domain,
        log.url,
        log.status,
        log.cache_status,
        log.blockReason,
        log.session_id,
        log.event_id,
      ]
        .map(escapeCell)
        .join(','),
    ),
  ]

  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `bsdm-logs-${new Date().toISOString().slice(0, 19)}.csv`
  anchor.click()
  URL.revokeObjectURL(url)
}
