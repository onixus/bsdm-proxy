import { X } from 'lucide-react'
import type { EnrichedLog } from '../../api/search'
import { BlockReasonBadge } from '../xai/ThreatIndicator'

interface LogDetailModalProps {
  log: EnrichedLog | null
  onClose: () => void
}

export function LogDetailModal({ log, onClose }: LogDetailModalProps) {
  if (!log) return null

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true">
      <button className="absolute inset-0" aria-label="Close" onClick={onClose} />
      <section className="relative z-10 max-h-[85vh] w-full max-w-3xl overflow-auto rounded-2xl border border-border bg-surface-1 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-text-primary">Log details</h2>
            <p className="mt-1 font-mono text-xs text-text-secondary">{log.event_id}</p>
          </div>
          <button type="button" className="rounded-md p-2 hover:bg-surface-2" onClick={onClose} aria-label="Close">
            <X className="size-5" />
          </button>
        </div>

        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          {Object.entries(log).map(([key, value]) => (
            <div key={key} className="rounded-lg border border-border bg-surface-0 p-3">
              <dt className="text-xs uppercase text-text-secondary">{key}</dt>
              <dd className="mt-1 break-all font-mono text-sm text-text-primary">
                {key === 'blockReason' ? <BlockReasonBadge reason={String(value ?? '')} /> : String(value ?? '—')}
              </dd>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
