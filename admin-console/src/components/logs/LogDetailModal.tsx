import type { ReactNode } from 'react'
import type { EnrichedLog } from '../../api/search'
import { Modal } from '../ui/Modal'
import { BlockReasonBadge, InsightPanel, ThreatIndicator } from '../xai/ThreatIndicator'

interface LogDetailModalProps {
  log: EnrichedLog | null
  related: EnrichedLog[]
  onClose: () => void
  onOpenSession: (sessionId: string) => void
}

export function LogDetailModal({ log, related, onClose, onOpenSession }: LogDetailModalProps) {
  const isMl = log?.blockReason === 'ml'
  const timeline = [...related].sort((a, b) => a.ts - b.ts)

  return (
    <Modal open={Boolean(log)} onClose={onClose} title="Request decision details" wide>
      {log && (
        <div className="space-y-6">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <Field label="URL" mono breakAll>{log.url ?? '—'}</Field>
            <Field label="Client IP / user" mono>
              {`${log.client_ip ?? '—'}${log.username ? ` · ${log.username}` : ''}`}
            </Field>
            <Field label="Method / HTTP status">{`${log.method ?? '—'} · ${log.status ?? '—'}`}</Field>
            <Field label="Cache status" mono>{log.cache_status ?? '—'}</Field>
            <div>
              <dt className="text-text-secondary">Decision</dt>
              <dd className="mt-1"><BlockReasonBadge reason={log.blockReason} /></dd>
            </div>
            <Field label="Decision source" mono>{log.decision_source ?? '—'}</Field>
            <Field label="Event / parent" mono>
              {`${log.event_id ?? '—'}${log.parent_event_id ? ` ← ${log.parent_event_id}` : ''}`}
            </Field>
            <Field label="Timestamp" mono>{new Date(log.ts * 1000).toLocaleString()}</Field>
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
            <section>
              <div className="mb-2 flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold text-text-primary">
                  Session timeline{' '}
                  <code className="font-mono text-xs text-text-secondary">{log.session_id}</code>
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
                  No other events for this session in the current result set. Query the full session to fetch it server-side.
                </p>
              ) : (
                <ol className="space-y-1.5 border-l border-border pl-4">
                  {timeline.map((event) => (
                    <li key={event.event_id ?? `${event.ts}-${event.url}`} className="relative text-xs">
                      <span
                        className={`absolute -left-[21px] top-1 size-2.5 rounded-full ${
                          event.event_id === log.event_id ? 'bg-accent' : 'bg-surface-3'
                        }`}
                      />
                      <span className="font-mono text-text-secondary">
                        {new Date(event.ts * 1000).toLocaleTimeString()}
                      </span>{' '}
                      <span className="text-text-primary">{event.domain}</span>{' '}
                      <span className="text-text-secondary">{event.method} {event.status}</span>{' '}
                      {event.blockReason !== 'none' && <BlockReasonBadge reason={event.blockReason} />}
                      {event.parent_event_id && (
                        <span className="ml-1 text-text-secondary">← {event.parent_event_id}</span>
                      )}
                    </li>
                  ))}
                </ol>
              )}
            </section>
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
  children: ReactNode
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
