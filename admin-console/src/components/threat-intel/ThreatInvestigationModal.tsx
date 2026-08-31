import React, { useState, useEffect } from 'react'
import {
  investigateIndicator,
  unblockIndicator,
  blockIndicator,
  type SoarInvestigateResponse,
} from '../../api/threatIntel'

interface Props {
  query: string
  isOpen: boolean
  onClose: () => void
  onActionComplete?: () => void
}

export const ThreatInvestigationModal: React.FC<Props> = ({
  query,
  isOpen,
  onClose,
  onActionComplete,
}) => {
  const [data, setData] = useState<SoarInvestigateResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [actionSuccess, setActionSuccess] = useState<string | null>(null)
  const [unblockReason, setUnblockReason] = useState('False Positive Verified by SOC Analyst')
  const [isSubmitting, setIsSubmitting] = useState(false)

  useEffect(() => {
    if (!isOpen || !query) return
    setLoading(true)
    setError(null)
    setActionSuccess(null)
    investigateIndicator(query)
      .then((res) => setData(res))
      .catch((err) => setError(err.message || 'Failed to fetch indicator details'))
      .finally(() => setLoading(false))
  }, [isOpen, query])

  if (!isOpen) return null

  const handleUnblock = async () => {
    if (!query) return
    setIsSubmitting(true)
    setError(null)
    try {
      const res = await unblockIndicator({
        indicator: query,
        reason: unblockReason,
        operator: 'soc-console-operator',
      })
      setActionSuccess(`Successfully whitelisted: ${res.message}`)
      onActionComplete?.()
      // Refresh investigation data
      const updated = await investigateIndicator(query)
      setData(updated)
    } catch (err: any) {
      setError(err.message || 'Failed to unblock indicator')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleBlock = async () => {
    if (!query) return
    setIsSubmitting(true)
    setError(null)
    try {
      const res = await blockIndicator({
        indicator: query,
        kind: 'domain',
        reason: 'Manual containment via SOC Console',
        operator: 'soc-console-operator',
        ttl_secs: 86400,
      })
      setActionSuccess(`Blocked indicator: ${res.message} (Mode: ${res.mode})`)
      onActionComplete?.()
      const updated = await investigateIndicator(query)
      setData(updated)
    } catch (err: any) {
      setError(err.message || 'Failed to block indicator')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Threat Intelligence Investigation</h3>
            <p className="font-mono text-sm text-sky-400">{query}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="my-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
            {error}
          </div>
        )}

        {actionSuccess && (
          <div className="my-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-400">
            {actionSuccess}
          </div>
        )}

        <div className="my-4">
          {loading ? (
            <div className="flex justify-center py-8 text-slate-400">Loading intelligence data...</div>
          ) : data ? (
            <div className="space-y-4 text-sm text-slate-300">
              <div className="grid grid-cols-2 gap-4 rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider">Status</span>
                  <p className="mt-1 font-semibold">
                    {data.found ? (
                      <span className="inline-flex items-center rounded-md bg-red-950 px-2.5 py-0.5 text-xs font-medium text-red-400 border border-red-800/40">
                        Active Threat Indicator
                      </span>
                    ) : (
                      <span className="inline-flex items-center rounded-md bg-emerald-950 px-2.5 py-0.5 text-xs font-medium text-emerald-400 border border-emerald-800/40">
                        Clean / Not in Active Feeds
                      </span>
                    )}
                  </p>
                </div>
                <div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider">Indicator Type</span>
                  <p className="mt-1 font-mono uppercase text-slate-200">{data.kind}</p>
                </div>
                {data.indicator && (
                  <>
                    <div>
                      <span className="text-xs text-slate-400 uppercase tracking-wider">Feed Source</span>
                      <p className="mt-1 font-semibold text-amber-400">{data.indicator.source}</p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-400 uppercase tracking-wider">Confidence Score</span>
                      <p className="mt-1 font-semibold text-sky-400">
                        {data.indicator.confidence_score} / 100
                      </p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-400 uppercase tracking-wider">Total Hit Count</span>
                      <p className="mt-1 font-mono text-slate-200">{data.indicator.hit_count}</p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-400 uppercase tracking-wider">First Seen</span>
                      <p className="mt-1 text-slate-400">
                        {new Date(data.indicator.first_seen_unix * 1000).toLocaleString()}
                      </p>
                    </div>
                  </>
                )}
              </div>

              {data.found && (
                <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-4">
                  <label className="block text-xs font-medium text-slate-400 mb-2">
                    False Positive Whitelist Reason
                  </label>
                  <input
                    type="text"
                    value={unblockReason}
                    onChange={(e) => setUnblockReason(e.target.value)}
                    className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:outline-none"
                    placeholder="Enter reason for whitelisting..."
                  />
                </div>
              )}
            </div>
          ) : null}
        </div>

        <div className="flex items-center justify-between border-t border-slate-800 pt-4">
          <button
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm font-medium text-slate-300 hover:bg-slate-800"
          >
            Close
          </button>
          <div className="flex gap-2">
            {data?.found ? (
              <button
                onClick={handleUnblock}
                disabled={isSubmitting}
                className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50 shadow-sm"
              >
                {isSubmitting ? 'Processing...' : '1-Click Whitelist / Unblock FP'}
              </button>
            ) : (
              <button
                onClick={handleBlock}
                disabled={isSubmitting}
                className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50 shadow-sm"
              >
                {isSubmitting ? 'Processing...' : 'Manual Containment (Block)'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
