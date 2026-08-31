import React, { useState } from 'react'
import {
  fetchDomainReputation,
  fetchDomainAnomaly,
  type DomainReputationScore,
  type DomainAnomalyReport,
} from '../../api/threatIntel'

export const MlDomainInspector: React.FC = () => {
  const [domainInput, setDomainInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [reputation, setReputation] = useState<DomainReputationScore | null>(null)
  const [anomaly, setAnomaly] = useState<DomainAnomalyReport | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleInspect = async (e: React.FormEvent) => {
    e.preventDefault()
    const target = domainInput.trim()
    if (!target) return
    setLoading(true)
    setError(null)
    setReputation(null)
    setAnomaly(null)

    try {
      const [rep, anom] = await Promise.all([
        fetchDomainReputation(target),
        fetchDomainAnomaly(target),
      ])
      setReputation(rep)
      setAnomaly(anom)
    } catch (err: any) {
      setError(err.message || 'Failed to inspect domain')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-sm">
      <div className="mb-6">
        <h3 className="text-lg font-semibold text-white">ML Phishing & Typosquatting Domain Inspector</h3>
        <p className="text-sm text-slate-400">
          Analyze suspicious domains using Damerau-Levenshtein brand distance, Unicode homoglyph detection, and Shannon entropy analysis.
        </p>
      </div>

      <form onSubmit={handleInspect} className="flex gap-3 mb-6">
        <input
          type="text"
          value={domainInput}
          onChange={(e) => setDomainInput(e.target.value)}
          placeholder="e.g. paypa1-login-verify.com, g00gle.ru, bank-auth.xyz"
          className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading || !domainInput.trim()}
          className="rounded-lg bg-sky-600 px-6 py-2.5 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-50 transition"
        >
          {loading ? 'Analyzing...' : 'Inspect Domain'}
        </button>
      </form>

      {error && (
        <div className="mb-6 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {(reputation || anomaly) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Reputation & Brand Squatting Card */}
          {reputation && (
            <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                <span className="text-sm font-semibold text-slate-200">Brand Typosquatting Analysis</span>
                <span
                  className={`inline-flex items-center rounded-md px-2.5 py-1 text-xs font-semibold ${
                    reputation.is_suspicious
                      ? 'bg-red-950 text-red-400 border border-red-800/40'
                      : 'bg-emerald-950 text-emerald-400 border border-emerald-800/40'
                  }`}
                >
                  {reputation.is_suspicious ? 'Suspicious Impersonation' : 'Normal / Low Risk'}
                </span>
              </div>

              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-400">Target Brand Impersonated:</span>
                  <span className="font-semibold text-amber-400">{reputation.target_brand || 'None Detected'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Risk Score:</span>
                  <span className="font-mono font-bold text-sky-400">{reputation.risk_score} / 100</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Unicode Homoglyphs:</span>
                  <span className={reputation.has_homoglyphs ? 'font-bold text-red-400' : 'text-slate-300'}>
                    {reputation.has_homoglyphs ? 'Yes (Cyrillic/Greek Mix)' : 'None'}
                  </span>
                </div>
                {reputation.damerau_distance !== undefined && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Damerau Edit Distance:</span>
                    <span className="font-mono text-slate-200">{reputation.damerau_distance}</span>
                  </div>
                )}
                {reputation.reasons.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-slate-800">
                    <span className="text-xs text-slate-400 uppercase tracking-wider block mb-1">Detections</span>
                    <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
                      {reputation.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Anomaly & Lexical Card */}
          {anomaly && (
            <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                <span className="text-sm font-semibold text-slate-200">Lexical & Entropy Analysis</span>
                <span
                  className={`inline-flex items-center rounded-md px-2.5 py-1 text-xs font-semibold ${
                    anomaly.is_anomalous
                      ? 'bg-amber-950 text-amber-400 border border-amber-800/40'
                      : 'bg-emerald-950 text-emerald-400 border border-emerald-800/40'
                  }`}
                >
                  {anomaly.is_anomalous ? 'Anomalous DGA / Structure' : 'Normal Lexical Structure'}
                </span>
              </div>

              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-400">Shannon Entropy:</span>
                  <span className="font-mono font-semibold text-sky-400">
                    {anomaly.shannon_entropy.toFixed(3)} bits
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Subdomain Depth:</span>
                  <span className="font-mono text-slate-200">{anomaly.subdomain_depth}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Digits Count:</span>
                  <span className="font-mono text-slate-200">{anomaly.digit_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Hyphens Count:</span>
                  <span className="font-mono text-slate-200">{anomaly.hyphen_count}</span>
                </div>
                {anomaly.reasons.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-slate-800">
                    <span className="text-xs text-slate-400 uppercase tracking-wider block mb-1">Anomaly Indicators</span>
                    <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
                      {anomaly.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
