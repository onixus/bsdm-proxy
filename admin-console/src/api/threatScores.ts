import { loadApiSettings } from './settings'
import { apiFetch } from './client'
import type { MlFactor } from './search'

export interface ThreatScoreEntry {
  entity_type: string
  entity_id: string
  score: number
  severity: string
  model: string
  scored_at: string
  expires_at: string
}

export interface ThreatScoreSnapshot {
  generated_at?: string
  scores: ThreatScoreEntry[]
}

export async function fetchThreatScores(): Promise<ThreatScoreSnapshot> {
  const settings = loadApiSettings()
  try {
    return await apiFetch<ThreatScoreSnapshot>('/api/threat-scores', {
      baseUrl: settings.mlBaseUrl,
    })
  } catch {
    return mockThreatScores()
  }
}

/** Heuristic XAI factors from model id + score (no features_json in write-back snapshot). */
export function factorsForThreatScore(entry: ThreatScoreEntry): MlFactor[] {
  const s = entry.score
  switch (entry.model) {
    case 'phishing_lexical_v0':
      return [
        { label: 'Lexical risk', weight: s >= 0.8 ? 'high' : 'medium', detail: 'Domain shape, entropy, suspicious keywords' },
        { label: 'Weak label overlap', weight: s >= 0.7 ? 'high' : 'low', detail: 'PhishTank / UT1 / category=phishing signals' },
      ]
    case 'cc_beacon_v0':
      return [
        { label: 'Periodic gaps', weight: s >= 0.8 ? 'high' : 'medium', detail: 'Regular client→domain request intervals' },
        { label: 'Behavioral mix', weight: s >= 0.6 ? 'medium' : 'low', detail: 'POST ratio, small payloads, off-hours traffic' },
      ]
    case 'ueba_zscore_v0':
    case 'anomaly_stub_v0':
      return [
        { label: 'Volume anomaly', weight: s >= 0.8 ? 'high' : 'medium', detail: 'Request rate vs population baseline' },
        { label: 'Deny / threat mix', weight: s >= 0.7 ? 'high' : 'low', detail: 'Elevated deny or threat_hit ratio in window' },
      ]
    default:
      return [
        { label: 'Model score', weight: s >= 0.8 ? 'high' : 'medium', detail: `Aggregated score from ${entry.model}` },
      ]
  }
}

function mockThreatScores(): ThreatScoreSnapshot {
  const now = new Date().toISOString()
  return {
    generated_at: now,
    scores: [
      {
        entity_type: 'domain',
        entity_id: 'login-verify.example',
        score: 0.88,
        severity: 'high',
        model: 'phishing_lexical_v0',
        scored_at: now,
        expires_at: now,
      },
      {
        entity_type: 'client_domain',
        entity_id: '10.0.1.42|c2.beacon.test',
        score: 0.93,
        severity: 'critical',
        model: 'cc_beacon_v0',
        scored_at: now,
        expires_at: now,
      },
      {
        entity_type: 'client_ip',
        entity_id: '10.0.1.42',
        score: 0.76,
        severity: 'high',
        model: 'ueba_zscore_v0',
        scored_at: now,
        expires_at: now,
      },
    ],
  }
}
