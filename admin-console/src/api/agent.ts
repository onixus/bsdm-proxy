import { apiFetch, controlClient } from './client'

/** Device inventory row from `GET /api/v1/devices` (Trust-UI / Admin Console shape). */
export interface AgentDevice {
  id: string
  name: string
  ip: string
  type: string
  status: 'Secured' | 'Flagged' | 'Revoked' | string
  connection: string
  lastSeen: number
  agentStatus?: string
  agentVersion?: string | null
  policyVersion?: string | null
  certSubject?: string | null
  certFingerprint?: string | null
  certSerial?: string | null
  trustScore?: number | null
  platform?: string | null
  userIdentity?: string | null
  enrolledAt?: number | null
  enrolled?: boolean
  capabilities?: string[]
  configDigest?: string | null
  systemProxyEnforced?: boolean | null
  activeTunnel?: string | null
}

export interface RevokeDeviceResult {
  success: boolean
  message: string
  persisted?: boolean
  crl_added?: boolean
  cert_fingerprint?: string | null
}

export interface AgentPolicyDocument {
  policy_version: string
  policy_mode?: string
  mitm_categories?: string[]
  pinning_exceptions?: string[]
  sni_deny_patterns?: string[]
  sni_rules?: Array<{ pattern: string; action: string }>
  [key: string]: unknown
}

export interface AgentPolicyPushResult {
  status: string
  policy_version: string
  reason?: string
  pushed_at?: number
  document?: AgentPolicyDocument
}

export interface AgentCrlEntry {
  fingerprint: string
  serial_hex?: string | null
  device_id: string
  revoked_at: number
  reason?: string
}

export interface AgentCrlDocument {
  version: number
  crl_number: number
  count: number
  entries: AgentCrlEntry[]
  updated_at: number
}

export interface AgentRecentEvent {
  device_id: string
  domain?: string
  action?: string
  decision_source?: string
  reason?: string | null
  received_at?: number
  [key: string]: unknown
}

export interface AgentEventsRecentResponse {
  events: AgentRecentEvent[]
}

export async function fetchDevices(signal?: AbortSignal): Promise<AgentDevice[]> {
  const { baseUrl, token } = controlClient()
  return apiFetch<AgentDevice[]>('/api/v1/devices', { baseUrl, token, signal })
}

export async function revokeDevice(deviceId: string): Promise<RevokeDeviceResult> {
  const { baseUrl, token } = controlClient()
  return apiFetch<RevokeDeviceResult>(`/api/v1/devices/${encodeURIComponent(deviceId)}/revoke`, {
    baseUrl,
    token,
    method: 'POST',
  })
}

export async function fetchAgentPolicy(signal?: AbortSignal): Promise<AgentPolicyDocument> {
  const { baseUrl, token } = controlClient()
  return apiFetch<AgentPolicyDocument>('/api/v1/agent/policy', { baseUrl, token, signal })
}

export async function pushAgentPolicy(payload?: {
  reason?: string
  actor?: string
}): Promise<AgentPolicyPushResult> {
  const { baseUrl, token } = controlClient()
  return apiFetch<AgentPolicyPushResult>('/api/v1/agent/policy/push', {
    baseUrl,
    token,
    method: 'POST',
    body: payload ?? { reason: 'console-push', actor: 'admin-console' },
  })
}

export async function fetchAgentCrl(signal?: AbortSignal): Promise<AgentCrlDocument> {
  const { baseUrl, token } = controlClient()
  return apiFetch<AgentCrlDocument>('/api/v1/agent/crl', { baseUrl, token, signal })
}

export async function fetchAgentEventsRecent(
  signal?: AbortSignal,
): Promise<AgentEventsRecentResponse> {
  const { baseUrl, token } = controlClient()
  return apiFetch<AgentEventsRecentResponse>('/api/v1/agent/events/recent', {
    baseUrl,
    token,
    signal,
  })
}
