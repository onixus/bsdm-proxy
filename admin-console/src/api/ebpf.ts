import { apiFetch, aclClient } from './client'
import { isDemoMode, sourced, type Sourced } from './source'

export type XdpMode = 'skb' | 'driver' | 'offload'

export interface EbpfXdpConfig {
  enabled: boolean
  interface: string
  mode: XdpMode
  mapName: string
  maxEntries: number
}

export interface EbpfBlockedIp {
  id: string
  ip: string
  addedAt: string
  reason: string
  packetsDropped: number
  bytesDropped: number
}

export interface EbpfStats {
  enabled: boolean
  /** Whether the XDP program is actually loaded on the interface right now. */
  attached: boolean
  interface: string
  mode: XdpMode
  activeBlockedIps: number
  packetsDroppedTotal: number
  bytesDroppedTotal: number
  /** null when the proxy has no latency measurement available. */
  kernelLatencyUs: number | null
  cpuUsageUserPercent: number
}

/**
 * Demo-mode scratch state. Only ever touched when demo mode is explicitly on —
 * a failed request in normal operation surfaces as an error, never as a
 * fabricated view of the kernel packet filter.
 */
let memoryIps: EbpfBlockedIp[] | null = null

export async function fetchEbpfConfig(): Promise<Sourced<EbpfXdpConfig>> {
  const { baseUrl, token } = aclClient()
  return sourced(
    () => apiFetch<EbpfXdpConfig>('/api/ebpf/config', { baseUrl, token }),
    getMockConfig,
  )
}

export async function updateEbpfConfig(config: EbpfXdpConfig): Promise<EbpfXdpConfig> {
  const { baseUrl, token } = aclClient()
  return apiFetch<EbpfXdpConfig>('/api/ebpf/config', {
    baseUrl,
    token,
    method: 'PUT',
    body: config,
  })
}

export async function fetchEbpfBlockedIps(): Promise<Sourced<EbpfBlockedIp[]>> {
  const { baseUrl, token } = aclClient()
  return sourced(
    () => apiFetch<EbpfBlockedIp[]>('/api/ebpf/ips', { baseUrl, token }),
    () => {
      if (!memoryIps) memoryIps = getMockBlockedIps()
      return memoryIps
    },
  )
}

export async function addEbpfBlockedIp(ip: string, reason: string): Promise<EbpfBlockedIp> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<EbpfBlockedIp>('/api/ebpf/ips', {
      baseUrl,
      token,
      method: 'POST',
      body: { ip, reason },
    })
  } catch (error) {
    if (!isDemoMode()) throw error
    const newItem: EbpfBlockedIp = {
      id: `ebpf-${Date.now()}`,
      ip,
      addedAt: new Date().toISOString(),
      reason: reason || 'Manual ACL kernel block',
      packetsDropped: 0,
      bytesDropped: 0,
    }
    if (!memoryIps) memoryIps = getMockBlockedIps()
    memoryIps.push(newItem)
    return newItem
  }
}

export async function removeEbpfBlockedIp(id: string): Promise<void> {
  const { baseUrl, token } = aclClient()
  try {
    await apiFetch(`/api/ebpf/ips/${encodeURIComponent(id)}`, {
      baseUrl,
      token,
      method: 'DELETE',
    })
  } catch (error) {
    if (!isDemoMode()) throw error
    if (!memoryIps) memoryIps = getMockBlockedIps()
    memoryIps = memoryIps.filter((item) => item.id !== id)
  }
}

export async function fetchEbpfStats(): Promise<Sourced<EbpfStats>> {
  const { baseUrl, token } = aclClient()
  return sourced(
    () => apiFetch<EbpfStats>('/api/ebpf/stats', { baseUrl, token }),
    getMockStats,
  )
}

function getMockConfig(): EbpfXdpConfig {
  return {
    enabled: false,
    interface: 'eth0',
    mode: 'driver',
    mapName: 'bsdm_blocked_ips',
    maxEntries: 65536,
  }
}

function getMockStats(): EbpfStats {
  if (!memoryIps) memoryIps = getMockBlockedIps()
  const config = getMockConfig()
  return {
    enabled: config.enabled,
    attached: false,
    interface: config.interface,
    mode: config.mode,
    activeBlockedIps: memoryIps.length,
    packetsDroppedTotal: memoryIps.reduce((acc, item) => acc + item.packetsDropped, 0),
    bytesDroppedTotal: memoryIps.reduce((acc, item) => acc + item.bytesDropped, 0),
    kernelLatencyUs: null,
    cpuUsageUserPercent: 0.0,
  }
}

function getMockBlockedIps(): EbpfBlockedIp[] {
  return [
    {
      id: 'ebpf-1',
      ip: '198.51.100.42',
      addedAt: '2026-07-21T09:15:00Z',
      reason: 'Malicious C&C Botnet scanner',
      packetsDropped: 142500,
      bytesDropped: 91200000,
    },
    {
      id: 'ebpf-2',
      ip: '203.0.113.105',
      addedAt: '2026-07-21T11:20:00Z',
      reason: 'High frequency HTTP flood probe',
      packetsDropped: 34250,
      bytesDropped: 21920000,
    },
    {
      id: 'ebpf-3',
      ip: '192.0.2.88',
      addedAt: '2026-07-21T13:05:00Z',
      reason: 'UT1 Category Blacklist override',
      packetsDropped: 7500,
      bytesDropped: 4800000,
    },
  ]
}
