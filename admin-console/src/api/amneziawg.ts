import { demo, isDemoMode, live, type Sourced } from './source'

export interface AwgObfuscationConfig {
  jc: number
  jmin: number
  jmax: number
  s1: number
  s2: number
  h1: number
  h2: number
  h3: number
  h4: number
}

export interface AwgPeerConfig {
  id: string
  name: string
  public_key: string
  private_key?: string
  allowed_ips: string
  assigned_ip: string
  created_at: string
  rx_bytes?: number
  tx_bytes?: number
  latest_handshake_secs?: number
}

export interface AwgServerConfig {
  enabled: boolean
  listen_port: number
  private_key: string
  public_key: string
  address: string
  obfuscation: AwgObfuscationConfig
  peers: AwgPeerConfig[]
  last_reload_status?: string
  last_reload_at?: number
}

const mockStatus: AwgServerConfig = {
  enabled: true,
  listen_port: 51820,
  private_key: 'wP4k...placeholder...key=',
  public_key: 'pub...placeholder...key=',
  address: '10.8.0.1/24',
  last_reload_status: 'Sidecar synced (awg0.conf updated)',
  last_reload_at: 1721812900,
  obfuscation: {
    jc: 4,
    jmin: 40,
    jmax: 70,
    s1: 15,
    s2: 25,
    h1: 10000001,
    h2: 10000002,
    h3: 10000003,
    h4: 10000004,
  },
  peers: [
    {
      id: 'peer-1',
      name: 'Corporate Laptop (Alice)',
      public_key: 'aliceKey123...',
      assigned_ip: '10.8.0.2',
      allowed_ips: '10.8.0.2/32',
      created_at: '2026-07-24',
      rx_bytes: 14258900,
      tx_bytes: 84210000,
      latest_handshake_secs: Math.floor(Date.now() / 1000) - 120,
    },
    {
      id: 'peer-2',
      name: 'Mobile Client (Bob)',
      public_key: 'bobKey456...',
      assigned_ip: '10.8.0.3',
      allowed_ips: '10.8.0.3/32',
      created_at: '2026-07-24',
      rx_bytes: 512000,
      tx_bytes: 1024000,
      latest_handshake_secs: Math.floor(Date.now() / 1000) - 3600,
    },
  ],
}

export async function fetchAwgStatus(): Promise<Sourced<AwgServerConfig>> {
  if (isDemoMode()) return demo(mockStatus)
  try {
    const res = await fetch('/api/amneziawg/status')
    if (!res.ok) throw new Error('HTTP ' + res.status)
    const json = await res.json()
    return live(json)
  } catch {
    return demo(mockStatus)
  }
}

export async function updateAwgConfig(config: AwgServerConfig): Promise<{ status: string; reload_status?: string }> {
  if (isDemoMode()) return { status: 'ok', reload_status: 'Sidecar synced' }
  const res = await fetch('/api/amneziawg/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  })
  if (!res.ok) throw new Error('HTTP ' + res.status)
  return res.json()
}

export async function addAwgPeer(peer: AwgPeerConfig): Promise<{ status: string; reload_status?: string }> {
  if (isDemoMode()) return { status: 'ok', reload_status: 'Sidecar synced' }
  const res = await fetch('/api/amneziawg/peers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(peer),
  })
  if (!res.ok) throw new Error('HTTP ' + res.status)
  return res.json()
}

export async function deleteAwgPeer(id: string): Promise<{ status: string; reload_status?: string }> {
  if (isDemoMode()) return { status: 'deleted', reload_status: 'Sidecar synced' }
  const res = await fetch('/api/amneziawg/peers', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id }),
  })
  if (!res.ok) throw new Error('HTTP ' + res.status)
  return res.json()
}
