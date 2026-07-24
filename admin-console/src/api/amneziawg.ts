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
}

export interface AwgServerConfig {
  enabled: boolean
  listen_port: number
  private_key: string
  public_key: string
  address: string
  obfuscation: AwgObfuscationConfig
  peers: AwgPeerConfig[]
}

const mockStatus: AwgServerConfig = {
  enabled: true,
  listen_port: 51820,
  private_key: 'wP4k...placeholder...key=',
  public_key: 'pub...placeholder...key=',
  address: '10.8.0.1/24',
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
    },
    {
      id: 'peer-2',
      name: 'Mobile Client (Bob)',
      public_key: 'bobKey456...',
      assigned_ip: '10.8.0.3',
      allowed_ips: '10.8.0.3/32',
      created_at: '2026-07-24',
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

export async function updateAwgConfig(config: AwgServerConfig): Promise<{ status: string }> {
  if (isDemoMode()) return { status: 'ok' }
  const res = await fetch('/api/amneziawg/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  })
  if (!res.ok) throw new Error('HTTP ' + res.status)
  return res.json()
}

export async function addAwgPeer(peer: AwgPeerConfig): Promise<{ status: string }> {
  if (isDemoMode()) return { status: 'ok' }
  const res = await fetch('/api/amneziawg/peers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(peer),
  })
  if (!res.ok) throw new Error('HTTP ' + res.status)
  return res.json()
}
