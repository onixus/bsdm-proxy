import { apiFetch } from './client'
import { loadApiSettings } from './settings'
import { demo, isDemoMode, live, type Sourced } from './source'

/** Live control-plane state of this proxy node (real endpoints on the metrics port). */

export interface HierarchyPeer {
  name?: string
  host?: string
  http_port?: number
  icp_port?: number
  peer_type?: string
  state?: string
  [key: string]: unknown
}

export interface UpstreamTlsStatus {
  [key: string]: unknown
}

export async function fetchHierarchyPeers(): Promise<Sourced<HierarchyPeer[]>> {
  const settings = loadApiSettings()
  try {
    const res = await apiFetch<HierarchyPeer[] | { peers: HierarchyPeer[] }>('/api/hierarchy/peers', {
      baseUrl: settings.metricsBaseUrl,
    })
    return live(Array.isArray(res) ? res : (res.peers ?? []))
  } catch (err) {
    if (isDemoMode())
      return demo([
        { name: 'parent-dc1', host: '10.0.2.1', http_port: 3128, icp_port: 3130, peer_type: 'parent', state: 'alive' },
        { name: 'sibling-dc2', host: '10.0.2.2', http_port: 3128, icp_port: 3130, peer_type: 'sibling', state: 'alive' },
      ])
    throw err
  }
}

export async function fetchUpstreamTls(): Promise<Sourced<UpstreamTlsStatus>> {
  const settings = loadApiSettings()
  try {
    return live(await apiFetch<UpstreamTlsStatus>('/api/upstream/tls', { baseUrl: settings.metricsBaseUrl }))
  } catch (err) {
    if (isDemoMode()) return demo({ mode: 'system-roots', client_certs: 0, note: 'demo' })
    throw err
  }
}
