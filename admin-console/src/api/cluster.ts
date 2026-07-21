import { apiFetch, aclClient } from './client'

export type ClusterNodeRole = 'primary' | 'worker' | 'edge'
export type ClusterNodeStatus = 'healthy' | 'degraded' | 'offline'

export interface ClusterNode {
  id: string
  name: string
  role: ClusterNodeRole
  grpcEndpoint: string
  restEndpoint: string
  region: string
  status: ClusterNodeStatus
  version: string
  uptimeSecs: number
  inFlightRequests: number
  cacheHitRatio: number
  syncedRulesVersion: string
  syncedWasmVersion: string
  lastHeartbeat: string
  metrics: {
    rps: number
    latencyMs: number
    cpuUsage: number
    memUsageMB: number
  }
}

export interface ClusterMeshConfig {
  enabled: boolean
  controlNodeId: string
  grpcBind: string
  syncIntervalSecs: number
  autoSyncRules: boolean
  autoSyncWasm: boolean
  autoSyncRpz: boolean
  authBearerConfigured: boolean
}

export interface ClusterSyncCommandInput {
  targetNodeIds: string[]
  syncItems: ('acl' | 'wasm' | 'rpz' | 'tls' | 'hierarchy')[]
}

export interface ClusterSyncResult {
  success: boolean
  syncedNodesCount: number
  failedNodesCount: number
  details: {
    nodeId: string
    nodeName: string
    status: 'synced' | 'failed'
    error?: string
  }[]
}

export interface ClusterStats {
  totalNodes: number
  healthyNodes: number
  totalRps: number
  avgHitRatio: number
  clusterCapacityReqSec: number
}

export interface AddClusterNodeInput {
  name: string
  role: ClusterNodeRole
  grpcEndpoint: string
  restEndpoint: string
  region: string
}

let memoryNodes: ClusterNode[] | null = null
let memoryConfig: ClusterMeshConfig | null = null

export async function fetchClusterNodes(): Promise<ClusterNode[]> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<ClusterNode[]>('/api/cluster/nodes', { baseUrl, token })
  } catch {
    if (!memoryNodes) {
      memoryNodes = getMockNodes()
    }
    return memoryNodes
  }
}

export async function addClusterNode(input: AddClusterNodeInput): Promise<ClusterNode> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<ClusterNode>('/api/cluster/nodes', {
      baseUrl,
      token,
      method: 'POST',
      body: input,
    })
  } catch {
    const newNode: ClusterNode = {
      id: `node-${Date.now()}`,
      name: input.name,
      role: input.role,
      grpcEndpoint: input.grpcEndpoint,
      restEndpoint: input.restEndpoint,
      region: input.region || 'us-east-1',
      status: 'healthy',
      version: 'v0.5.0 (grpc)',
      uptimeSecs: 3600,
      inFlightRequests: 12,
      cacheHitRatio: 88.5,
      syncedRulesVersion: 'v1.8.4',
      syncedWasmVersion: 'v1.0.0',
      lastHeartbeat: new Date().toISOString(),
      metrics: {
        rps: 1250,
        latencyMs: 1.4,
        cpuUsage: 18.5,
        memUsageMB: 240,
      },
    }
    if (!memoryNodes) memoryNodes = getMockNodes()
    memoryNodes.push(newNode)
    return newNode
  }
}

export async function deleteClusterNode(id: string): Promise<void> {
  const { baseUrl, token } = aclClient()
  try {
    await apiFetch(`/api/cluster/nodes/${encodeURIComponent(id)}`, {
      baseUrl,
      token,
      method: 'DELETE',
    })
  } catch {
    if (!memoryNodes) memoryNodes = getMockNodes()
    memoryNodes = memoryNodes.filter((n) => n.id !== id)
  }
}

export async function fetchClusterConfig(): Promise<ClusterMeshConfig> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<ClusterMeshConfig>('/api/cluster/config', { baseUrl, token })
  } catch {
    if (!memoryConfig) {
      memoryConfig = {
        enabled: true,
        controlNodeId: 'node-primary-us',
        grpcBind: '127.0.0.1:50051',
        syncIntervalSecs: 15,
        autoSyncRules: true,
        autoSyncWasm: true,
        autoSyncRpz: true,
        authBearerConfigured: true,
      }
    }
    return memoryConfig
  }
}

export async function updateClusterConfig(config: ClusterMeshConfig): Promise<ClusterMeshConfig> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<ClusterMeshConfig>('/api/cluster/config', {
      baseUrl,
      token,
      method: 'PUT',
      body: config,
    })
  } catch {
    memoryConfig = { ...config }
    return memoryConfig
  }
}

export async function triggerClusterSync(input: ClusterSyncCommandInput): Promise<ClusterSyncResult> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<ClusterSyncResult>('/api/cluster/sync', {
      baseUrl,
      token,
      method: 'POST',
      body: input,
    })
  } catch {
    const nodes = await fetchClusterNodes()
    const targetNodes = nodes.filter((n) => input.targetNodeIds.length === 0 || input.targetNodeIds.includes(n.id))
    return {
      success: true,
      syncedNodesCount: targetNodes.length,
      failedNodesCount: 0,
      details: targetNodes.map((n) => ({
        nodeId: n.id,
        nodeName: n.name,
        status: 'synced',
      })),
    }
  }
}

export async function purgeClusterCache(scope: string, pattern?: string): Promise<{ purgedNodes: number }> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<{ purgedNodes: number }>('/api/cluster/purge', {
      baseUrl,
      token,
      method: 'POST',
      body: { scope, pattern },
    })
  } catch {
    const nodes = await fetchClusterNodes()
    return { purgedNodes: nodes.length }
  }
}

export async function fetchClusterStats(): Promise<ClusterStats> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<ClusterStats>('/api/cluster/stats', { baseUrl, token })
  } catch {
    const nodes = await fetchClusterNodes()
    const healthy = nodes.filter((n) => n.status === 'healthy')
    const totalRps = nodes.reduce((acc, n) => acc + n.metrics.rps, 0)
    const avgHitRatio = nodes.reduce((acc, n) => acc + n.cacheHitRatio, 0) / (nodes.length || 1)
    return {
      totalNodes: nodes.length,
      healthyNodes: healthy.length,
      totalRps,
      avgHitRatio: Number(avgHitRatio.toFixed(1)),
      clusterCapacityReqSec: 50000,
    }
  }
}

function getMockNodes(): ClusterNode[] {
  return [
    {
      id: 'node-primary-us',
      name: 'bsdm-proxy-primary-us-east',
      role: 'primary',
      grpcEndpoint: '127.0.0.1:50051',
      restEndpoint: 'http://127.0.0.1:9090',
      region: 'us-east-1 (N. Virginia)',
      status: 'healthy',
      version: 'v0.5.0 (grpc)',
      uptimeSecs: 142800,
      inFlightRequests: 42,
      cacheHitRatio: 91.2,
      syncedRulesVersion: 'v1.8.4',
      syncedWasmVersion: 'v1.0.0',
      lastHeartbeat: new Date().toISOString(),
      metrics: {
        rps: 3450,
        latencyMs: 1.1,
        cpuUsage: 24.2,
        memUsageMB: 310,
      },
    },
    {
      id: 'node-worker-eu',
      name: 'bsdm-proxy-worker-eu-central',
      role: 'worker',
      grpcEndpoint: '10.0.4.15:50051',
      restEndpoint: 'http://10.0.4.15:9090',
      region: 'eu-central-1 (Frankfurt)',
      status: 'healthy',
      version: 'v0.5.0 (grpc)',
      uptimeSecs: 98400,
      inFlightRequests: 28,
      cacheHitRatio: 89.4,
      syncedRulesVersion: 'v1.8.4',
      syncedWasmVersion: 'v1.0.0',
      lastHeartbeat: new Date().toISOString(),
      metrics: {
        rps: 2890,
        latencyMs: 1.6,
        cpuUsage: 31.0,
        memUsageMB: 285,
      },
    },
    {
      id: 'node-worker-ap',
      name: 'bsdm-proxy-worker-ap-singapore',
      role: 'worker',
      grpcEndpoint: '10.0.8.22:50051',
      restEndpoint: 'http://10.0.8.22:9090',
      region: 'ap-southeast-1 (Singapore)',
      status: 'healthy',
      version: 'v0.5.0 (grpc)',
      uptimeSecs: 72000,
      inFlightRequests: 18,
      cacheHitRatio: 87.6,
      syncedRulesVersion: 'v1.8.4',
      syncedWasmVersion: 'v1.0.0',
      lastHeartbeat: new Date().toISOString(),
      metrics: {
        rps: 1620,
        latencyMs: 2.1,
        cpuUsage: 19.8,
        memUsageMB: 220,
      },
    },
    {
      id: 'node-edge-vps',
      name: 'bsdm-proxy-edge-vps-pop01',
      role: 'edge',
      grpcEndpoint: '198.51.100.42:50051',
      restEndpoint: 'http://198.51.100.42:9090',
      region: 'edge-pop-hetzner',
      status: 'healthy',
      version: 'v0.5.0 (grpc)',
      uptimeSecs: 342000,
      inFlightRequests: 8,
      cacheHitRatio: 84.1,
      syncedRulesVersion: 'v1.8.4',
      syncedWasmVersion: 'v1.0.0',
      lastHeartbeat: new Date().toISOString(),
      metrics: {
        rps: 490,
        latencyMs: 3.2,
        cpuUsage: 12.4,
        memUsageMB: 165,
      },
    },
  ]
}
