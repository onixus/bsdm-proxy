import { useState, useEffect, useTransition } from 'react'
import {
  Network,
  Plus,
  RefreshCw,
  Settings,
  Trash2,
  CheckCircle2,
  Zap,
  ShieldCheck,
  Flame,
} from 'lucide-react'

import {
  fetchClusterNodes,
  addClusterNode,
  deleteClusterNode,
  fetchClusterConfig,
  updateClusterConfig,
  triggerClusterSync,
  purgeClusterCache,
  fetchClusterStats,
  type ClusterNode,
  type ClusterMeshConfig,
  type ClusterStats,
  type ClusterNodeRole,
} from '../api/cluster'

import { Button } from '../components/ui/Button'
import { Modal } from '../components/ui/Modal'
import { FormField } from '../components/ui/Form'
import { PreviewBanner } from '../components/ui/DataState'

export function ClusterMeshPage() {
  const [, startTransition] = useTransition()
  const [nodes, setNodes] = useState<ClusterNode[]>([])
  const [config, setConfig] = useState<ClusterMeshConfig | null>(null)
  const [stats, setStats] = useState<ClusterStats | null>(null)

  const [activeTab, setActiveTab] = useState<'nodes' | 'grpc' | 'audit'>('nodes')
  const [searchQuery, setSearchQuery] = useState('')
  const [syncing, setSyncing] = useState(false)
  const [syncSuccessMsg, setSyncSuccessMsg] = useState<string | null>(null)

  // Modals
  const [addNodeModalOpen, setAddNodeModalOpen] = useState(false)
  const [syncModalOpen, setSyncModalOpen] = useState(false)
  const [purgeModalOpen, setPurgeModalOpen] = useState(false)
  const [configModalOpen, setConfigModalOpen] = useState(false)

  // Add Node Form
  const [nodeName, setNodeName] = useState('')
  const [nodeRole, setNodeRole] = useState<ClusterNodeRole>('worker')
  const [nodeGrpc, setNodeGrpc] = useState('10.0.4.15:50051')
  const [nodeRest, setNodeRest] = useState('http://10.0.4.15:9090')
  const [nodeRegion, setNodeRegion] = useState('eu-central-1')

  // Sync Form
  const [syncTargetNodes] = useState<string[]>([])
  const [syncItems] = useState<('acl' | 'wasm' | 'rpz' | 'tls' | 'hierarchy')[]>([
    'acl',
    'wasm',
    'rpz',
  ])

  // Purge Form
  const [purgeScope, setPurgeScope] = useState('all')
  const [purgePattern, setPurgePattern] = useState('')
  const [purging, setPurging] = useState(false)

  // Config Form
  const [cfgEnabled, setCfgEnabled] = useState(true)
  const [cfgGrpcBind, setCfgGrpcBind] = useState('127.0.0.1:50051')
  const [cfgSyncInterval, setCfgSyncInterval] = useState(15)
  const [cfgAutoRules, setCfgAutoRules] = useState(true)
  const [cfgAutoWasm, setCfgAutoWasm] = useState(true)

  const loadData = async () => {
    try {
      const [nList, cfg, st] = await Promise.all([
        fetchClusterNodes(),
        fetchClusterConfig(),
        fetchClusterStats(),
      ])
      setNodes(nList)
      setConfig(cfg)
      setStats(st)

      if (cfg) {
        setCfgEnabled(cfg.enabled)
        setCfgGrpcBind(cfg.grpcBind)
        setCfgSyncInterval(cfg.syncIntervalSecs)
        setCfgAutoRules(cfg.autoSyncRules)
        setCfgAutoWasm(cfg.autoSyncWasm)
      }
    } catch (err) {
      console.error('Error loading cluster data:', err)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleCreateNode = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!nodeName || !nodeGrpc) return
    const created = await addClusterNode({
      name: nodeName,
      role: nodeRole,
      grpcEndpoint: nodeGrpc,
      restEndpoint: nodeRest,
      region: nodeRegion,
    })
    setNodes((prev) => [...prev, created])
    setAddNodeModalOpen(false)
    resetNodeForm()
    const st = await fetchClusterStats()
    setStats(st)
  }

  const resetNodeForm = () => {
    setNodeName('')
    setNodeRole('worker')
    setNodeGrpc('10.0.4.15:50051')
    setNodeRest('http://10.0.4.15:9090')
    setNodeRegion('eu-central-1')
  }

  const handleDeleteNode = async (id: string) => {
    if (!window.confirm('Remove this node from the cluster mesh?')) return
    setNodes((prev) => prev.filter((n) => n.id !== id))
    await deleteClusterNode(id)
    const st = await fetchClusterStats()
    setStats(st)
  }

  const handleTriggerSync = async (e: React.FormEvent) => {
    e.preventDefault()
    setSyncing(true)
    try {
      const res = await triggerClusterSync({
        targetNodeIds: syncTargetNodes,
        syncItems,
      })
      setSyncSuccessMsg(`Successfully pushed updates to ${res.syncedNodesCount} nodes via gRPC`)
      setSyncModalOpen(false)
      setTimeout(() => setSyncSuccessMsg(null), 4000)
    } finally {
      setSyncing(false)
    }
  }

  const handlePurgeMeshCache = async (e: React.FormEvent) => {
    e.preventDefault()
    setPurging(true)
    try {
      const res = await purgeClusterCache(purgeScope, purgePattern)
      setSyncSuccessMsg(`Cluster cache purged across all ${res.purgedNodes} nodes`)
      setPurgeModalOpen(false)
      setTimeout(() => setSyncSuccessMsg(null), 4000)
    } finally {
      setPurging(false)
    }
  }

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault()
    const updated = await updateClusterConfig({
      enabled: cfgEnabled,
      controlNodeId: config?.controlNodeId || 'node-primary-us',
      grpcBind: cfgGrpcBind,
      syncIntervalSecs: cfgSyncInterval,
      autoSyncRules: cfgAutoRules,
      autoSyncWasm: cfgAutoWasm,
      autoSyncRpz: config?.autoSyncRpz ?? true,
      authBearerConfigured: config?.authBearerConfigured ?? true,
    })
    setConfig(updated)
    setConfigModalOpen(false)
  }

  const filteredNodes = nodes.filter(
    (n) =>
      n.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      n.region.toLowerCase().includes(searchQuery.toLowerCase()) ||
      n.grpcEndpoint.toLowerCase().includes(searchQuery.toLowerCase()),
  )

  return (
    <div className="space-y-6">
      <PreviewBanner feature="Cluster mesh management">
        {' '}The real gRPC control plane exposes GetStats / PurgeCache / hierarchy RPCs, but node CRUD and mesh-wide
        stats have no REST API yet.
      </PreviewBanner>
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2.5 text-2xl font-bold text-text-primary">
            <Network className="size-7 text-accent" />
            Cluster & gRPC Mesh Topology
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            Manage distributed BSDM Proxy clusters via gRPC control plane (<code className="text-accent">bsdm.control.v1</code>).
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="secondary" onClick={() => setConfigModalOpen(true)}>
            <Settings className="size-4" />
            Mesh Settings
          </Button>
          <Button variant="secondary" onClick={() => setPurgeModalOpen(true)}>
            <Flame className="size-4 text-warning" />
            Purge Mesh Cache
          </Button>
          <Button variant="secondary" onClick={() => setSyncModalOpen(true)}>
            <RefreshCw className="size-4" />
            Cluster Sync
          </Button>
          <Button variant="primary" onClick={() => setAddNodeModalOpen(true)}>
            <Plus className="size-4" />
            Add Cluster Node
          </Button>
        </div>
      </div>

      {syncSuccessMsg && (
        <div className="rounded-md border border-success/40 bg-success/10 p-3 text-xs font-semibold text-success flex items-center gap-2">
          <CheckCircle2 className="size-4" />
          {syncSuccessMsg}
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Primary Control Node */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Control Plane Status
            </span>
            <span className="rounded-full bg-success/20 px-2 py-0.5 text-xs font-bold text-success">
              gRPC ONLINE
            </span>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">
              {stats?.healthyNodes || 0} / {stats?.totalNodes || 0} Healthy
            </span>
          </div>
          <div className="mt-2 text-xs text-text-secondary font-mono">
            Bind: {config?.grpcBind || '127.0.0.1:50051'}
          </div>
        </div>

        {/* Total Cluster RPS */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Total Mesh Throughput
            </span>
            <Zap className="size-4 text-accent" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">
              {stats ? stats.totalRps.toLocaleString() : '0'} req/s
            </span>
            <span className="text-xs text-success font-semibold">Live Mesh</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Cluster capacity: 50,000 req/s
          </div>
        </div>

        {/* Avg Hit Ratio */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Avg Cache Hit Ratio
            </span>
            <ShieldCheck className="size-4 text-success" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-success">
              {stats?.avgHitRatio || 89.4}%
            </span>
            <span className="text-xs text-text-secondary">warmgoodput</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Shared L1/L2 sharded cache
          </div>
        </div>

        {/* Rule Sync State */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Policy & Wasm Version
            </span>
            <RefreshCw className="size-4 text-accent" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">v1.8.4</span>
            <span className="text-xs text-success font-semibold">All Synced</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Auto-sync interval: {config?.syncIntervalSecs || 15}s
          </div>
        </div>
      </div>

      {/* Cluster Node Visual Grid */}
      <div className="space-y-3">
        <h2 className="text-base font-semibold text-text-primary">Active Cluster Mesh Topology Cards</h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {nodes.map((node) => (
            <div
              key={node.id}
              className={`rounded-lg border p-4 shadow-sm transition-all ${
                node.role === 'primary'
                  ? 'border-accent/40 bg-accent/5'
                  : 'border-border bg-surface-1'
              }`}
            >
              <div className="flex items-center justify-between">
                <span
                  className={`rounded px-2 py-0.5 text-xs font-mono font-bold ${
                    node.role === 'primary'
                      ? 'bg-accent text-white'
                      : node.role === 'worker'
                      ? 'bg-surface-2 text-text-primary'
                      : 'bg-surface-3 text-text-secondary'
                  }`}
                >
                  {node.role.toUpperCase()}
                </span>
                <span className="rounded-full bg-success/20 px-2 py-0.5 text-[10px] font-bold text-success">
                  HEALTHY
                </span>
              </div>

              <div className="mt-3 font-semibold text-text-primary truncate" title={node.name}>
                {node.name}
              </div>
              <div className="text-xs text-text-secondary truncate">{node.region}</div>
              <div className="mt-1 font-mono text-xs text-accent truncate">{node.grpcEndpoint}</div>

              {/* Node Metrics */}
              <div className="mt-4 grid grid-cols-2 gap-2 text-xs border-t border-border/50 pt-3">
                <div>
                  <span className="text-text-secondary">RPS: </span>
                  <span className="font-mono font-bold text-text-primary">{node.metrics.rps.toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-text-secondary">Latency: </span>
                  <span className="font-mono font-bold text-success">{node.metrics.latencyMs}ms</span>
                </div>
                <div>
                  <span className="text-text-secondary">Hit Ratio: </span>
                  <span className="font-mono text-text-primary">{node.cacheHitRatio}%</span>
                </div>
                <div>
                  <span className="text-text-secondary">Rules: </span>
                  <span className="font-mono text-text-primary">{node.syncedRulesVersion}</span>
                </div>
              </div>

              {/* Resource usage bars */}
              <div className="mt-3 space-y-1">
                <div className="flex justify-between text-[10px] text-text-secondary">
                  <span>CPU: {node.metrics.cpuUsage}%</span>
                  <span>RAM: {node.metrics.memUsageMB} MB</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-surface-0 overflow-hidden">
                  <div
                    className="h-full bg-accent transition-all"
                    style={{ width: `${node.metrics.cpuUsage}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-col justify-between border-b border-border sm:flex-row sm:items-center">
        <div className="flex space-x-4">
          <button
            type="button"
            onClick={() => setActiveTab('nodes')}
            className={`border-b-2 py-3 px-1 text-sm font-semibold transition-colors ${
              activeTab === 'nodes'
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            Node Directory ({nodes.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('grpc')}
            className={`border-b-2 py-3 px-1 text-sm font-semibold transition-colors ${
              activeTab === 'grpc'
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            gRPC Control Services (bsdm.control.v1)
          </button>
        </div>

        {activeTab === 'nodes' && (
          <div className="py-2">
            <input
              type="text"
              placeholder="Search cluster nodes..."
              value={searchQuery}
              onChange={(e) => startTransition(() => setSearchQuery(e.target.value))}
              className="rounded-md border border-border bg-surface-0 px-3 py-1 text-xs text-text-primary focus:border-accent focus:outline-none"
            />
          </div>
        )}
      </div>

      {/* Tab 1: Node Directory */}
      {activeTab === 'nodes' && (
        <div className="overflow-x-auto rounded-lg border border-border bg-surface-1">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-surface-2 text-xs uppercase text-text-secondary">
              <tr>
                <th className="px-4 py-3">Node Name & Region</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">gRPC Endpoint</th>
                <th className="px-4 py-3">Throughput</th>
                <th className="px-4 py-3">Hit Ratio</th>
                <th className="px-4 py-3">Sync Versions</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border text-text-primary">
              {filteredNodes.map((n) => (
                <tr key={n.id} className="hover:bg-surface-2/50 transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-semibold text-text-primary">{n.name}</div>
                    <div className="text-xs text-text-secondary">{n.region}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-mono font-bold ${
                        n.role === 'primary' ? 'bg-accent text-white' : 'bg-surface-2 text-text-primary'
                      }`}
                    >
                      {n.role.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-accent">{n.grpcEndpoint}</td>
                  <td className="px-4 py-3 font-mono text-xs font-bold text-text-primary">
                    {n.metrics.rps.toLocaleString()} req/s
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-success">{n.cacheHitRatio}%</td>
                  <td className="px-4 py-3 font-mono text-xs text-text-secondary">
                    ACL: {n.syncedRulesVersion} | Wasm: {n.syncedWasmVersion}
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded-full bg-success/20 px-2.5 py-0.5 text-xs font-bold text-success">
                      HEALTHY
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => handleDeleteNode(n.id)}
                      className="rounded p-1.5 text-danger/70 hover:bg-danger/20 hover:text-danger"
                      title="Remove Node"
                    >
                      <Trash2 className="size-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 2: gRPC Control Plane Methods */}
      {activeTab === 'grpc' && (
        <div className="rounded-lg border border-border bg-surface-1 p-5 space-y-4">
          <h3 className="text-base font-bold text-text-primary">
            Active gRPC Service Methods (<code className="text-accent">bsdm.control.v1.ControlPlane</code>)
          </h3>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-md border border-border bg-surface-0 p-3">
              <div className="font-mono text-sm font-bold text-accent">rpc GetStats(Empty) returns (StatsResponse)</div>
              <div className="mt-1 text-xs text-text-secondary">Retrieves uptime, in-flight requests, cache capacity, shards, and hit ratios</div>
            </div>
            <div className="rounded-md border border-border bg-surface-0 p-3">
              <div className="font-mono text-sm font-bold text-accent">rpc PurgeCache(PurgeRequest) returns (PurgeResponse)</div>
              <div className="mt-1 text-xs text-text-secondary">Purges URL, tags, or entire L1/L2 cache across the cluster mesh</div>
            </div>
            <div className="rounded-md border border-border bg-surface-0 p-3">
              <div className="font-mono text-sm font-bold text-accent">rpc ListHierarchyPeers(Empty) returns (PeersListResponse)</div>
              <div className="mt-1 text-xs text-text-secondary">Lists ICP/HTCP static and dynamic hierarchy peers</div>
            </div>
            <div className="rounded-md border border-border bg-surface-0 p-3">
              <div className="font-mono text-sm font-bold text-accent">rpc ReloadHierarchy(Empty) returns (HierarchyReloadResponse)</div>
              <div className="mt-1 text-xs text-text-secondary">Triggers hot reload of static hierarchy peers configuration</div>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Add Node */}
      <Modal
        open={addNodeModalOpen}
        onClose={() => setAddNodeModalOpen(false)}
        title="Add Cluster Node to Mesh"
        wide
        footer={
          <>
            <Button variant="ghost" onClick={() => setAddNodeModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleCreateNode} disabled={!nodeName || !nodeGrpc}>
              <Plus className="size-4" />
              Add Node
            </Button>
          </>
        }
      >
        <form onSubmit={handleCreateNode} className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label="Node Name" required>
              <input
                type="text"
                placeholder="e.g. bsdm-proxy-worker-us-west"
                value={nodeName}
                onChange={(e) => setNodeName(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>

            <FormField label="Region">
              <input
                type="text"
                placeholder="e.g. us-west-2 (Oregon)"
                value={nodeRegion}
                onChange={(e) => setNodeRegion(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <FormField label="Node Role">
              <select
                value={nodeRole}
                onChange={(e) => setNodeRole(e.target.value as ClusterNodeRole)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              >
                <option value="worker">Worker Node</option>
                <option value="edge">Edge Node</option>
                <option value="primary">Primary Control Node</option>
              </select>
            </FormField>

            <FormField label="gRPC Endpoint" required>
              <input
                type="text"
                placeholder="10.0.4.15:50051"
                value={nodeGrpc}
                onChange={(e) => setNodeGrpc(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>

            <FormField label="REST Endpoint">
              <input
                type="text"
                placeholder="http://10.0.4.15:9090"
                value={nodeRest}
                onChange={(e) => setNodeRest(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          </div>
        </form>
      </Modal>

      {/* Modal: Realtime Cluster Sync */}
      <Modal
        open={syncModalOpen}
        onClose={() => setSyncModalOpen(false)}
        title="Trigger Cluster Mesh Realtime Sync"
        footer={
          <>
            <Button variant="ghost" onClick={() => setSyncModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleTriggerSync} disabled={syncing}>
              {syncing ? <RefreshCw className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
              Push Realtime Sync via gRPC
            </Button>
          </>
        }
      >
        <form onSubmit={handleTriggerSync} className="space-y-4">
          <p className="text-xs text-text-secondary">
            Push updated ACL rules, Wasm modules, and RPZ feeds to all cluster nodes simultaneously using gRPC streams.
          </p>

          <FormField label="Payloads to Synchronize">
            <div className="space-y-2 text-xs text-text-primary">
              <label className="flex items-center gap-2">
                <input type="checkbox" defaultChecked className="size-4 rounded accent-accent" />
                ACL Policies & Category Blacklists
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" defaultChecked className="size-4 rounded accent-accent" />
                Wasmtime Request Hook Modules
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" defaultChecked className="size-4 rounded accent-accent" />
                RPZ Feeds & DNS Sinkhole Blocklists
              </label>
            </div>
          </FormField>
        </form>
      </Modal>

      {/* Modal: Purge Mesh Cache */}
      <Modal
        open={purgeModalOpen}
        onClose={() => setPurgeModalOpen(false)}
        title="Purge Mesh Cache Across Cluster"
        footer={
          <>
            <Button variant="ghost" onClick={() => setPurgeModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handlePurgeMeshCache} disabled={purging}>
              <Flame className="size-4" />
              Purge Mesh Cache
            </Button>
          </>
        }
      >
        <form onSubmit={handlePurgeMeshCache} className="space-y-4">
          <FormField label="Purge Scope">
            <select
              value={purgeScope}
              onChange={(e) => setPurgeScope(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            >
              <option value="all">Purge ENTIRE L1/L2 Cache Mesh</option>
              <option value="url">Specific URL</option>
              <option value="tag">Cache-Tag / Surrogate-Key</option>
            </select>
          </FormField>

          {purgeScope !== 'all' && (
            <FormField label="URL or Tag Pattern">
              <input
                type="text"
                placeholder={purgeScope === 'url' ? 'https://example.com/api/v1' : 'tag-static-assets'}
                value={purgePattern}
                onChange={(e) => setPurgePattern(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          )}
        </form>
      </Modal>

      {/* Modal: Config Settings */}
      <Modal
        open={configModalOpen}
        onClose={() => setConfigModalOpen(false)}
        title="gRPC Mesh Control Plane Settings"
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfigModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleSaveConfig}>
              Save Config
            </Button>
          </>
        }
      >
        <form onSubmit={handleSaveConfig} className="space-y-4">
          <div className="flex items-center justify-between rounded-md border border-border bg-surface-0 p-3">
            <div>
              <div className="text-sm font-semibold text-text-primary">Enable gRPC Control Plane</div>
              <div className="text-xs text-text-secondary">Binds tonic gRPC server for cluster management</div>
            </div>
            <input
              type="checkbox"
              checked={cfgEnabled}
              onChange={(e) => setCfgEnabled(e.target.checked)}
              className="size-5 rounded border-border text-accent focus:ring-accent"
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label="gRPC Bind Address">
              <input
                type="text"
                value={cfgGrpcBind}
                onChange={(e) => setCfgGrpcBind(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>

            <FormField label="Auto-Sync Interval (Seconds)">
              <input
                type="number"
                value={cfgSyncInterval}
                onChange={(e) => setCfgSyncInterval(Number(e.target.value))}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          </div>
        </form>
      </Modal>
    </div>
  )
}
