import { useState, useEffect, useTransition } from 'react'
import {
  Cpu,
  Plus,
  Play,
  Settings,
  Trash2,
  Code2,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Zap,
  ShieldCheck,
  Search,
  Layers,
} from 'lucide-react'

import {
  fetchWasmPlugins,
  addWasmPlugin,
  toggleWasmPlugin,
  deleteWasmPlugin,
  fetchWasmConfig,
  updateWasmConfig,
  testWasmPlugin,
  fetchWasmStats,
  type WasmPlugin,
  type WasmGlobalConfig,
  type WasmTestResult,
  type WasmStats,
  type WasmHookType,
  type WasmCodeType,
} from '../api/wasm'

import { Button } from '../components/ui/Button'
import { Modal } from '../components/ui/Modal'
import { FormField } from '../components/ui/Form'
import { PreviewBanner } from '../components/ui/DataState'

export function WasmPluginsPage() {
  const [, startTransition] = useTransition()
  const [plugins, setPlugins] = useState<WasmPlugin[]>([])
  const [config, setConfig] = useState<WasmGlobalConfig | null>(null)
  const [stats, setStats] = useState<WasmStats | null>(null)

  // Search filter
  const [searchQuery, setSearchQuery] = useState('')

  // Interactive Sandbox state
  const [testMethod, setTestMethod] = useState('GET')
  const [testUrl, setTestUrl] = useState('https://evil.blocked.test/phish')
  const [testClientIp, setTestClientIp] = useState('192.168.1.50')
  const [testUsername] = useState('alice')
  const [testResult, setTestResult] = useState<WasmTestResult | null>(null)
  const [testing, setTesting] = useState(false)

  // Modals
  const [uploadModalOpen, setUploadModalOpen] = useState(false)
  const [viewCodeModalOpen, setViewCodeModalOpen] = useState(false)
  const [configModalOpen, setConfigModalOpen] = useState(false)
  const [selectedPlugin, setSelectedPlugin] = useState<WasmPlugin | null>(null)

  // Upload Form
  const [inputName, setInputName] = useState('')
  const [inputVersion, setInputVersion] = useState('1.0.0')
  const [inputDesc, setInputDesc] = useState('')
  const [inputAuthor, setInputAuthor] = useState('')
  const [inputHookType, setInputHookType] = useState<WasmHookType>('on_request')
  const [inputCodeType, setInputCodeType] = useState<WasmCodeType>('wat')
  const [inputSourceCode, setInputSourceCode] = useState('')
  const [inputFuelLimit, setInputFuelLimit] = useState(50000)
  const [inputFailOpen, setInputFailOpen] = useState(true)

  // Config Form
  const [cfgEnabled, setCfgEnabled] = useState(true)
  const [cfgFuel, setCfgFuel] = useState(50000)
  const [cfgFailOpen, setCfgFailOpen] = useState(true)
  const [cfgMaxMem, setCfgMaxMem] = useState(16)

  const loadData = async () => {
    try {
      const [pList, cfg, st] = await Promise.all([
        fetchWasmPlugins(),
        fetchWasmConfig(),
        fetchWasmStats(),
      ])
      setPlugins(pList)
      setConfig(cfg)
      setStats(st)

      if (cfg) {
        setCfgEnabled(cfg.enabled)
        setCfgFuel(cfg.defaultFuelLimit)
        setCfgFailOpen(cfg.failOpenDefault)
        setCfgMaxMem(cfg.maxMemoryMB)
      }
    } catch (err) {
      console.error('Error loading Wasm plugin data:', err)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleTestSandbox = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!testUrl.trim()) return
    setTesting(true)
    try {
      const res = await testWasmPlugin({
        method: testMethod,
        url: testUrl.trim(),
        clientIp: testClientIp,
        username: testUsername,
      })
      setTestResult(res)
    } finally {
      setTesting(false)
    }
  }

  const handleToggle = async (id: string, currentStatus: string) => {
    const isNextActive = currentStatus !== 'active'
    setPlugins((prev) =>
      prev.map((p) => (p.id === id ? { ...p, status: isNextActive ? 'active' : 'disabled' } : p)),
    )
    await toggleWasmPlugin(id, isNextActive)
    const st = await fetchWasmStats()
    setStats(st)
  }

  const handleDelete = async (id: string) => {
    if (!window.confirm('Delete this Wasm plugin?')) return
    setPlugins((prev) => prev.filter((p) => p.id !== id))
    await deleteWasmPlugin(id)
    const st = await fetchWasmStats()
    setStats(st)
  }

  const handleUploadPlugin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!inputName || !inputSourceCode) return
    const created = await addWasmPlugin({
      name: inputName,
      version: inputVersion,
      description: inputDesc,
      author: inputAuthor,
      hookType: inputHookType,
      codeType: inputCodeType,
      sourceCode: inputSourceCode,
      fuelLimit: inputFuelLimit,
      failOpen: inputFailOpen,
    })
    setPlugins((prev) => [created, ...prev])
    setUploadModalOpen(false)
    resetUploadForm()
    const st = await fetchWasmStats()
    setStats(st)
  }

  const resetUploadForm = () => {
    setInputName('')
    setInputVersion('1.0.0')
    setInputDesc('')
    setInputAuthor('')
    setInputSourceCode('')
    setInputHookType('on_request')
    setInputCodeType('wat')
    setInputFuelLimit(50000)
    setInputFailOpen(true)
  }

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault()
    const updated = await updateWasmConfig({
      enabled: cfgEnabled,
      defaultFuelLimit: cfgFuel,
      failOpenDefault: cfgFailOpen,
      runtimeEngine: config?.runtimeEngine || 'Wasmtime 46.0.0',
      maxMemoryMB: cfgMaxMem,
      features: config?.features || ['url_contains', 'method_eq', 'set_request_header', 'deny'],
    })
    setConfig(updated)
    setConfigModalOpen(false)
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (!inputName) setInputName(file.name.replace(/\.[^/.]+$/, ''))
    if (file.name.endsWith('.wat')) setInputCodeType('wat')
    else if (file.name.endsWith('.wasm')) setInputCodeType('wasm')

    const reader = new FileReader()
    reader.onload = (event) => {
      setInputSourceCode((event.target?.result as string) || '')
    }
    reader.readAsText(file)
  }

  const filteredPlugins = plugins.filter(
    (p) =>
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase())),
  )

  return (
    <div className="space-y-6">
      <PreviewBanner feature="Wasm plugin management" />
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2.5 text-2xl font-bold text-text-primary">
            <Cpu className="size-7 text-accent" />
            Wasm Plugins & Request Hooks
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            Manage Wasmtime request hooks, fuel limits, sandbox evaluation, and custom WAT/WASM modules.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="secondary" onClick={() => setConfigModalOpen(true)}>
            <Settings className="size-4" />
            Wasm Settings
          </Button>
          <Button variant="primary" onClick={() => setUploadModalOpen(true)}>
            <Plus className="size-4" />
            Upload / Compile Plugin
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Runtime Status */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Wasmtime Host Engine
            </span>
            <span
              className={`rounded-full px-2 py-0.5 text-xs font-bold ${
                config?.enabled ? 'bg-success/20 text-success' : 'bg-danger/20 text-danger'
              }`}
            >
              {config?.enabled ? 'ACTIVE' : 'DISABLED'}
            </span>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">Wasmtime v46</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Fuel default: {config?.defaultFuelLimit?.toLocaleString()} · Fail-open: {config?.failOpenDefault ? 'Yes' : 'No'}
          </div>
        </div>

        {/* Active Plugins */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Active Hooks
            </span>
            <Layers className="size-4 text-accent" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">
              {stats?.activePlugins || 0} / {stats?.totalPlugins || 0}
            </span>
            <span className="text-xs font-medium text-success">Loaded in memory</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Hook stage: <strong className="text-text-primary font-mono">on_request</strong>
          </div>
        </div>

        {/* Evaluated Requests */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Evaluated (24h)
            </span>
            <Zap className="size-4 text-warning" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">
              {stats ? stats.totalExecutions.toLocaleString() : '0'}
            </span>
            <span className="text-xs text-accent font-semibold">
              {stats ? ((stats.denyCount / stats.totalExecutions) * 100).toFixed(1) : 0}% Denied
            </span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Total denied: {stats?.denyCount?.toLocaleString()} requests
          </div>
        </div>

        {/* Avg Latency */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Avg Hook Latency
            </span>
            <ShieldCheck className="size-4 text-success" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-success">
              {stats?.avgExecutionMs || 0.08} ms
            </span>
            <span className="text-xs text-text-secondary font-mono">Cranelift JIT</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Zero WASI network/FS overhead
          </div>
        </div>
      </div>

      {/* WebAssembly Request Hook Sandbox */}
      <div className="rounded-xl border border-border bg-surface-1 p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-3">
          <Play className="size-5 text-accent" />
          <h2 className="text-base font-semibold text-text-primary">Wasm Request Hook Sandbox Evaluator</h2>
        </div>
        <p className="text-xs text-text-secondary mb-4">
          Simulate inbound HTTP requests against loaded Wasm modules. Tests exports (<code className="text-accent">on_request</code>) and host imports (<code className="text-text-primary">url_contains</code>, <code className="text-text-primary font-mono">set_request_header</code>, <code className="text-text-primary">deny</code>).
        </p>

        <form onSubmit={handleTestSandbox} className="grid grid-cols-1 gap-3 sm:grid-cols-12">
          <div className="sm:col-span-2">
            <select
              value={testMethod}
              onChange={(e) => setTestMethod(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-0 py-2 px-3 text-sm font-mono text-text-primary focus:border-accent focus:outline-none"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>

          <div className="sm:col-span-6">
            <input
              type="text"
              placeholder="https://evil.blocked.test/phish or https://example.com/ok"
              value={testUrl}
              onChange={(e) => setTestUrl(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-0 py-2 px-3 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </div>

          <div className="sm:col-span-2">
            <input
              type="text"
              placeholder="Client IP (192.168.1.50)"
              value={testClientIp}
              onChange={(e) => setTestClientIp(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-0 py-2 px-3 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </div>

          <div className="sm:col-span-2">
            <Button type="submit" disabled={testing} className="w-full">
              {testing ? <RefreshCw className="size-4 animate-spin" /> : <Play className="size-4" />}
              Run Hook
            </Button>
          </div>
        </form>

        {testResult && (
          <div
            className={`mt-4 rounded-md border p-4 transition-all ${
              testResult.decision === 'DENY'
                ? 'border-accent/40 bg-accent/10'
                : 'border-success/40 bg-success/10'
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-3">
              <div className="flex items-center gap-2">
                {testResult.decision === 'DENY' ? (
                  <XCircle className="size-5 text-accent" />
                ) : (
                  <CheckCircle2 className="size-5 text-success" />
                )}
                <span className="font-bold text-text-primary">Decision: {testResult.decision}</span>
                <span className="text-xs text-text-secondary">({testResult.executedPluginName})</span>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono">
                <span className="text-text-secondary">Latency: <strong>{testResult.executionTimeMs}ms</strong></span>
                <span className="text-text-secondary">Fuel used: <strong className="text-accent">{testResult.fuelConsumed}</strong></span>
              </div>
            </div>

            <div className="mt-3 space-y-2 text-xs">
              {testResult.decision === 'DENY' && testResult.denyReason && (
                <div>
                  <span className="text-text-secondary">Deny Reason: </span>
                  <span className="font-mono text-accent font-semibold">{testResult.denyReason}</span>
                </div>
              )}

              {testResult.setHeaders && Object.keys(testResult.setHeaders).length > 0 && (
                <div>
                  <span className="text-text-secondary">Injected Headers: </span>
                  <div className="mt-1 flex flex-wrap gap-2">
                    {Object.entries(testResult.setHeaders).map(([k, v]) => (
                      <span key={k} className="rounded border border-border bg-surface-0 px-2 py-0.5 font-mono text-success">
                        {k}: {v}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Search & Filter */}
      <div className="flex items-center justify-between gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-secondary" />
          <input
            type="text"
            placeholder="Search Wasm plugins by name or tag..."
            value={searchQuery}
            onChange={(e) => startTransition(() => setSearchQuery(e.target.value))}
            className="w-full rounded-md border border-border bg-surface-0 py-1.5 pl-9 pr-3 text-xs text-text-primary focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      {/* Plugins Directory Table */}
      <div className="overflow-x-auto rounded-lg border border-border bg-surface-1">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-border bg-surface-2 text-xs uppercase text-text-secondary">
            <tr>
              <th className="px-4 py-3">Plugin & Description</th>
              <th className="px-4 py-3">Format</th>
              <th className="px-4 py-3">Hook Stage</th>
              <th className="px-4 py-3">Fuel Limit</th>
              <th className="px-4 py-3">Executions (24h)</th>
              <th className="px-4 py-3">Avg Latency</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border text-text-primary">
            {filteredPlugins.map((plugin) => (
              <tr key={plugin.id} className="hover:bg-surface-2/50 transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-text-primary">{plugin.name}</span>
                    <span className="text-xs text-text-secondary font-mono">v{plugin.version}</span>
                  </div>
                  <div className="text-xs text-text-secondary line-clamp-1">{plugin.description}</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {plugin.tags.map((t) => (
                      <span
                        key={t}
                        className="rounded border border-border bg-surface-0 px-1.5 py-0.2 text-[10px] text-text-secondary"
                      >
                        {t}
                      </span>
                    ))}
                    <span className="text-[10px] text-text-secondary">by {plugin.author}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded px-2 py-0.5 text-xs font-mono font-bold ${
                      plugin.codeType === 'wat'
                        ? 'bg-accent/20 text-accent'
                        : 'bg-warning/20 text-warning'
                    }`}
                  >
                    {plugin.codeType.toUpperCase()}
                  </span>
                  <div className="text-[10px] text-text-secondary mt-0.5">{plugin.moduleSize}</div>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-text-secondary">
                  {plugin.hookType}
                </td>
                <td className="px-4 py-3 font-mono text-xs font-bold text-text-primary">
                  {plugin.fuelLimit.toLocaleString()}
                  <div className="text-[10px] text-text-secondary font-normal">
                    Fail-open: {plugin.failOpen ? 'Yes' : 'No'}
                  </div>
                </td>
                <td className="px-4 py-3 font-mono text-xs font-bold text-text-primary">
                  {plugin.execCount.toLocaleString()}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-success">
                  {plugin.avgLatencyMs} ms
                </td>
                <td className="px-4 py-3">
                  <button
                    type="button"
                    onClick={() => handleToggle(plugin.id, plugin.status)}
                    className={`rounded-full px-2.5 py-0.5 text-xs font-bold transition-colors ${
                      plugin.status === 'active'
                        ? 'bg-success/20 text-success hover:bg-success/30'
                        : 'bg-surface-3 text-text-secondary hover:bg-surface-2'
                    }`}
                  >
                    {plugin.status === 'active' ? 'ACTIVE' : 'DISABLED'}
                  </button>
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedPlugin(plugin)
                        setViewCodeModalOpen(true)
                      }}
                      className="rounded p-1.5 text-text-secondary hover:bg-surface-2 hover:text-text-primary"
                      title="View Code / WAT Source"
                    >
                      <Code2 className="size-4" />
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDelete(plugin.id)}
                      className="rounded p-1.5 text-danger/70 hover:bg-danger/20 hover:text-danger"
                      title="Delete Plugin"
                    >
                      <Trash2 className="size-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Modal: View / Edit WAT Code */}
      <Modal
        open={viewCodeModalOpen}
        onClose={() => setViewCodeModalOpen(false)}
        title={`Wasm Module Code: ${selectedPlugin?.name || ''}`}
        wide
        footer={
          <Button variant="ghost" onClick={() => setViewCodeModalOpen(false)}>
            Close
          </Button>
        }
      >
        {selectedPlugin && (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-text-secondary">
              <span>Format: <strong className="font-mono text-text-primary">{selectedPlugin.codeType.toUpperCase()}</strong></span>
              <span>Fuel Limit: <strong className="font-mono text-accent">{selectedPlugin.fuelLimit.toLocaleString()}</strong></span>
              <span>Size: <strong className="font-mono text-text-primary">{selectedPlugin.moduleSize}</strong></span>
            </div>
            <pre className="max-h-96 overflow-y-auto rounded-md border border-border bg-surface-0 p-4 font-mono text-xs leading-relaxed text-success whitespace-pre-wrap">
              {selectedPlugin.sourceCode || ';; No source code available'}
            </pre>
          </div>
        )}
      </Modal>

      {/* Modal: Upload & Compile Plugin */}
      <Modal
        open={uploadModalOpen}
        onClose={() => setUploadModalOpen(false)}
        title="Upload & Compile Wasm Plugin"
        wide
        footer={
          <>
            <Button variant="ghost" onClick={() => setUploadModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleUploadPlugin} disabled={!inputName || !inputSourceCode}>
              <Plus className="size-4" />
              Compile & Install Hook
            </Button>
          </>
        }
      >
        <form onSubmit={handleUploadPlugin} className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label="Plugin Name" required>
              <input
                type="text"
                placeholder="e.g. Auth Token Verifier"
                value={inputName}
                onChange={(e) => setInputName(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>

            <FormField label="Version">
              <input
                type="text"
                value={inputVersion}
                onChange={(e) => setInputVersion(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          </div>

          <FormField label="Description">
            <input
              type="text"
              placeholder="Short description of what this request hook does"
              value={inputDesc}
              onChange={(e) => setInputDesc(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </FormField>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <FormField label="Hook Stage">
              <select
                value={inputHookType}
                onChange={(e) => setInputHookType(e.target.value as WasmHookType)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              >
                <option value="on_request">on_request (Inbound request)</option>
                <option value="on_response">on_response (Outbound header/body)</option>
              </select>
            </FormField>

            <FormField label="Format">
              <select
                value={inputCodeType}
                onChange={(e) => setInputCodeType(e.target.value as WasmCodeType)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              >
                <option value="wat">WebAssembly Text (.wat)</option>
                <option value="wasm">Compiled Binary (.wasm)</option>
              </select>
            </FormField>

            <FormField label="Fuel Instruction Limit">
              <input
                type="number"
                value={inputFuelLimit}
                onChange={(e) => setInputFuelLimit(Number(e.target.value))}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          </div>

          <FormField label="Select File (.wat or .wasm)">
            <input
              type="file"
              accept=".wat,.wasm"
              onChange={handleFileUpload}
              className="w-full text-xs text-text-secondary file:mr-4 file:rounded-md file:border-0 file:bg-surface-2 file:px-4 file:py-2 file:text-xs file:font-semibold file:text-text-primary hover:file:bg-surface-3"
            />
          </FormField>

          <FormField label="WAT Source Code / Code Editor">
            <textarea
              rows={8}
              placeholder="(module ...)"
              value={inputSourceCode}
              onChange={(e) => setInputSourceCode(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-0 p-3 font-mono text-xs text-text-primary focus:border-accent focus:outline-none"
            />
          </FormField>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="failOpenInput"
              checked={inputFailOpen}
              onChange={(e) => setInputFailOpen(e.target.checked)}
              className="size-4 rounded border-border text-accent focus:ring-accent"
            />
            <label htmlFor="failOpenInput" className="text-xs text-text-primary">
              Fail-open strategy (Allow request if Wasm module panics or traps)
            </label>
          </div>
        </form>
      </Modal>

      {/* Modal: Wasm Settings */}
      <Modal
        open={configModalOpen}
        onClose={() => setConfigModalOpen(false)}
        title="Wasmtime Host Engine Settings"
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfigModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleSaveConfig}>
              Save Wasm Config
            </Button>
          </>
        }
      >
        <form onSubmit={handleSaveConfig} className="space-y-4">
          <div className="flex items-center justify-between rounded-md border border-border bg-surface-0 p-3">
            <div>
              <div className="text-sm font-semibold text-text-primary">Enable Wasm Host Engine</div>
              <div className="text-xs text-text-secondary">Executes compiled WebAssembly request hooks on incoming traffic</div>
            </div>
            <input
              type="checkbox"
              checked={cfgEnabled}
              onChange={(e) => setCfgEnabled(e.target.checked)}
              className="size-5 rounded border-border text-accent focus:ring-accent"
            />
          </div>

          <FormField label="Default Fuel Limit per Hook Execution">
            <input
              type="number"
              value={cfgFuel}
              onChange={(e) => setCfgFuel(Number(e.target.value))}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </FormField>

          <FormField label="Max Memory Limit per Wasm Instance (MB)">
            <input
              type="number"
              value={cfgMaxMem}
              onChange={(e) => setCfgMaxMem(Number(e.target.value))}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </FormField>

          <div className="flex items-center gap-2 pt-2">
            <input
              type="checkbox"
              id="cfgFailOpenCheck"
              checked={cfgFailOpen}
              onChange={(e) => setCfgFailOpen(e.target.checked)}
              className="size-4 rounded border-border text-accent focus:ring-accent"
            />
            <label htmlFor="cfgFailOpenCheck" className="text-xs text-text-primary">
              Global Fail-Open (Pass request if execution traps or exceeds fuel)
            </label>
          </div>
        </form>
      </Modal>
    </div>
  )
}
