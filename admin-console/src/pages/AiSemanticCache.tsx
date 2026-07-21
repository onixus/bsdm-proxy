import { useState, useEffect, useTransition } from 'react'
import {
  Sparkles,
  Play,
  Settings,
  Trash2,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Zap,
  Flame,
  DollarSign,
  TrendingUp,
} from 'lucide-react'

import {
  fetchAiCacheConfig,
  updateAiCacheConfig,
  fetchAiCacheEntries,
  deleteAiCacheEntry,
  purgeAiCache,
  testAiCacheQuery,
  fetchAiCacheStats,
  type AiCacheConfig,
  type AiCacheEntry,
  type AiCacheTestResult,
  type AiCacheStats,
  type VectorBackendKind,
  type EmbedProviderKind,
} from '../api/aiCache'

import { Button } from '../components/ui/Button'
import { Modal } from '../components/ui/Modal'
import { FormField } from '../components/ui/Form'

export function AiSemanticCachePage() {
  const [, startTransition] = useTransition()
  const [config, setConfig] = useState<AiCacheConfig | null>(null)
  const [entries, setEntries] = useState<AiCacheEntry[]>([])
  const [stats, setStats] = useState<AiCacheStats | null>(null)

  const [activeTab, setActiveTab] = useState<'entries' | 'vectordb' | 'analytics'>('entries')
  const [searchQuery, setSearchQuery] = useState('')

  // Tester state
  const [testPrompt, setTestPrompt] = useState('Summarize BSDM proxy architecture and sharded L1 cache design')
  const [testModel, setTestModel] = useState('gpt-4o')
  const [testThreshold, setTestThreshold] = useState(0.90)
  const [testResult, setTestResult] = useState<AiCacheTestResult | null>(null)
  const [testing, setTesting] = useState(false)

  // Modals state
  const [purgeModalOpen, setPurgeModalOpen] = useState(false)
  const [configModalOpen, setConfigModalOpen] = useState(false)
  const [purgeScope, setPurgeScope] = useState('all')
  const [purgePattern, setPurgePattern] = useState('')
  const [purging, setPurging] = useState(false)
  const [purgeMsg, setPurgeMsg] = useState<string | null>(null)

  // Config Form
  const [cfgEnabled, setCfgEnabled] = useState(true)
  const [cfgThreshold, setCfgThreshold] = useState(0.90)
  const [cfgTtlSecs, setCfgTtlSecs] = useState(3600)
  const [cfgDims, setCfgDims] = useState(384)
  const [cfgBackend, setCfgBackend] = useState<VectorBackendKind>('qdrant')
  const [cfgVectorUrl, setCfgVectorUrl] = useState('http://127.0.0.1:6333')
  const [cfgCollection, setCfgCollection] = useState('bsdm_semantic')
  const [cfgEmbedProvider, setCfgEmbedProvider] = useState<EmbedProviderKind>('local')
  const [cfgPrefixes, setCfgPrefixes] = useState('/v1/chat/completions, /v1/completions, /chat/completions')

  const loadData = async () => {
    try {
      const [cfg, eList, st] = await Promise.all([
        fetchAiCacheConfig(),
        fetchAiCacheEntries(),
        fetchAiCacheStats(),
      ])
      setConfig(cfg)
      setEntries(eList)
      setStats(st)

      if (cfg) {
        setCfgEnabled(cfg.enabled)
        setCfgThreshold(cfg.similarityThreshold)
        setCfgTtlSecs(cfg.ttlSecs)
        setCfgDims(cfg.embedDims)
        setCfgBackend(cfg.vectorBackend)
        setCfgVectorUrl(cfg.vectorUrl || 'http://127.0.0.1:6333')
        setCfgCollection(cfg.vectorCollection)
        setCfgEmbedProvider(cfg.embedProvider)
        setCfgPrefixes(cfg.pathPrefixes.join(', '))
      }
    } catch (err) {
      console.error('Error loading AI Cache data:', err)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleTestQuery = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!testPrompt.trim()) return
    setTesting(true)
    try {
      const res = await testAiCacheQuery({
        promptText: testPrompt.trim(),
        model: testModel,
        similarityThresholdOverride: testThreshold,
      })
      setTestResult(res)
    } finally {
      setTesting(false)
    }
  }

  const handleDeleteEntry = async (id: string) => {
    if (!window.confirm('Delete this cached prompt entry?')) return
    setEntries((prev) => prev.filter((e) => e.id !== id))
    await deleteAiCacheEntry(id)
    const st = await fetchAiCacheStats()
    setStats(st)
  }

  const handlePurge = async (e: React.FormEvent) => {
    e.preventDefault()
    setPurging(true)
    try {
      const res = await purgeAiCache(purgeScope, purgePattern)
      setPurgeMsg(`Purged ${res.purgedCount} cached LLM prompts from memory & vector DB`)
      setPurgeModalOpen(false)
      loadData()
      setTimeout(() => setPurgeMsg(null), 4000)
    } finally {
      setPurging(false)
    }
  }

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault()
    const prefixesArray = cfgPrefixes
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0)

    const updated = await updateAiCacheConfig({
      enabled: cfgEnabled,
      pathPrefixes: prefixesArray,
      ttlSecs: cfgTtlSecs,
      similarityThreshold: cfgThreshold,
      embedDims: cfgDims,
      maxIndexEntries: config?.maxIndexEntries || 10000,
      vectorBackend: cfgBackend,
      vectorUrl: cfgVectorUrl,
      vectorCollection: cfgCollection,
      vectorApiKeyConfigured: config?.vectorApiKeyConfigured ?? false,
      embedProvider: cfgEmbedProvider,
      embedUrl: config?.embedUrl || 'http://127.0.0.1:8000/embed',
    })
    setConfig(updated)
    setConfigModalOpen(false)
  }

  const filteredEntries = entries.filter(
    (e) =>
      e.promptText.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.responseSample.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.model.toLowerCase().includes(searchQuery.toLowerCase()),
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2.5 text-2xl font-bold text-text-primary">
            <Sparkles className="size-7 text-accent" />
            AI & LLM Semantic Cache Dashboard
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            Content-addressable POST caching + Qdrant vector similarity search for LLM API prompts (/v1/chat/completions).
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="secondary" onClick={() => setConfigModalOpen(true)}>
            <Settings className="size-4" />
            AI Cache Settings
          </Button>
          <Button variant="secondary" onClick={() => setPurgeModalOpen(true)}>
            <Flame className="size-4 text-warning" />
            Purge AI Cache
          </Button>
        </div>
      </div>

      {purgeMsg && (
        <div className="rounded-md border border-success/40 bg-success/10 p-3 text-xs font-semibold text-success flex items-center gap-2">
          <CheckCircle2 className="size-4" />
          {purgeMsg}
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Status */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Vector DB Engine
            </span>
            <span
              className={`rounded-full px-2 py-0.5 text-xs font-bold ${
                config?.enabled ? 'bg-success/20 text-success' : 'bg-danger/20 text-danger'
              }`}
            >
              {config?.enabled ? 'QDRANT ACTIVE' : 'PAUSED'}
            </span>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">
              {config?.vectorBackend.toUpperCase() || 'QDRANT'}
            </span>
            <span className="text-xs font-mono text-accent">
              Collection: {config?.vectorCollection || 'bsdm_semantic'}
            </span>
          </div>
          <div className="mt-2 text-xs text-text-secondary truncate">
            URL: {config?.vectorUrl || 'http://127.0.0.1:6333'}
          </div>
        </div>

        {/* Tokens Saved */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Tokens Saved (24h)
            </span>
            <Zap className="size-4 text-accent" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">
              {stats ? (stats.tokensSaved24h / 1000000).toFixed(2) : 0}M
            </span>
            <span className="text-xs text-text-secondary">Tokens</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Avoided redundant LLM inference calls
          </div>
        </div>

        {/* Cost Savings */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Est. Cost Savings (24h)
            </span>
            <DollarSign className="size-4 text-success" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-success">
              ${stats?.estimatedCostSavingsUsd.toFixed(2) || '285.00'}
            </span>
            <span className="text-xs text-success font-semibold">USD</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Based on OpenAI / Claude pricing
          </div>
        </div>

        {/* Hit Ratio */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Combined Hit Ratio
            </span>
            <TrendingUp className="size-4 text-accent" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-text-primary">
              {stats?.hitRatio || 78.6}%
            </span>
            <span className="text-xs text-success font-semibold">
              Exact + Near-Hit
            </span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            Similarity Threshold: <strong className="text-accent">{config?.similarityThreshold || 0.9}</strong>
          </div>
        </div>
      </div>

      {/* Interactive LLM Vector Match Simulator */}
      <div className="rounded-xl border border-border bg-surface-1 p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-3">
          <Play className="size-5 text-accent" />
          <h2 className="text-base font-semibold text-text-primary">LLM Semantic Similarity Vector Match Simulator</h2>
        </div>
        <p className="text-xs text-text-secondary mb-4">
          Test prompt texts against the Qdrant vector index. Exact hits use SHA-256 POST body hash; near-hits use cosine similarity.
        </p>

        <form onSubmit={handleTestQuery} className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-12">
            <div className="sm:col-span-8">
              <input
                type="text"
                placeholder="Enter prompt text (e.g. Summarize BSDM proxy architecture and sharded L1 cache design)..."
                value={testPrompt}
                onChange={(e) => setTestPrompt(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 py-2 px-3 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </div>

            <div className="sm:col-span-2">
              <select
                value={testModel}
                onChange={(e) => setTestModel(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 py-2 px-3 text-sm font-mono text-text-primary focus:border-accent focus:outline-none"
              >
                <option value="gpt-4o">gpt-4o</option>
                <option value="claude-3-5-sonnet">claude-3-5-sonnet</option>
                <option value="llama-3.1-70b">llama-3.1-70b</option>
              </select>
            </div>

            <div className="sm:col-span-2">
              <Button type="submit" disabled={testing} className="w-full">
                {testing ? <RefreshCw className="size-4 animate-spin" /> : <Play className="size-4" />}
                Simulate Query
              </Button>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <span className="text-text-secondary">Similarity Threshold: <strong className="font-mono text-accent">{testThreshold}</strong></span>
            <input
              type="range"
              min="0.70"
              max="1.00"
              step="0.01"
              value={testThreshold}
              onChange={(e) => setTestThreshold(Number(e.target.value))}
              className="w-48 accent-accent"
            />
            <span className="text-text-secondary font-mono">(1.0 = Exact match only)</span>
          </div>
        </form>

        {testResult && (
          <div
            className={`mt-4 rounded-md border p-4 transition-all ${
              testResult.matched
                ? 'border-success/40 bg-success/10'
                : 'border-border bg-surface-0'
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-3">
              <div className="flex items-center gap-2">
                {testResult.matched ? (
                  <CheckCircle2 className="size-5 text-success" />
                ) : (
                  <XCircle className="size-5 text-text-secondary" />
                )}
                <span className="font-bold text-text-primary">
                  Result: {testResult.hitType}
                </span>
                {testResult.matched && (
                  <span className="rounded bg-success/20 px-2 py-0.5 text-xs font-mono font-bold text-success">
                    Similarity: {(testResult.similarityScore * 100).toFixed(1)}%
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3 text-xs font-mono">
                <span className="text-text-secondary">Tokens saved: <strong className="text-accent">{testResult.tokenCostSaved}</strong></span>
                <span className="text-text-secondary">Latency saved: <strong className="text-success">{testResult.latencySavedMs}ms</strong></span>
              </div>
            </div>

            {testResult.matched ? (
              <div className="mt-3 space-y-2 text-xs">
                <div>
                  <span className="text-text-secondary">Matched Cached Prompt: </span>
                  <span className="font-mono text-text-primary">{testResult.matchedPromptText}</span>
                </div>
                <div>
                  <span className="text-text-secondary">Cached LLM Response Sample: </span>
                  <pre className="mt-1 rounded bg-surface-0 p-2 font-mono text-[11px] text-success leading-relaxed whitespace-pre-wrap">
                    {testResult.cachedResponse}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="mt-2 text-xs text-text-secondary">
                No vector match above threshold {testThreshold}. Query forwarded upstream to LLM provider.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Main Tabs */}
      <div className="flex flex-col justify-between border-b border-border sm:flex-row sm:items-center">
        <div className="flex space-x-4">
          <button
            type="button"
            onClick={() => setActiveTab('entries')}
            className={`border-b-2 py-3 px-1 text-sm font-semibold transition-colors ${
              activeTab === 'entries'
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            Cached Prompts ({entries.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('vectordb')}
            className={`border-b-2 py-3 px-1 text-sm font-semibold transition-colors ${
              activeTab === 'vectordb'
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            Vector DB & Qdrant Collections
          </button>
        </div>

        {activeTab === 'entries' && (
          <div className="py-2">
            <input
              type="text"
              placeholder="Search cached prompts..."
              value={searchQuery}
              onChange={(e) => startTransition(() => setSearchQuery(e.target.value))}
              className="rounded-md border border-border bg-surface-0 px-3 py-1 text-xs text-text-primary focus:border-accent focus:outline-none"
            />
          </div>
        )}
      </div>

      {/* Tab 1: Cached Prompts Directory */}
      {activeTab === 'entries' && (
        <div className="overflow-x-auto rounded-lg border border-border bg-surface-1">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-surface-2 text-xs uppercase text-text-secondary">
              <tr>
                <th className="px-4 py-3">Prompt Text & Model</th>
                <th className="px-4 py-3">Exact SHA-256 Hash</th>
                <th className="px-4 py-3">Cache Type</th>
                <th className="px-4 py-3">Tokens Saved</th>
                <th className="px-4 py-3">Hit Count</th>
                <th className="px-4 py-3">Last Hit</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border text-text-primary">
              {filteredEntries.map((e) => (
                <tr key={e.id} className="hover:bg-surface-2/50 transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-semibold text-text-primary">{e.promptText}</div>
                    <div className="text-xs text-text-secondary font-mono">Model: {e.model}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-accent max-w-xs truncate" title={e.exactHash}>
                    {e.exactHash.substring(0, 16)}...
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-mono font-bold ${
                        e.cacheType === 'EXACT_HIT'
                          ? 'bg-success/20 text-success'
                          : 'bg-accent/20 text-accent'
                      }`}
                    >
                      {e.cacheType}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs font-bold text-text-primary">
                    {e.tokenSavings.toLocaleString()}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-text-primary">{e.hitCount}</td>
                  <td className="px-4 py-3 text-xs text-text-secondary">
                    {new Date(e.lastHitAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => handleDeleteEntry(e.id)}
                      className="rounded p-1.5 text-danger/70 hover:bg-danger/20 hover:text-danger"
                      title="Delete Entry"
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

      {/* Tab 2: Vector DB & Qdrant Collections */}
      {activeTab === 'vectordb' && (
        <div className="rounded-lg border border-border bg-surface-1 p-5 space-y-4">
          <h3 className="text-base font-bold text-text-primary">Qdrant Vector Database Integration Overview</h3>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="rounded-md border border-border bg-surface-0 p-4 space-y-2">
              <div className="text-xs font-semibold uppercase text-text-secondary">Collection Name</div>
              <div className="font-mono text-lg font-bold text-accent">{config?.vectorCollection || 'bsdm_semantic'}</div>
              <div className="text-xs text-text-secondary">Distance Metric: <strong className="text-text-primary font-mono">Cosine</strong></div>
            </div>

            <div className="rounded-md border border-border bg-surface-0 p-4 space-y-2">
              <div className="text-xs font-semibold uppercase text-text-secondary">Vector Dimensions</div>
              <div className="font-mono text-lg font-bold text-success">{config?.embedDims || 384} Dims</div>
              <div className="text-xs text-text-secondary">Embed Provider: <strong className="text-text-primary font-mono">{config?.embedProvider || 'local'}</strong></div>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Purge AI Cache */}
      <Modal
        open={purgeModalOpen}
        onClose={() => setPurgeModalOpen(false)}
        title="Purge AI Semantic Cache"
        footer={
          <>
            <Button variant="ghost" onClick={() => setPurgeModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handlePurge} disabled={purging}>
              <Flame className="size-4" />
              Purge Cache Entries
            </Button>
          </>
        }
      >
        <form onSubmit={handlePurge} className="space-y-4">
          <FormField label="Purge Scope">
            <select
              value={purgeScope}
              onChange={(e) => setPurgeScope(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            >
              <option value="all">Purge ALL AI Cached Prompts & Vector Collections</option>
              <option value="hash">Exact SHA-256 Hash</option>
            </select>
          </FormField>

          {purgeScope === 'hash' && (
            <FormField label="SHA-256 Hash Pattern">
              <input
                type="text"
                placeholder="e3b0c44298fc1c149afbf4c8996fb924..."
                value={purgePattern}
                onChange={(e) => setPurgePattern(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          )}
        </form>
      </Modal>

      {/* Modal: AI Cache Settings */}
      <Modal
        open={configModalOpen}
        onClose={() => setConfigModalOpen(false)}
        title="AI & LLM Semantic Cache Settings"
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
              <div className="text-sm font-semibold text-text-primary">Enable AI Semantic Cache</div>
              <div className="text-xs text-text-secondary">Caches POST /v1/chat/completions exact and vector near-hits</div>
            </div>
            <input
              type="checkbox"
              checked={cfgEnabled}
              onChange={(e) => setCfgEnabled(e.target.checked)}
              className="size-5 rounded border-border text-accent focus:ring-accent"
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label="Similarity Threshold (0.0 – 1.0)">
              <input
                type="number"
                step="0.01"
                min="0.5"
                max="1.0"
                value={cfgThreshold}
                onChange={(e) => setCfgThreshold(Number(e.target.value))}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>

            <FormField label="Cache TTL (Seconds)">
              <input
                type="number"
                value={cfgTtlSecs}
                onChange={(e) => setCfgTtlSecs(Number(e.target.value))}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label="Vector Backend">
              <select
                value={cfgBackend}
                onChange={(e) => setCfgBackend(e.target.value as VectorBackendKind)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              >
                <option value="qdrant">Qdrant Vector Database</option>
                <option value="local">Local In-Memory Index</option>
              </select>
            </FormField>

            <FormField label="Qdrant URL">
              <input
                type="text"
                value={cfgVectorUrl}
                onChange={(e) => setCfgVectorUrl(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label="Vector Collection">
              <input
                type="text"
                value={cfgCollection}
                onChange={(e) => setCfgCollection(e.target.value)}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>

            <FormField label="Embed Dimensions">
              <input
                type="number"
                value={cfgDims}
                onChange={(e) => setCfgDims(Number(e.target.value))}
                className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </FormField>
          </div>

          <FormField label="Target Path Prefixes (Comma-separated)">
            <input
              type="text"
              value={cfgPrefixes}
              onChange={(e) => setCfgPrefixes(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </FormField>
        </form>
      </Modal>
    </div>
  )
}
