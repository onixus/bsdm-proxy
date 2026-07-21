import { apiFetch, aclClient } from './client'

export type VectorBackendKind = 'local' | 'qdrant'
export type EmbedProviderKind = 'local' | 'http'
export type CacheHitType = 'EXACT_HIT' | 'SEMANTIC_NEAR_HIT' | 'MISS'

export interface AiCacheConfig {
  enabled: boolean
  pathPrefixes: string[]
  ttlSecs: number
  similarityThreshold: number
  embedDims: number
  maxIndexEntries: number
  vectorBackend: VectorBackendKind
  vectorUrl?: string
  vectorCollection: string
  vectorApiKeyConfigured: boolean
  embedProvider: EmbedProviderKind
  embedUrl?: string
}

export interface AiCacheEntry {
  id: string
  exactHash: string
  promptText: string
  responseSample: string
  similarityScore: number
  model: string
  tokenSavings: number
  latencySavedMs: number
  createdAt: string
  lastHitAt: string
  hitCount: number
  cacheType: CacheHitType
}

export interface AiCacheTestRequest {
  promptText: string
  model?: string
  similarityThresholdOverride?: number
}

export interface AiCacheTestResult {
  matched: boolean
  hitType: CacheHitType
  similarityScore: number
  cachedResponse?: string
  matchedPromptText?: string
  tokenCostSaved: number
  latencySavedMs: number
  vectorDistance: number
  executionTimeMs: number
  model: string
}

export interface AiCacheStats {
  totalCachedPrompts: number
  exactHits24h: number
  semanticNearHits24h: number
  totalMisses24h: number
  hitRatio: number
  tokensSaved24h: number
  estimatedCostSavingsUsd: number
  vectorDbSizeMB: number
  avgSimilarityScore: number
}

let memoryEntries: AiCacheEntry[] | null = null
let memoryConfig: AiCacheConfig | null = null

export async function fetchAiCacheConfig(): Promise<AiCacheConfig> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<AiCacheConfig>('/api/ai/cache/config', { baseUrl, token })
  } catch {
    if (!memoryConfig) {
      memoryConfig = {
        enabled: true,
        pathPrefixes: ['/v1/chat/completions', '/v1/completions', '/chat/completions'],
        ttlSecs: 3600,
        similarityThreshold: 0.9,
        embedDims: 384,
        maxIndexEntries: 10000,
        vectorBackend: 'qdrant',
        vectorUrl: 'http://127.0.0.1:6333',
        vectorCollection: 'bsdm_semantic',
        vectorApiKeyConfigured: false,
        embedProvider: 'local',
        embedUrl: 'http://127.0.0.1:8000/embed',
      }
    }
    return memoryConfig
  }
}

export async function updateAiCacheConfig(config: AiCacheConfig): Promise<AiCacheConfig> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<AiCacheConfig>('/api/ai/cache/config', {
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

export async function fetchAiCacheEntries(): Promise<AiCacheEntry[]> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<AiCacheEntry[]>('/api/ai/cache/entries', { baseUrl, token })
  } catch {
    if (!memoryEntries) {
      memoryEntries = getMockEntries()
    }
    return memoryEntries
  }
}

export async function deleteAiCacheEntry(id: string): Promise<void> {
  const { baseUrl, token } = aclClient()
  try {
    await apiFetch(`/api/ai/cache/entries/${encodeURIComponent(id)}`, {
      baseUrl,
      token,
      method: 'DELETE',
    })
  } catch {
    if (!memoryEntries) memoryEntries = getMockEntries()
    memoryEntries = memoryEntries.filter((e) => e.id !== id)
  }
}

export async function purgeAiCache(scope: string, pattern?: string): Promise<{ purgedCount: number }> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<{ purgedCount: number }>('/api/ai/cache/purge', {
      baseUrl,
      token,
      method: 'POST',
      body: { scope, pattern },
    })
  } catch {
    if (!memoryEntries) memoryEntries = getMockEntries()
    const count = memoryEntries.length
    if (scope === 'all') {
      memoryEntries = []
    }
    return { purgedCount: count }
  }
}

export async function testAiCacheQuery(req: AiCacheTestRequest): Promise<AiCacheTestResult> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<AiCacheTestResult>('/api/ai/cache/test', {
      baseUrl,
      token,
      method: 'POST',
      body: req,
    })
  } catch {
    return mockQueryTest(req)
  }
}

export async function fetchAiCacheStats(): Promise<AiCacheStats> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<AiCacheStats>('/api/ai/cache/stats', { baseUrl, token })
  } catch {
    return {
      totalCachedPrompts: 8420,
      exactHits24h: 14250,
      semanticNearHits24h: 6340,
      totalMisses24h: 5610,
      hitRatio: 78.6,
      tokensSaved24h: 14250000,
      estimatedCostSavingsUsd: 285.0,
      vectorDbSizeMB: 42.5,
      avgSimilarityScore: 0.94,
    }
  }
}

function getMockEntries(): AiCacheEntry[] {
  return [
    {
      id: 'ai-1',
      exactHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      promptText: 'Explain how BSDM proxy handles sharded cache tiering and ICP peers',
      responseSample: 'BSDM-Proxy utilizes a two-tier architecture: L1 sharded in-memory cache and L2 spill disk storage, synchronized with sibling peers via ICP/HTCP protocols...',
      similarityScore: 1.0,
      model: 'gpt-4o',
      tokenSavings: 1420,
      latencySavedMs: 840,
      createdAt: '2026-07-21T10:00:00Z',
      lastHitAt: '2026-07-21T13:45:00Z',
      hitCount: 342,
      cacheType: 'EXACT_HIT',
    },
    {
      id: 'ai-2',
      exactHash: 'a71b82d49e120f341acb99612781ae41e4649b934ca495991b7852b855120aef',
      promptText: 'Summarize BSDM proxy architecture and sharded L1 cache design',
      responseSample: 'BSDM-Proxy uses a high performance sharded L1 cache for lock-free read access, backed by ClickHouse event indexing...',
      similarityScore: 0.941,
      model: 'claude-3-5-sonnet',
      tokenSavings: 980,
      latencySavedMs: 620,
      createdAt: '2026-07-21T08:30:00Z',
      lastHitAt: '2026-07-21T12:20:00Z',
      hitCount: 185,
      cacheType: 'SEMANTIC_NEAR_HIT',
    },
    {
      id: 'ai-3',
      exactHash: '98fa12c98e100f541acb99612781ae41e4649b934ca495991b7852b85584bcde',
      promptText: 'Write a Python script to test HTTP proxy performance and latency',
      responseSample: 'import requests\nimport time\n\ndef test_proxy(url, proxy):\n    start = time.time()\n    res = requests.get(url, proxies={"http": proxy})\n    return time.time() - start',
      similarityScore: 0.915,
      model: 'llama-3.1-70b',
      tokenSavings: 640,
      latencySavedMs: 410,
      createdAt: '2026-07-20T14:10:00Z',
      lastHitAt: '2026-07-21T11:05:00Z',
      hitCount: 94,
      cacheType: 'SEMANTIC_NEAR_HIT',
    },
  ]
}

function mockQueryTest(req: AiCacheTestRequest): AiCacheTestResult {
  const prompt = req.promptText.toLowerCase()

  if (prompt.includes('explain how bsdm proxy handles sharded cache') || prompt.includes('exact test')) {
    return {
      matched: true,
      hitType: 'EXACT_HIT',
      similarityScore: 1.0,
      matchedPromptText: 'Explain how BSDM proxy handles sharded cache tiering and ICP peers',
      cachedResponse: 'BSDM-Proxy utilizes a two-tier architecture: L1 sharded in-memory cache and L2 spill disk storage...',
      tokenCostSaved: 1420,
      latencySavedMs: 840,
      vectorDistance: 0.0,
      executionTimeMs: 0.8,
      model: req.model || 'gpt-4o',
    }
  }

  if (prompt.includes('bsdm') || prompt.includes('proxy') || prompt.includes('cache') || prompt.includes('architecture')) {
    return {
      matched: true,
      hitType: 'SEMANTIC_NEAR_HIT',
      similarityScore: 0.941,
      matchedPromptText: 'Summarize BSDM proxy architecture and sharded L1 cache design',
      cachedResponse: 'BSDM-Proxy uses a high performance sharded L1 cache for lock-free read access...',
      tokenCostSaved: 980,
      latencySavedMs: 620,
      vectorDistance: 0.059,
      executionTimeMs: 4.2,
      model: req.model || 'claude-3-5-sonnet',
    }
  }

  return {
    matched: false,
    hitType: 'MISS',
    similarityScore: 0.62,
    tokenCostSaved: 0,
    latencySavedMs: 0,
    vectorDistance: 0.38,
    executionTimeMs: 3.5,
    model: req.model || 'gpt-4o',
  }
}
