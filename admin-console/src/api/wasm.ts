import { apiFetch, aclClient } from './client'

export type WasmHookType = 'on_request' | 'on_response' | 'transform'
export type WasmCodeType = 'wat' | 'wasm'
export type WasmPluginStatus = 'active' | 'disabled' | 'error'

export interface WasmPlugin {
  id: string
  name: string
  version: string
  description: string
  author: string
  hookType: WasmHookType
  codeType: WasmCodeType
  status: WasmPluginStatus
  fuelLimit: number
  failOpen: boolean
  moduleSize: string
  loadedAt: string
  execCount: number
  avgLatencyMs: number
  errorCount: number
  sourceCode?: string
  tags: string[]
}

export interface WasmGlobalConfig {
  enabled: boolean
  defaultFuelLimit: number
  failOpenDefault: boolean
  runtimeEngine: string
  maxMemoryMB: number
  features: string[]
}

export interface WasmTestRequest {
  method: string
  url: string
  clientIp: string
  username?: string
  pluginId?: string
}

export interface WasmTestResult {
  decision: 'ALLOW' | 'DENY'
  denyReason?: string
  setHeaders?: Record<string, string>
  executionTimeMs: number
  fuelConsumed: number
  executedPluginName: string
}

export interface WasmStats {
  totalPlugins: number
  activePlugins: number
  totalExecutions: number
  denyCount: number
  avgExecutionMs: number
  fuelConsumption24h: number
}

export interface AddWasmPluginInput {
  name: string
  version: string
  description: string
  author: string
  hookType: WasmHookType
  codeType: WasmCodeType
  sourceCode: string
  fuelLimit: number
  failOpen: boolean
}

let memoryPlugins: WasmPlugin[] | null = null
let memoryConfig: WasmGlobalConfig | null = null

export async function fetchWasmPlugins(): Promise<WasmPlugin[]> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<WasmPlugin[]>('/api/wasm/plugins', { baseUrl, token })
  } catch {
    if (!memoryPlugins) {
      memoryPlugins = getMockPlugins()
    }
    return memoryPlugins
  }
}

export async function addWasmPlugin(input: AddWasmPluginInput): Promise<WasmPlugin> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<WasmPlugin>('/api/wasm/plugins', {
      baseUrl,
      token,
      method: 'POST',
      body: input,
    })
  } catch {
    const newPlugin: WasmPlugin = {
      id: `wasm-${Date.now()}`,
      name: input.name,
      version: input.version || '1.0.0',
      description: input.description,
      author: input.author || 'Admin',
      hookType: input.hookType,
      codeType: input.codeType,
      status: 'active',
      fuelLimit: input.fuelLimit || 50000,
      failOpen: input.failOpen,
      moduleSize: `${(input.sourceCode.length / 1024).toFixed(1)} KB`,
      loadedAt: new Date().toISOString(),
      execCount: 0,
      avgLatencyMs: 0.08,
      errorCount: 0,
      sourceCode: input.sourceCode,
      tags: ['Custom', input.codeType.toUpperCase()],
    }
    if (!memoryPlugins) memoryPlugins = getMockPlugins()
    memoryPlugins.unshift(newPlugin)
    return newPlugin
  }
}

export async function toggleWasmPlugin(id: string, active: boolean): Promise<void> {
  const { baseUrl, token } = aclClient()
  try {
    await apiFetch(`/api/wasm/plugins/${encodeURIComponent(id)}/toggle`, {
      baseUrl,
      token,
      method: 'POST',
      body: { active },
    })
  } catch {
    if (!memoryPlugins) memoryPlugins = getMockPlugins()
    const item = memoryPlugins.find((p) => p.id === id)
    if (item) item.status = active ? 'active' : 'disabled'
  }
}

export async function deleteWasmPlugin(id: string): Promise<void> {
  const { baseUrl, token } = aclClient()
  try {
    await apiFetch(`/api/wasm/plugins/${encodeURIComponent(id)}`, {
      baseUrl,
      token,
      method: 'DELETE',
    })
  } catch {
    if (!memoryPlugins) memoryPlugins = getMockPlugins()
    memoryPlugins = memoryPlugins.filter((p) => p.id !== id)
  }
}

export async function fetchWasmConfig(): Promise<WasmGlobalConfig> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<WasmGlobalConfig>('/api/wasm/config', { baseUrl, token })
  } catch {
    if (!memoryConfig) {
      memoryConfig = {
        enabled: true,
        defaultFuelLimit: 50000,
        failOpenDefault: true,
        runtimeEngine: 'Wasmtime 46.0.0 (Cranelift JIT)',
        maxMemoryMB: 16,
        features: ['url_contains', 'method_eq', 'set_request_header', 'deny'],
      }
    }
    return memoryConfig
  }
}

export async function updateWasmConfig(config: WasmGlobalConfig): Promise<WasmGlobalConfig> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<WasmGlobalConfig>('/api/wasm/config', {
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

export async function testWasmPlugin(req: WasmTestRequest): Promise<WasmTestResult> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<WasmTestResult>('/api/wasm/test', {
      baseUrl,
      token,
      method: 'POST',
      body: req,
    })
  } catch {
    return mockTestPlugin(req)
  }
}

export async function fetchWasmStats(): Promise<WasmStats> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<WasmStats>('/api/wasm/stats', { baseUrl, token })
  } catch {
    const plugins = await fetchWasmPlugins()
    const active = plugins.filter((p) => p.status === 'active')
    return {
      totalPlugins: plugins.length,
      activePlugins: active.length,
      totalExecutions: 842100,
      denyCount: 14200,
      avgExecutionMs: 0.12,
      fuelConsumption24h: 42105000,
    }
  }
}

function getMockPlugins(): WasmPlugin[] {
  return [
    {
      id: 'wasm-deny-suffix',
      name: 'Deny Blocked Suffix Hook',
      version: '1.0.0',
      description: 'PoC hook denying requests matching ".blocked.test" suffix and adding x-wasm-hook header',
      author: 'BSDM Security Team',
      hookType: 'on_request',
      codeType: 'wat',
      status: 'active',
      fuelLimit: 50000,
      failOpen: true,
      moduleSize: '0.8 KB',
      loadedAt: '2026-07-21T09:00:00Z',
      execCount: 521400,
      avgLatencyMs: 0.06,
      errorCount: 0,
      tags: ['Security', 'DenyRule', 'PoC'],
      sourceCode: `(module
  (import "bsdm" "url_contains" (func $url_contains (param i32 i32) (result i32)))
  (import "bsdm" "set_request_header" (func $set_header (param i32 i32 i32 i32)))
  (import "bsdm" "deny" (func $deny (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) ".blocked.test")
  (data (i32.const 16) "blocked by wasm PoC")
  (data (i32.const 48) "x-wasm-hook")
  (data (i32.const 64) "allow")
  (func (export "on_request")
    (if (i32.eqz (call $url_contains (i32.const 0) (i32.const 13)))
      (then
        (call $set_header (i32.const 48) (i32.const 11) (i32.const 64) (i32.const 5))
      )
      (else
        (call $deny (i32.const 16) (i32.const 19))
      )
    )
  )
)`,
    },
    {
      id: 'wasm-header-rewrite',
      name: 'Security Header Injector',
      version: '1.2.0',
      description: 'Injects proxy tracing and client security headers into outbound requests',
      author: 'DevOps Team',
      hookType: 'on_request',
      codeType: 'wat',
      status: 'active',
      fuelLimit: 30000,
      failOpen: true,
      moduleSize: '1.2 KB',
      loadedAt: '2026-07-20T14:30:00Z',
      execCount: 310200,
      avgLatencyMs: 0.04,
      errorCount: 0,
      tags: ['Headers', 'Tracing'],
      sourceCode: `(module
  (import "bsdm" "set_request_header" (func $set_header (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "x-bsdm-wasm-traced")
  (data (i32.const 24) "true")
  (func (export "on_request")
    (call $set_header (i32.const 0) (i32.const 18) (i32.const 24) (i32.const 4))
  )
)`,
    },
    {
      id: 'wasm-geo-filter',
      name: 'GeoIP Access Limiter (Wasm binary)',
      version: '2.0.1',
      description: 'Compiled Rust Wasm module for high speed subnet & GeoIP verification',
      author: 'SecOps',
      hookType: 'on_request',
      codeType: 'wasm',
      status: 'disabled',
      fuelLimit: 100000,
      failOpen: false,
      moduleSize: '14.5 KB',
      loadedAt: '2026-07-18T10:15:00Z',
      execCount: 10500,
      avgLatencyMs: 0.18,
      errorCount: 2,
      tags: ['GeoIP', 'CompiledWasm'],
      sourceCode: ';; Binary WebAssembly module (14.5 KB)',
    },
  ]
}

function mockTestPlugin(req: WasmTestRequest): WasmTestResult {
  const rawUrl = req.url.toLowerCase().trim()
  let hostname = ''
  try {
    const parsed = new URL(rawUrl.includes('://') ? rawUrl : `https://${rawUrl}`)
    hostname = parsed.hostname
  } catch {
    hostname = rawUrl
  }

  const isBlockedHost =
    hostname === 'evil.com' ||
    hostname.endsWith('.evil.com') ||
    hostname.endsWith('.blocked.test') ||
    hostname === 'blocked.test'

  if (isBlockedHost || rawUrl.includes('/phish')) {
    return {
      decision: 'DENY',
      denyReason: 'blocked by wasm PoC (.blocked.test pattern matched)',
      executionTimeMs: 0.11,
      fuelConsumed: 1420,
      executedPluginName: 'Deny Blocked Suffix Hook',
    }
  }

  return {
    decision: 'ALLOW',
    setHeaders: {
      'x-wasm-hook': 'allow',
      'x-bsdm-wasm-traced': 'true',
    },
    executionTimeMs: 0.06,
    fuelConsumed: 850,
    executedPluginName: 'Deny Blocked Suffix Hook + Security Header Injector',
  }
}
