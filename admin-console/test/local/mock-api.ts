/**
 * Local mock backend for the Admin Console.
 *
 * Serves every REST endpoint and the Prometheus `/metrics` scrape the console
 * consumes, so the UI can be exercised — by a human or by the smoke test —
 * without a running proxy, cache-indexer or ML worker.
 *
 * Two ways to use it:
 *
 *   npm run mock:api            # listens on 9090 (control/ACL/metrics),
 *                              # 8080 (search) and 8091 (ML), i.e. exactly the
 *                              # targets `vite.config.ts` proxies to, so
 *                              # `npm run dev` becomes fully live-backed.
 *
 *   startMockApi({ distDir })  # single ephemeral port that also serves the
 *                              # production build under /admin/ — used by
 *                              # ui.smoke.test.ts.
 *
 * Mutating requests are accepted and acknowledged but never mutate fixtures:
 * the test asserts a reproducible read-only surface.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import { extname, join, normalize, resolve, sep } from 'node:path'
import * as fx from './fixtures.ts'

/** Ports `vite.config.ts` proxies to in development. */
export const DEV_BACKEND_PORTS = [9090, 8080, 8091] as const

export interface MockApiOptions {
  /** Directory of a production build served under `/admin/` with SPA fallback. */
  distDir?: string
  /** Log every handled request to stderr. */
  verbose?: boolean
}

const JSON_ROUTES: Record<string, unknown> = {
  '/api/stats': fx.proxyStats,
  '/api/threat-scores': fx.threatScores,
  '/api/acl/rules': fx.aclRules,
  '/api/hierarchy/peers': fx.hierarchyPeers,
  '/api/upstream/tls': fx.upstreamTls,
  '/api/security/casb': fx.casbDomains,
  '/api/security/dlp': fx.dlpPatterns,
  '/api/dns/rpz/lists': fx.rpzLists,
  '/api/dns/rpz/rules/custom': fx.rpzCustomRules,
  '/api/dns/rpz/stats': fx.rpzStats,
  '/api/dns/sinkhole/config': fx.sinkholeConfig,
  '/api/auth/basic/users': fx.basicUsers,
  '/api/config': fx.nodeConfig,
  '/api/v1/devices': fx.devices,
  '/api/v1/agent/policy': fx.agentPolicy,
  '/api/v1/agent/crl': fx.agentCrl,
  '/api/v1/agent/events/recent': fx.agentEvents,
  '/api/ebpf/config': fx.ebpfConfig,
  '/api/ebpf/ips': fx.ebpfBlockedIps,
  '/api/ebpf/stats': fx.ebpfStats,
  '/api/wasm/plugins': fx.wasmPlugins,
  '/api/wasm/config': fx.wasmConfig,
  '/api/wasm/stats': fx.wasmStats,
  '/api/cluster/nodes': fx.clusterNodes,
  '/api/cluster/config': fx.clusterConfig,
  '/api/cluster/stats': fx.clusterStats,
  '/api/cluster/session-state': fx.clusterSessionState,
  '/api/threats/sync/peers': fx.threatSyncPeers,
  '/api/ai/cache/config': fx.aiCacheConfig,
  '/api/ai/cache/entries': fx.aiCacheEntries,
  '/api/ai/cache/stats': fx.aiCacheStats,
  '/api/amneziawg/status': fx.awgStatus,
  '/api/v1/rpz/status': {
    zone_path: '/var/lib/threat-intel/threats.rpz',
    exists: true,
    file_size_bytes: 48120,
    soa_serial: 2026083101,
    domain_count: 1420,
    is_shadow: false,
    has_backup: true,
    backup_soa_serial: 2026083100,
  },
  '/api/v1/rpz/rollback': {
    rolled_back: true,
    status: {
      zone_path: '/var/lib/threat-intel/threats.rpz',
      exists: true,
      file_size_bytes: 47900,
      soa_serial: 2026083100,
      domain_count: 1400,
      is_shadow: false,
      has_backup: false,
    },
  },
  '/api/v1/soar/investigate': {
    query: 'phish.test',
    found: true,
    count: 1,
    indicators: [
      {
        id: 1,
        raw: 'phish.test',
        normalized: 'phish.test',
        kind: 'domain',
        confidence_score: 90,
        source: 'openphish',
        category: 'phishing',
        created_at: 1725100000,
        last_seen_at: 1725100000,
        hit_count: 5,
      },
    ],
  },
  '/api/v1/ml/reputation': {
    domain: 'phish.test',
    score: 88,
    risk_level: 'High',
    anomalies: ['homoglyph', 'brand_distance'],
    details: { homoglyphs: [], brand_distance: 1, entropy: 3.5 },
  },
  '/api/v1/ml/anomaly': {
    domain: 'phish.test',
    entropy: 3.8,
    is_anomaly: true,
    labels: ['high_entropy'],
  },
  '/api/v1/ml/cluster': {
    cluster_count: 1,
    clusters: [{ name: 'phish-campaign-1', domains: ['phish.test', 'phish2.test'], size: 2 }],
  },
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
  })
  res.end(payload)
}

function corsHeaders(res: ServerResponse, origin: string | undefined): void {
  res.setHeader('Access-Control-Allow-Origin', origin ?? '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Authorization,Content-Type,Accept')
}

/** Fixture-backed answers for the handful of endpoints that take parameters. */
function dynamicRoute(pathname: string, url: URL): unknown | undefined {
  if (pathname === '/api/search') {
    const limit = Number(url.searchParams.get('limit') ?? '100')
    const domain = url.searchParams.get('domain')?.toLowerCase() ?? ''
    const username = url.searchParams.get('username')?.toLowerCase() ?? ''
    const sessionId = url.searchParams.get('session_id') ?? ''
    const decisionSource = url.searchParams.get('decision_source') ?? ''
    return fx.trafficLogs
      .filter((log) => !domain || (log.domain ?? '').toLowerCase().includes(domain))
      .filter((log) => !username || (log.username ?? '').toLowerCase().includes(username))
      .filter((log) => !sessionId || log.session_id === sessionId)
      .filter((log) => !decisionSource || log.decision_source === decisionSource)
      .slice(0, Number.isFinite(limit) && limit > 0 ? limit : 100)
  }

  if (pathname === '/api/dns/rpz/test') {
    const domain = url.searchParams.get('domain') ?? ''
    const rule = fx.rpzCustomRules.find((candidate) => candidate.domain === domain)
    return {
      domain,
      matched: Boolean(rule),
      matchedRule: rule
        ? { domain: rule.domain, action: rule.action, listId: rule.listId, listName: rule.listName }
        : undefined,
      appliedAction: rule?.action ?? 'PASSTHRU',
      targetResponse: rule?.targetIp ?? 'upstream',
      durationMs: 1.2,
    }
  }

  if (pathname === '/health' || pathname === '/ready') {
    return { status: 'ok', service: 'bsdm-mock-api' }
  }

  return undefined
}

/** Acknowledgements for mutating calls — fixtures stay immutable. */
function mutationResponse(method: string, pathname: string): unknown {
  if (pathname === '/api/config/apply') {
    return {
      status: 'applied',
      env_path: fx.nodeConfig.env_path,
      hot_reload: ['acl', 'upstream_tls'],
      restart: 'skipped',
      message: 'Local mock backend: configuration accepted, nothing was written.',
    }
  }
  if (pathname === '/api/cluster/sync') {
    return {
      success: true,
      syncedNodesCount: fx.clusterNodes.length,
      failedNodesCount: 0,
      details: fx.clusterNodes.map((node) => ({ nodeId: node.id, nodeName: node.name, status: 'synced' })),
    }
  }
  if (pathname === '/api/cluster/purge') return { purgedNodes: 0 }
  if (pathname === '/api/ai/cache/purge') return { purgedCount: 0 }
  return { status: 'ok', method, path: pathname, note: 'local mock backend — not persisted' }
}

export function isPathWithinRoot(root: string, candidate: string): boolean {
  const resolvedRoot = resolve(root)
  const resolvedCandidate = resolve(candidate)
  return resolvedCandidate === resolvedRoot || resolvedCandidate.startsWith(`${resolvedRoot}${sep}`)
}

async function serveStatic(distDir: string, pathname: string, res: ServerResponse): Promise<boolean> {
  const relative = pathname.replace(/^\/admin\/?/, '') || 'index.html'
  const root = resolve(distDir)
  const candidate = resolve(join(root, normalize(relative)))
  if (!isPathWithinRoot(root, candidate)) {
    sendJson(res, 403, { error: 'path traversal rejected' })
    return true
  }

  const file = await stat(candidate).catch(() => null)
  const target = file?.isFile() ? candidate : join(root, 'index.html')
  const fallback = await stat(target).catch(() => null)
  if (!fallback?.isFile()) return false

  res.writeHead(200, {
    'Content-Type': MIME[extname(target)] ?? 'application/octet-stream',
    'Cache-Control': 'no-store',
  })
  createReadStream(target).pipe(res)
  return true
}

export function createMockApiHandler(options: MockApiOptions = {}) {
  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const pathname = url.pathname
    const method = (req.method ?? 'GET').toUpperCase()
    if (options.verbose) process.stderr.write(`[mock-api] ${method} ${pathname}\n`)

    corsHeaders(res, req.headers.origin)
    if (method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    if (pathname === '/metrics') {
      const body = fx.metricsText()
      res.writeHead(200, {
        'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
        'Cache-Control': 'no-store',
      })
      res.end(body)
      return
    }

    if (method === 'GET') {
      const dynamic = dynamicRoute(pathname, url)
      if (dynamic !== undefined) {
        sendJson(res, 200, dynamic)
        return
      }
      if (pathname in JSON_ROUTES) {
        sendJson(res, 200, JSON_ROUTES[pathname])
        return
      }
    } else if (pathname.startsWith('/api/')) {
      req.resume() // drain the request body; fixtures are immutable
      sendJson(res, 200, mutationResponse(method, pathname))
      return
    }

    if (options.distDir && !pathname.startsWith('/api/')) {
      if (pathname === '/' || pathname === '/trust' || pathname.startsWith('/trust/')) {
        res.writeHead(302, { Location: '/admin/' })
        res.end()
        return
      }
      if (pathname === '/admin' ) {
        res.writeHead(302, { Location: '/admin/' })
        res.end()
        return
      }
      if (pathname.startsWith('/admin/') && (await serveStatic(options.distDir, pathname, res))) return
    }

    sendJson(res, 404, { error: 'not found', path: pathname })
  }
}

export interface MockApiInstance {
  servers: Server[]
  /** Base URL of the first listening port. */
  url: string
  close(): Promise<void>
}

export async function startMockApi(
  options: MockApiOptions & { ports?: readonly number[]; host?: string } = {},
): Promise<MockApiInstance> {
  const host = options.host ?? '127.0.0.1'
  const ports = options.ports ?? [0]
  const handler = createMockApiHandler(options)

  const servers = await Promise.all(
    ports.map(
      (port) =>
        new Promise<Server>((resolvePort, rejectPort) => {
          const server = createServer((req, res) => {
            void handler(req, res).catch((err: unknown) => {
              sendJson(res, 500, { error: String(err) })
            })
          })
          server.once('error', rejectPort)
          server.listen(port, host, () => resolvePort(server))
        }),
    ),
  )

  const address = servers[0].address()
  const boundPort = typeof address === 'object' && address ? address.port : ports[0]

  return {
    servers,
    url: `http://${host}:${boundPort}`,
    close: () =>
      Promise.all(
        servers.map((server) => new Promise<void>((done) => server.close(() => done()))),
      ).then(() => undefined),
  }
}

const isCli = process.argv[1] && import.meta.url === `file://${resolve(process.argv[1])}`
if (isCli) {
  const custom = process.argv
    .filter((arg) => arg.startsWith('--port='))
    .map((arg) => Number(arg.slice('--port='.length)))
    .filter((port) => Number.isInteger(port) && port > 0)
  const ports = custom.length > 0 ? custom : DEV_BACKEND_PORTS

  const instance = await startMockApi({ ports, verbose: process.argv.includes('--verbose') })
  process.stderr.write(
    `[mock-api] serving Admin Console fixtures on ${ports.map((port) => `http://127.0.0.1:${port}`).join(', ')}\n` +
      '[mock-api] run `npm run dev` in another shell → http://127.0.0.1:5173/admin/\n',
  )
  const shutdown = () => {
    void instance.close().then(() => process.exit(0))
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}
