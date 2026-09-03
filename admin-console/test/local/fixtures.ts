/**
 * Deterministic fixtures for the local UI test backend.
 *
 * These are NOT the console's demo-mode payloads: they are served over HTTP by
 * `mock-api.ts`, so from the browser's point of view they are ordinary live
 * backend responses. That is what makes the local UI test meaningful — every
 * page must render `Live` provenance, never the demo badge or an error state.
 *
 * Types are imported from the production API clients, so a contract change in
 * `src/api/*` breaks these fixtures at type-check time instead of silently
 * drifting.
 */

import type { AclRulesResponse } from '../../src/api/acl.ts'
import type {
  AgentCrlDocument,
  AgentDevice,
  AgentEventsRecentResponse,
  AgentPolicyDocument,
} from '../../src/api/agent.ts'
import type { AiCacheConfig, AiCacheEntry, AiCacheStats } from '../../src/api/aiCache.ts'
import type { AwgServerConfig } from '../../src/api/amneziawg.ts'
import type { BasicUser } from '../../src/api/auth.ts'
import type {
  ClusterMeshConfig,
  ClusterNode,
  ClusterSessionState,
  ClusterStats,
  ThreatSyncPeersReport,
} from '../../src/api/cluster.ts'
import type { ConfigSnapshot } from '../../src/api/config.ts'
import type { EbpfBlockedIp, EbpfStats, EbpfXdpConfig } from '../../src/api/ebpf.ts'
import type { ProxyStats } from '../../src/api/metrics.ts'
import type { HierarchyPeer, UpstreamTlsStatus } from '../../src/api/node.ts'
import type { DnsSinkholeConfig, RpzList, RpzRule, RpzStats } from '../../src/api/rpz.ts'
import type { TrafficLog } from '../../src/api/search.ts'
import type { DlpPatternDto } from '../../src/api/security.ts'
import type { ThreatScoreSnapshot } from '../../src/api/threatScores.ts'
import type { WasmGlobalConfig, WasmPlugin, WasmStats } from '../../src/api/wasm.ts'

/** Fixed clock so charts, "last seen" labels and expiries stay reproducible. */
export const NOW_MS = Date.UTC(2026, 4, 12, 9, 30, 0)
const NOW_S = Math.floor(NOW_MS / 1000)
const iso = (offsetMs: number) => new Date(NOW_MS + offsetMs).toISOString()

/**
 * Marker strings asserted by the UI smoke test. Keeping them in one place
 * means a fixture rename cannot leave the assertions silently matching
 * nothing.
 */
export const NODE_ID = 'bsdm-proxy-node-alpha'
export const ENV_PATH = '/etc/bsdm-proxy/bsdm-proxy.env'

export const MARKERS = {
  dashboard: 'cdn.example.net',
  logs: 'login-verify.example',
  analytics: 'docs.internal.example',
  threatScores: 'phishing_lexical_v0',
  security: 'api.openai.com',
  policies: 'block-file-sharing',
  rpz: 'Corporate malware feed',
  devices: 'ALICE-LAPTOP',
  users: 'operator',
  settings: ENV_PATH,
} as const

export const proxyStats: ProxyStats = {
  service: 'bsdm-proxy',
  uptime_secs: 372_045,
  requests_in_flight: 12,
  cache: {
    hits: 184_213,
    misses: 51_904,
    bypasses: 8_732,
    hit_ratio: 0.752,
    entries: 42_118,
    capacity: 100_000,
    shards: 16,
  },
}

/**
 * Prometheus exposition text covering every metric family the dashboard
 * scrapes: request/ACL/decision-source counters, the latency histogram,
 * upstream tables and the standalone gauges.
 */
export function metricsText(): string {
  return `# HELP bsdm_proxy_requests_total Total proxied requests.
# TYPE bsdm_proxy_requests_total counter
bsdm_proxy_requests_total{status="200",cache_status="HIT"} 148902
bsdm_proxy_requests_total{status="200",cache_status="MISS"} 41255
bsdm_proxy_requests_total{status="204",cache_status="BYPASS"} 8732
bsdm_proxy_requests_total{status="304",cache_status="REVALIDATED"} 12044
bsdm_proxy_requests_total{status="403",cache_status="BYPASS"} 2610
bsdm_proxy_requests_total{status="502",cache_status="MISS"} 318
# HELP bsdm_proxy_request_duration_seconds Request latency.
# TYPE bsdm_proxy_request_duration_seconds histogram
bsdm_proxy_request_duration_seconds_bucket{le="0.005"} 90210
bsdm_proxy_request_duration_seconds_bucket{le="0.01"} 148300
bsdm_proxy_request_duration_seconds_bucket{le="0.025"} 189440
bsdm_proxy_request_duration_seconds_bucket{le="0.05"} 205110
bsdm_proxy_request_duration_seconds_bucket{le="0.1"} 210880
bsdm_proxy_request_duration_seconds_bucket{le="0.25"} 213090
bsdm_proxy_request_duration_seconds_bucket{le="0.5"} 213700
bsdm_proxy_request_duration_seconds_bucket{le="1"} 213840
bsdm_proxy_request_duration_seconds_bucket{le="+Inf"} 213861
bsdm_proxy_request_duration_seconds_sum 4120.5
bsdm_proxy_request_duration_seconds_count 213861
# HELP bsdm_proxy_acl_decisions_total ACL decisions by action.
# TYPE bsdm_proxy_acl_decisions_total counter
bsdm_proxy_acl_decisions_total{action="allow"} 209140
bsdm_proxy_acl_decisions_total{action="deny"} 4102
bsdm_proxy_acl_decisions_total{action="redirect"} 619
# HELP bsdm_proxy_policy_decision_source_total Hybrid policy decision path.
# TYPE bsdm_proxy_policy_decision_source_total counter
bsdm_proxy_policy_decision_source_total{source="dns"} 88104
bsdm_proxy_policy_decision_source_total{source="sni"} 71220
bsdm_proxy_policy_decision_source_total{source="mitm"} 52140
bsdm_proxy_policy_decision_source_total{source="pinning-bypass"} 2397
# HELP bsdm_proxy_upstream_requests_total Upstream requests by host.
# TYPE bsdm_proxy_upstream_requests_total counter
bsdm_proxy_upstream_requests_total{host="${MARKERS.dashboard}"} 51204
bsdm_proxy_upstream_requests_total{host="docs.internal.example"} 30118
bsdm_proxy_upstream_requests_total{host="updates.example.org"} 18740
bsdm_proxy_upstream_requests_total{host="telemetry.example.io"} 9012
# HELP bsdm_proxy_upstream_errors_total Upstream errors by host.
# TYPE bsdm_proxy_upstream_errors_total counter
bsdm_proxy_upstream_errors_total{host="${MARKERS.dashboard}"} 118
bsdm_proxy_upstream_errors_total{host="telemetry.example.io"} 402
# HELP bsdm_proxy_cache_evictions_total Cache evictions.
# TYPE bsdm_proxy_cache_evictions_total counter
bsdm_proxy_cache_evictions_total 7311
# HELP bsdm_proxy_rate_limit_rejected_total Rate limited requests.
# TYPE bsdm_proxy_rate_limit_rejected_total counter
bsdm_proxy_rate_limit_rejected_total 843
# HELP bsdm_proxy_tls_handshakes_total TLS handshakes by status.
# TYPE bsdm_proxy_tls_handshakes_total counter
bsdm_proxy_tls_handshakes_total{status="success"} 118402
bsdm_proxy_tls_handshakes_total{status="failure"} 274
`
}

export const trafficLogs: TrafficLog[] = [
  {
    ts: NOW_S - 30,
    username: 'a.ivanov',
    client_ip: '10.0.1.42',
    url: `https://${MARKERS.logs}/session/renew`,
    domain: MARKERS.logs,
    method: 'GET',
    status: 403,
    cache_status: 'BYPASS',
    event_id: 'evt-0001',
    session_id: 'sess-7781',
    decision_source: 'sni',
  },
  {
    ts: NOW_S - 95,
    username: 'a.ivanov',
    client_ip: '10.0.1.42',
    url: `https://${MARKERS.analytics}/handbook/index.html`,
    domain: MARKERS.analytics,
    method: 'GET',
    status: 200,
    cache_status: 'HIT',
    event_id: 'evt-0002',
    session_id: 'sess-7781',
    parent_event_id: 'evt-0001',
    decision_source: 'mitm',
  },
  {
    ts: NOW_S - 240,
    username: 'p.orlova',
    client_ip: '10.0.2.17',
    url: `https://${MARKERS.dashboard}/assets/app.js`,
    domain: MARKERS.dashboard,
    method: 'GET',
    status: 200,
    cache_status: 'MISS',
    event_id: 'evt-0003',
    session_id: 'sess-4410',
    decision_source: 'dns',
  },
  {
    ts: NOW_S - 610,
    username: 'p.orlova',
    client_ip: '10.0.2.17',
    url: 'https://c2.beacon.test/ping',
    domain: 'c2.beacon.test',
    method: 'POST',
    status: 403,
    cache_status: 'BYPASS',
    event_id: 'evt-0004',
    session_id: 'sess-4410',
    decision_source: 'dns',
  },
  {
    ts: NOW_S - 1_250,
    username: 'svc.build',
    client_ip: '10.0.3.9',
    url: 'https://updates.example.org/pkg/index.json',
    domain: 'updates.example.org',
    method: 'GET',
    status: 502,
    cache_status: 'MISS',
    event_id: 'evt-0005',
    session_id: 'sess-9002',
    decision_source: 'mitm',
  },
  {
    ts: NOW_S - 2_400,
    username: 'svc.build',
    client_ip: '10.0.3.9',
    url: 'https://telemetry.example.io/v1/batch',
    domain: 'telemetry.example.io',
    method: 'POST',
    status: 200,
    cache_status: 'BYPASS',
    event_id: 'evt-0006',
    session_id: 'sess-9002',
    decision_source: 'pinning-bypass',
  },
]

export const threatScores: ThreatScoreSnapshot = {
  generated_at: iso(0),
  scores: [
    {
      entity_type: 'domain',
      entity_id: MARKERS.logs,
      score: 0.91,
      severity: 'high',
      model: MARKERS.threatScores,
      scored_at: iso(-120_000),
      expires_at: iso(3_600_000),
    },
    {
      entity_type: 'client_domain',
      entity_id: '10.0.2.17|c2.beacon.test',
      score: 0.87,
      severity: 'critical',
      model: 'cc_beacon_v0',
      scored_at: iso(-600_000),
      expires_at: iso(3_600_000),
    },
    {
      entity_type: 'user',
      entity_id: 'svc.build',
      score: 0.62,
      severity: 'medium',
      model: 'ueba_zscore_v0',
      scored_at: iso(-1_800_000),
      expires_at: iso(7_200_000),
    },
  ],
}

export const aclRules: AclRulesResponse = {
  default_action: 'allow',
  rules: [
    {
      id: 'rule-001',
      name: MARKERS.policies,
      enabled: true,
      priority: 10,
      action: 'deny',
      rule_type: { domain_suffix: 'files.example.net' },
      comment: 'Corporate data-exfiltration control',
    },
    {
      id: 'rule-002',
      name: 'redirect-blocked-page',
      enabled: true,
      priority: 20,
      action: 'redirect',
      rule_type: { category: 'phishing' },
      redirect_url: 'https://intranet.example/blocked',
      comment: null,
    },
    {
      id: 'rule-003',
      name: 'allow-build-agents',
      enabled: false,
      priority: 30,
      action: 'allow',
      rule_type: { client_cidr: '10.0.3.0/24' },
      comment: null,
    },
  ],
}

export const hierarchyPeers: HierarchyPeer[] = [
  { name: 'parent-dc1', host: '10.0.9.1', http_port: 3128, icp_port: 3130, peer_type: 'parent', state: 'alive' },
  { name: 'sibling-dc2', host: '10.0.9.2', http_port: 3128, icp_port: 3130, peer_type: 'sibling', state: 'alive' },
  { name: 'sibling-dc3', host: '10.0.9.3', http_port: 3128, icp_port: 3130, peer_type: 'sibling', state: 'down' },
]

export const upstreamTls: UpstreamTlsStatus = {
  mode: 'system-roots',
  client_certs: 1,
  min_version: 'TLSv1.2',
  verify_peer: true,
}

export const casbDomains: string[] = [
  MARKERS.security,
  'chatgpt.com',
  'api.anthropic.com',
  'claude.ai',
  'copilot.microsoft.com',
]

export const dlpPatterns: DlpPatternDto[] = [
  { pattern: 'sk-ant-api', description: 'Anthropic API Key' },
  { pattern: 'sk-proj-', description: 'OpenAI Project Key' },
  { pattern: 'ghp_', description: 'GitHub Personal Access Token' },
  { pattern: 'BEGIN RSA PRIVATE KEY', description: 'RSA Private Key' },
]

export const rpzLists: RpzList[] = [
  {
    id: 'rpz-001',
    name: MARKERS.rpz,
    description: 'Aggregated malware domains, refreshed hourly',
    source: 'url_feed',
    format: 'rpz-zone',
    url: 'https://feeds.example.org/malware.rpz',
    defaultAction: 'NXDOMAIN',
    ruleCount: 128_402,
    active: true,
    priority: 10,
    lastUpdated: iso(-3_600_000),
    syncError: null,
    tags: ['malware', 'feed'],
  },
  {
    id: 'rpz-002',
    name: 'Internal sinkhole list',
    description: 'Manually curated internal blocks',
    source: 'inline',
    format: 'domain-list',
    defaultAction: 'SINKHOLE',
    ruleCount: 24,
    active: true,
    priority: 20,
    lastUpdated: iso(-86_400_000),
    syncError: null,
    tags: ['internal'],
  },
]

export const rpzCustomRules: RpzRule[] = [
  {
    id: 'rpz-rule-1',
    listId: 'rpz-002',
    listName: 'Internal sinkhole list',
    domain: 'c2.beacon.test',
    action: 'SINKHOLE',
    targetIp: '10.0.0.9',
    comment: 'Known beacon infrastructure',
    createdAt: iso(-172_800_000),
  },
  {
    id: 'rpz-rule-2',
    listId: 'rpz-002',
    listName: 'Internal sinkhole list',
    domain: MARKERS.logs,
    action: 'NXDOMAIN',
    comment: 'Credential phishing',
    createdAt: iso(-259_200_000),
  },
]

export const sinkholeConfig: DnsSinkholeConfig = {
  enabled: true,
  defaultAction: 'NXDOMAIN',
  sinkholeIpv4: '10.0.0.9',
  sinkholeIpv6: 'fd00::9',
  sinkholeCname: 'sinkhole.internal.example',
  logBlocks: true,
  wildcardMatching: true,
  upstreamDns: ['10.0.0.53', '1.1.1.1'],
  dohEnabled: true,
  dohBind: '0.0.0.0:8443',
  dohPath: '/dns-query',
  dotEnabled: false,
  dotBind: '0.0.0.0:853',
}

export const rpzStats: RpzStats = {
  totalLists: rpzLists.length,
  activeLists: rpzLists.filter((list) => list.active).length,
  totalRules: 128_426,
  blocked24h: 3_142,
  dohQueries24h: 91_204,
  dotQueries24h: 0,
  topDomains: [
    { domain: 'c2.beacon.test', count: 812, action: 'SINKHOLE', category: 'c2' },
    { domain: MARKERS.logs, count: 517, action: 'NXDOMAIN', category: 'phishing' },
    { domain: 'ads.tracker.example', count: 402, action: 'NXDOMAIN', category: 'tracking' },
  ],
}

export const basicUsers: BasicUser[] = [
  { username: MARKERS.users, role: 'admin' },
  { username: 'a.ivanov', role: 'user' },
  { username: 'svc.build', role: 'service' },
]

export const nodeConfig: ConfigSnapshot = {
  env_path: ENV_PATH,
  env: {
    NODE_ID,
    HTTP_PORT: '3128',
    METRICS_PORT: '9090',
    MITM_ENABLED: 'true',
    CACHE_CAPACITY: '100000',
    CACHE_SHARDS: '16',
    AUTH_MODE: 'basic',
    ACL_ENABLED: 'true',
    RATE_LIMIT_ENABLED: 'true',
    KAFKA_ENABLED: 'false',
  },
}

export const devices: AgentDevice[] = [
  {
    id: 'dev-001',
    name: MARKERS.devices,
    ip: '10.0.1.42',
    type: 'laptop',
    status: 'Secured',
    connection: 'agent',
    lastSeen: NOW_MS - 60_000,
    agentStatus: 'online',
    agentVersion: '0.9.1',
    policyVersion: '2026-05-11T18:00:00Z',
    certSubject: 'CN=ALICE-LAPTOP',
    certFingerprint: 'ab:cd:ef:01:23:45',
    certSerial: '0x1f4',
    trustScore: 92,
    platform: 'windows',
    userIdentity: 'a.ivanov',
    enrolledAt: NOW_MS - 30 * 86_400_000,
    enrolled: true,
    capabilities: ['mitm', 'dns', 'events'],
  },
  {
    id: 'dev-002',
    name: 'BOB-DESKTOP',
    ip: '10.0.2.17',
    type: 'desktop',
    status: 'Flagged',
    connection: 'agent',
    lastSeen: NOW_MS - 900_000,
    agentStatus: 'stale',
    agentVersion: '0.9.0',
    policyVersion: '2026-05-04T12:00:00Z',
    certSubject: 'CN=BOB-DESKTOP',
    certFingerprint: '11:22:33:44:55:66',
    certSerial: '0x1f5',
    trustScore: 48,
    platform: 'linux',
    userIdentity: 'p.orlova',
    enrolledAt: NOW_MS - 60 * 86_400_000,
    enrolled: true,
    capabilities: ['dns', 'events'],
  },
]

export const agentPolicy: AgentPolicyDocument = {
  policy_version: '2026-05-11T18:00:00Z',
  policy_mode: 'hybrid',
  mitm_categories: ['webmail', 'file-sharing'],
  pinning_exceptions: ['telemetry.example.io'],
  sni_deny_patterns: ['*.beacon.test'],
  sni_rules: [{ pattern: '*.beacon.test', action: 'deny' }],
}

export const agentCrl: AgentCrlDocument = {
  version: 1,
  crl_number: 7,
  count: 1,
  updated_at: NOW_S - 7_200,
  entries: [
    {
      fingerprint: '99:88:77:66:55:44',
      serial_hex: '0x1e0',
      device_id: 'dev-legacy-009',
      revoked_at: NOW_S - 7_200,
      reason: 'decommissioned',
    },
  ],
}

export const agentEvents: AgentEventsRecentResponse = {
  events: [
    {
      device_id: 'dev-001',
      domain: MARKERS.logs,
      action: 'deny',
      decision_source: 'sni',
      reason: 'phishing',
      received_at: NOW_S - 30,
    },
    {
      device_id: 'dev-002',
      domain: 'c2.beacon.test',
      action: 'deny',
      decision_source: 'dns',
      reason: 'rpz',
      received_at: NOW_S - 610,
    },
  ],
}

export const ebpfConfig: EbpfXdpConfig = {
  enabled: false,
  interface: 'eth0',
  mode: 'skb',
  mapName: 'bsdm_blocklist',
  maxEntries: 10_000,
}

export const ebpfBlockedIps: EbpfBlockedIp[] = [
  {
    id: 'ip-1',
    ip: '198.51.100.44',
    addedAt: iso(-1_200_000),
    reason: 'threat feed',
    packetsDropped: 18_402,
    bytesDropped: 2_418_004,
  },
]

export const ebpfStats: EbpfStats = {
  enabled: false,
  attached: false,
  interface: 'eth0',
  mode: 'skb',
  activeBlockedIps: ebpfBlockedIps.length,
  packetsDroppedTotal: 18_402,
  bytesDroppedTotal: 2_418_004,
  kernelLatencyUs: 12,
  cpuUsageUserPercent: 1.4,
}

export const wasmPlugins: WasmPlugin[] = [
  {
    id: 'wasm-001',
    name: 'header-scrubber',
    version: '0.2.0',
    description: 'Strips internal headers from egress requests',
    author: 'platform-team',
    hookType: 'on_request',
    codeType: 'wat',
    status: 'active',
    fuelLimit: 100_000,
    failOpen: true,
    moduleSize: '12 KB',
    loadedAt: iso(-86_400_000),
    execCount: 210_004,
    avgLatencyMs: 0.3,
    errorCount: 0,
    tags: ['egress'],
  },
]

export const wasmConfig: WasmGlobalConfig = {
  enabled: true,
  defaultFuelLimit: 100_000,
  failOpenDefault: true,
  runtimeEngine: 'wasmtime',
  maxMemoryMB: 64,
  features: ['on_request', 'on_response'],
}

export const wasmStats: WasmStats = {
  totalPlugins: wasmPlugins.length,
  activePlugins: wasmPlugins.filter((plugin) => plugin.status === 'active').length,
  totalExecutions: 210_004,
  denyCount: 128,
  avgExecutionMs: 0.3,
  fuelConsumption24h: 4_120_000,
}

export const clusterNodes: ClusterNode[] = [
  {
    id: 'node-alpha',
    name: NODE_ID,
    role: 'primary',
    grpcEndpoint: '10.0.9.1:9091',
    restEndpoint: 'http://10.0.9.1:9090',
    region: 'dc1',
    status: 'healthy',
    version: '0.9.1',
    uptimeSecs: 372_045,
    inFlightRequests: 12,
    cacheHitRatio: 0.752,
    syncedRulesVersion: '2026-05-11T18:00:00Z',
    syncedWasmVersion: '0.2.0',
    lastHeartbeat: iso(-15_000),
    metrics: { rps: 412, latencyMs: 19, cpuUsage: 0.34, memUsageMB: 1_820 },
  },
  {
    id: 'node-beta',
    name: 'bsdm-proxy-node-beta',
    role: 'worker',
    grpcEndpoint: '10.0.9.2:9091',
    restEndpoint: 'http://10.0.9.2:9090',
    region: 'dc2',
    status: 'degraded',
    version: '0.9.1',
    uptimeSecs: 120_400,
    inFlightRequests: 31,
    cacheHitRatio: 0.61,
    syncedRulesVersion: '2026-05-04T12:00:00Z',
    syncedWasmVersion: '0.2.0',
    lastHeartbeat: iso(-90_000),
    metrics: { rps: 288, latencyMs: 42, cpuUsage: 0.71, memUsageMB: 2_140 },
  },
]

export const clusterConfig: ClusterMeshConfig = {
  enabled: true,
  controlNodeId: 'node-alpha',
  grpcBind: '0.0.0.0:9091',
  syncIntervalSecs: 30,
  autoSyncRules: true,
  autoSyncWasm: false,
  autoSyncRpz: true,
  authBearerConfigured: true,
}

export const clusterStats: ClusterStats = {
  totalNodes: clusterNodes.length,
  healthyNodes: clusterNodes.filter((node) => node.status === 'healthy').length,
  totalRps: 700,
  avgHitRatio: 0.68,
  clusterCapacityReqSec: 4_000,
}

export const clusterSessionState: ClusterSessionState = {
  status: 'redis_connected',
  redis_connected: true,
  session_count: 142,
  distributed_rate_limit_enabled: true,
}

export const threatSyncPeers: ThreatSyncPeersReport = {
  node_id: NODE_ID,
  sync_enabled: true,
  peers: [`${NODE_ID} (local)`, 'bsdm-proxy-node-beta'],
  recent_events: [
    {
      id: 'ioc-node-beta-1',
      ioc_type: 'domain',
      value: MARKERS.logs,
      threat_score: 0.98,
      action: 'block',
      ttl_secs: 86_400,
      origin_node: 'bsdm-proxy-node-beta',
      timestamp: NOW_S - 300,
    },
  ],
}

export const aiCacheConfig: AiCacheConfig = {
  enabled: false,
  pathPrefixes: ['/v1/chat/completions'],
  ttlSecs: 3_600,
  similarityThreshold: 0.92,
  embedDims: 384,
  maxIndexEntries: 50_000,
  vectorBackend: 'local',
  vectorCollection: 'bsdm-ai-cache',
  vectorApiKeyConfigured: false,
  embedProvider: 'local',
}

export const aiCacheEntries: AiCacheEntry[] = [
  {
    id: 'ai-1',
    exactHash: 'a1b2c3',
    promptText: 'Summarize the proxy deployment checklist',
    responseSample: 'Checklist: generate CA, configure ACL, enable metrics…',
    similarityScore: 0.97,
    model: 'gpt-4o-mini',
    tokenSavings: 1_820,
    latencySavedMs: 940,
    createdAt: iso(-7_200_000),
    lastHitAt: iso(-600_000),
    hitCount: 14,
    cacheType: 'SEMANTIC_NEAR_HIT',
  },
]

export const aiCacheStats: AiCacheStats = {
  totalCachedPrompts: 1,
  exactHits24h: 4,
  semanticNearHits24h: 10,
  totalMisses24h: 22,
  hitRatio: 0.39,
  tokensSaved24h: 18_204,
  estimatedCostSavingsUsd: 2.41,
  vectorDbSizeMB: 12.4,
  avgSimilarityScore: 0.94,
}

export const awgStatus: AwgServerConfig = {
  enabled: false,
  listen_port: 51_820,
  private_key: 'local-test-private-key=',
  public_key: 'local-test-public-key=',
  address: '10.8.0.1/24',
  last_reload_status: 'sidecar not running (local UI test)',
  last_reload_at: NOW_S - 3_600,
  obfuscation: { jc: 4, jmin: 40, jmax: 70, s1: 15, s2: 25, h1: 10_000_001, h2: 10_000_002, h3: 10_000_003, h4: 10_000_004 },
  peers: [
    {
      id: 'peer-1',
      name: 'ALICE-LAPTOP',
      public_key: 'alice-public-key=',
      assigned_ip: '10.8.0.2',
      allowed_ips: '10.8.0.2/32',
      created_at: iso(-30 * 86_400_000),
      rx_bytes: 14_258_900,
      tx_bytes: 84_210_000,
      latest_handshake_secs: NOW_S - 120,
    },
  ],
}
