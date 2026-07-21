import type { ConfigFormState } from './types'
import { defaultFormState } from './types'

function truthyEnv(v: string): boolean {
  return ['1', 'true', 'yes', 'on'].includes(String(v).trim().toLowerCase())
}

export function parseEnvText(text: string): Record<string, string> {
  const map: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eq = trimmed.indexOf('=')
    if (eq < 1) continue
    map[trimmed.slice(0, eq)] = trimmed.slice(eq + 1)
  }
  return map
}

export function applyEnvToForm(map: Record<string, string>, prev: ConfigFormState): ConfigFormState {
  const next = { ...prev }

  if (map.HTTP_PORT) next.httpPort = map.HTTP_PORT
  if (map.METRICS_PORT) next.metricsPort = map.METRICS_PORT
  if (map.RUST_LOG) next.logLevel = map.RUST_LOG
  if (map.SHUTDOWN_TIMEOUT_SECONDS) next.shutdownTimeout = map.SHUTDOWN_TIMEOUT_SECONDS
  if (map.MAX_CACHE_BODY_SIZE) {
    next.maxBodySizeMb = String(Math.round(parseInt(map.MAX_CACHE_BODY_SIZE, 10) / 1024 / 1024))
  }
  next.mitmEnabled = truthyEnv(map.MITM_ENABLED ?? 'true')

  if (map.CACHE_CAPACITY) next.cacheCapacity = map.CACHE_CAPACITY
  if (map.CACHE_TTL_SECONDS) next.cacheTtl = map.CACHE_TTL_SECONDS
  if (map.CACHE_SHARDS) next.cacheShards = map.CACHE_SHARDS
  next.cacheHonorCacheControl = map.CACHE_HONOR_CACHE_CONTROL !== 'false'
  next.negativeCacheEnabled = truthyEnv(map.NEGATIVE_CACHE_ENABLED ?? 'true')
  if (map.NEGATIVE_CACHE_TTL_SECONDS) next.negativeCacheTtl = map.NEGATIVE_CACHE_TTL_SECONDS
  if (map.CACHE_SPILL_THRESHOLD_BYTES) {
    next.spillThresholdKb = String(Math.round(parseInt(map.CACHE_SPILL_THRESHOLD_BYTES, 10) / 1024))
  }
  next.redisL2Enabled = truthyEnv(map.REDIS_L2_ENABLED ?? 'false')
  if (map.REDIS_URL) next.redisUrl = map.REDIS_URL
  if (map.REDIS_KEY_PREFIX) next.redisKeyPrefix = map.REDIS_KEY_PREFIX

  if (map.WORKER_COUNT) next.workerCount = map.WORKER_COUNT
  next.perfFastCacheHit = truthyEnv(map.PERF_FAST_CACHE_HIT ?? 'false')
  next.streamingMissEnabled = map.STREAMING_MISS_ENABLED !== 'false'
  if (map.KAFKA_SAMPLE_RATE) next.kafkaSampleRate = map.KAFKA_SAMPLE_RATE
  if (map.METRICS_SAMPLE_RATE) next.metricsSampleRate = map.METRICS_SAMPLE_RATE
  if (map.KAFKA_QUEUE_CAPACITY) next.kafkaQueueCapacity = map.KAFKA_QUEUE_CAPACITY

  if (map.KAFKA_BROKERS) next.kafkaBrokers = map.KAFKA_BROKERS
  if (map.KAFKA_TOPIC) next.kafkaTopic = map.KAFKA_TOPIC
  if (map.KAFKA_ACKS) next.kafkaAcks = map.KAFKA_ACKS
  if (map.KAFKA_BATCH_SIZE) next.kafkaBatchSize = map.KAFKA_BATCH_SIZE
  if (map.KAFKA_BATCH_TIMEOUT) next.kafkaBatchTimeout = map.KAFKA_BATCH_TIMEOUT

  next.authEnabled = truthyEnv(map.AUTH_ENABLED ?? 'false')
  if (map.AUTH_BACKEND) next.authBackend = map.AUTH_BACKEND
  if (map.AUTH_REALM) next.authRealm = map.AUTH_REALM
  if (map.AUTH_CACHE_TTL) next.authCacheTtl = map.AUTH_CACHE_TTL
  if (map.LDAP_SERVERS) next.ldapServers = map.LDAP_SERVERS
  if (map.LDAP_BASE_DN) next.ldapBaseDn = map.LDAP_BASE_DN
  if (map.LDAP_BIND_DN) next.ldapBindDn = map.LDAP_BIND_DN
  if (map.LDAP_BIND_PASSWORD) next.ldapBindPassword = map.LDAP_BIND_PASSWORD
  if (map.LDAP_USER_FILTER) next.ldapUserFilter = map.LDAP_USER_FILTER
  next.ldapUseTls = map.LDAP_USE_TLS !== 'false'
  if (map.NTLM_DOMAIN) next.ntlmDomain = map.NTLM_DOMAIN
  if (map.NTLM_WORKSTATION) next.ntlmWorkstation = map.NTLM_WORKSTATION

  next.aclEnabled = truthyEnv(map.ACL_ENABLED ?? 'false')
  if (map.ACL_DEFAULT_ACTION) next.aclDefaultAction = map.ACL_DEFAULT_ACTION
  if (map.ACL_RULES_PATH) next.aclRulesPath = map.ACL_RULES_PATH
  next.aclAutoReload = truthyEnv(map.ACL_AUTO_RELOAD ?? 'false')
  if (map.ACL_RELOAD_INTERVAL) next.aclReloadInterval = map.ACL_RELOAD_INTERVAL
  if (map.ACL_API_TOKEN) next.aclApiToken = map.ACL_API_TOKEN

  next.categorizationEnabled = truthyEnv(map.CATEGORIZATION_ENABLED ?? 'false')
  if (map.CATEGORIZATION_CACHE_TTL) next.categorizationCacheTtl = map.CATEGORIZATION_CACHE_TTL
  next.ut1Enabled = truthyEnv(map.UT1_ENABLED ?? 'true')
  if (map.UT1_PATH) next.ut1Path = map.UT1_PATH
  next.urlhausEnabled = truthyEnv(map.URLHAUS_ENABLED ?? 'false')
  if (map.URLHAUS_API) next.urlhausApi = map.URLHAUS_API
  next.phishtankEnabled = truthyEnv(map.PHISHTANK_ENABLED ?? 'false')
  if (map.PHISHTANK_API) next.phishtankApi = map.PHISHTANK_API
  if (map.PHISHTANK_API_KEY) next.phishtankApiKey = map.PHISHTANK_API_KEY
  next.customDbEnabled = truthyEnv(map.CUSTOM_DB_ENABLED ?? 'false')
  if (map.CUSTOM_DB_PATH) next.customDbPath = map.CUSTOM_DB_PATH

  if (map.CLICKHOUSE_URL) next.clickhouseUrl = map.CLICKHOUSE_URL
  if (map.CLICKHOUSE_DATABASE) next.clickhouseDatabase = map.CLICKHOUSE_DATABASE
  if (map.CLICKHOUSE_TABLE) next.clickhouseTable = map.CLICKHOUSE_TABLE
  if (map.SEARCH_API_TOKEN) next.searchApiToken = map.SEARCH_API_TOKEN

  if (map.UPSTREAM_CA_CERT) next.upstreamCaCert = map.UPSTREAM_CA_CERT
  next.upstreamHttp2Enabled = truthyEnv(map.UPSTREAM_HTTP2_ENABLED ?? 'false')
  next.preserveHeaderCase = truthyEnv(map.HTTP_PRESERVE_HEADER_CASE ?? 'false')

  next.threatScoreEnabled = truthyEnv(map.THREAT_SCORE_ENABLED ?? 'false')
  if (map.THREAT_SCORE_POLL_URL) next.threatScorePollUrl = map.THREAT_SCORE_POLL_URL
  if (map.THREAT_SCORE_POLL_INTERVAL_SECS) next.threatScorePollInterval = map.THREAT_SCORE_POLL_INTERVAL_SECS
  if (map.THREAT_SCORE_BLOCK_THRESHOLD) next.threatScoreBlockThreshold = map.THREAT_SCORE_BLOCK_THRESHOLD
  if (map.THREAT_SCORE_WARN_THRESHOLD) next.threatScoreWarnThreshold = map.THREAT_SCORE_WARN_THRESHOLD

  if (map.HIERARCHY_PEERS_PATH) next.hierarchyPeersPath = map.HIERARCHY_PEERS_PATH
  next.icpServerEnabled = truthyEnv(map.ICP_SERVER_ENABLED ?? 'false')
  if (map.ICP_BIND) next.icpBind = map.ICP_BIND
  next.htcpServerEnabled = truthyEnv(map.HTCP_SERVER_ENABLED ?? 'false')
  if (map.HTCP_BIND) next.htcpBind = map.HTCP_BIND
  next.peerDiscoveryEnabled = truthyEnv(map.PEER_DISCOVERY_ENABLED ?? 'false')
  if (map.PEER_DISCOVERY_MULTICAST) next.peerDiscoveryMulticast = map.PEER_DISCOVERY_MULTICAST

  next.rateLimitEnabled = truthyEnv(map.RATE_LIMIT_ENABLED ?? 'false')
  if (map.RATE_LIMIT_MAX_KEYS) next.rateLimitMaxKeys = map.RATE_LIMIT_MAX_KEYS

  next.ebpfXdpEnabled = truthyEnv(map.EBPF_XDP_ENABLED ?? 'false')
  if (map.EBPF_XDP_IFACE) next.ebpfXdpIface = map.EBPF_XDP_IFACE
  if (map.EBPF_XDP_MODE) next.ebpfXdpMode = map.EBPF_XDP_MODE

  next.wasmEnabled = truthyEnv(map.WASM_ENABLED ?? 'false')
  if (map.WASM_MODULE_PATH) next.wasmModulePath = map.WASM_MODULE_PATH
  next.wasmFailOpen = map.WASM_FAIL_OPEN !== 'false'
  if (map.WASM_FUEL) next.wasmFuel = map.WASM_FUEL

  next.controlGrpcEnabled = truthyEnv(map.CONTROL_GRPC_ENABLED ?? 'false')
  if (map.CONTROL_GRPC_BIND) next.controlGrpcBind = map.CONTROL_GRPC_BIND
  if (map.CONTROL_API_TOKEN) next.controlApiToken = map.CONTROL_API_TOKEN

  return next
}

export function importEnvFile(text: string, prev = defaultFormState): ConfigFormState {
  return applyEnvToForm(parseEnvText(text), prev)
}

const FORM_STORAGE_KEY = 'bsdm-admin-config-form'

/** Keys never written to localStorage (session-only secrets). */
const SENSITIVE_FORM_KEYS = [
  'ldapBindPassword',
  'aclApiToken',
  'phishtankApiKey',
  'searchApiToken',
  'controlApiToken',
] as const satisfies readonly (keyof ConfigFormState)[]

function formForStorage(form: ConfigFormState): Omit<ConfigFormState, (typeof SENSITIVE_FORM_KEYS)[number]> {
  const stored = { ...form }
  for (const key of SENSITIVE_FORM_KEYS) {
    delete (stored as Partial<ConfigFormState>)[key]
  }
  return stored as Omit<ConfigFormState, (typeof SENSITIVE_FORM_KEYS)[number]>
}

export function loadSavedForm(): ConfigFormState {
  try {
    const raw = localStorage.getItem(FORM_STORAGE_KEY)
    if (!raw) return { ...defaultFormState }
    const parsed = JSON.parse(raw) as Partial<ConfigFormState>
    return { ...defaultFormState, ...parsed }
  } catch {
    return { ...defaultFormState }
  }
}

/** Persist non-secret fields only; passwords/tokens stay in memory for this session. */
export function saveFormState(form: ConfigFormState): void {
  localStorage.setItem(FORM_STORAGE_KEY, JSON.stringify(formForStorage(form)))
}
