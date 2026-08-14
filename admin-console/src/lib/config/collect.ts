import type { ConfigFormState, ProxyConfig } from './types.ts'
import { defaultFormState } from './types.ts'

export function collectConfig(form: ConfigFormState): ProxyConfig {
  const maxBodyMb = parseInt(form.maxBodySizeMb, 10) || 10
  const spillKb = parseInt(form.spillThresholdKb, 10) || 0

  const config: ProxyConfig = {
    HTTP_PORT: form.httpPort,
    METRICS_PORT: form.metricsPort,
    RUST_LOG: form.logLevel,
    SHUTDOWN_TIMEOUT_SECONDS: form.shutdownTimeout,
    MAX_CACHE_BODY_SIZE: String(maxBodyMb * 1024 * 1024),
    MITM_ENABLED: String(form.mitmEnabled),
    CACHE_CAPACITY: form.cacheCapacity,
    CACHE_TTL_SECONDS: form.cacheTtl,
    CACHE_SHARDS: form.cacheShards,
    CACHE_HONOR_CACHE_CONTROL: String(form.cacheHonorCacheControl),
    NEGATIVE_CACHE_ENABLED: String(form.negativeCacheEnabled),
    NEGATIVE_CACHE_TTL_SECONDS: form.negativeCacheTtl,
    CACHE_SPILL_THRESHOLD_BYTES: String(spillKb * 1024),
    WORKER_COUNT: form.workerCount,
    PERF_FAST_CACHE_HIT: String(form.perfFastCacheHit),
    STREAMING_MISS_ENABLED: String(form.streamingMissEnabled),
    KAFKA_SAMPLE_RATE: form.kafkaSampleRate,
    METRICS_SAMPLE_RATE: form.metricsSampleRate,
    KAFKA_QUEUE_CAPACITY: form.kafkaQueueCapacity,
    KAFKA_BROKERS: form.kafkaBrokers,
    KAFKA_TOPIC: form.kafkaTopic,
    KAFKA_ACKS: form.kafkaAcks,
    KAFKA_BATCH_SIZE: form.kafkaBatchSize,
    KAFKA_BATCH_TIMEOUT: form.kafkaBatchTimeout,
    AUTH_ENABLED: String(form.authEnabled),
    AUTH_BACKEND: form.authBackend,
    AUTH_REALM: form.authRealm,
    AUTH_CACHE_TTL: form.authCacheTtl,
    ACL_ENABLED: String(form.aclEnabled),
    ACL_DEFAULT_ACTION: form.aclDefaultAction,
    ACL_RULES_PATH: form.aclRulesPath,
    ACL_AUTO_RELOAD: String(form.aclAutoReload),
    ACL_RELOAD_INTERVAL: form.aclReloadInterval,
    CATEGORIZATION_ENABLED: String(form.categorizationEnabled),
    CATEGORIZATION_CACHE_TTL: form.categorizationCacheTtl,
    UT1_ENABLED: String(form.ut1Enabled),
    UT1_PATH: form.ut1Path,
    URLHAUS_ENABLED: String(form.urlhausEnabled),
    URLHAUS_API: form.urlhausApi,
    PHISHTANK_ENABLED: String(form.phishtankEnabled),
    PHISHTANK_API: form.phishtankApi,
    PHISHTANK_API_KEY: form.phishtankApiKey,
    CUSTOM_DB_ENABLED: String(form.customDbEnabled),
    CUSTOM_DB_PATH: form.customDbPath,
    CLICKHOUSE_URL: form.clickhouseUrl,
    CLICKHOUSE_DATABASE: form.clickhouseDatabase,
    CLICKHOUSE_TABLE: form.clickhouseTable,
    PROMETHEUS_ENABLED: String(form.prometheusEnabled),
    GRAFANA_ENABLED: String(form.grafanaEnabled),
    ICAP_ENABLED: String(form.icapEnabled),
    ICAP_URL: form.icapUrl,
    ICAP_FAIL_OPEN: String(form.icapFailOpen),
    ICAP_REQMOD: String(form.icapReqmod),
    ICAP_RESPMOD: String(form.icapRespmod),
    ALERT_WORKER_ENABLED: String(form.alertWorkerEnabled),
    ALERT_WEBHOOK_URL: form.alertWebhookUrl,
    AI_CACHE_ENABLED: String(form.aiCacheEnabled),
    OLLAMA_URL: form.ollamaUrl,
    QDRANT_URL: form.qdrantUrl,
    RKN_SYNC_ENABLED: String(form.rknSyncEnabled),
    RKN_SYNC_URL: form.rknSyncUrl,
    DOH_ENABLED: String(form.dohEnabled),
    DOH_BIND: form.dohBind,
    DOT_ENABLED: String(form.dotEnabled),
    DOT_BIND: form.dotBind,
  }

  if (form.authEnabled && form.authBackend === 'ldap') {
    Object.assign(config, {
      LDAP_SERVERS: form.ldapServers,
      LDAP_BASE_DN: form.ldapBaseDn,
      LDAP_BIND_DN: form.ldapBindDn,
      LDAP_BIND_PASSWORD: form.ldapBindPassword,
      LDAP_USER_FILTER: form.ldapUserFilter,
      LDAP_USE_TLS: String(form.ldapUseTls),
    })
  }

  if (form.authEnabled && form.authBackend === 'ntlm') {
    Object.assign(config, {
      NTLM_DOMAIN: form.ntlmDomain,
      NTLM_WORKSTATION: form.ntlmWorkstation,
    })
  }

  Object.assign(config, {
    REDIS_L2_ENABLED: String(form.redisL2Enabled),
  })
  if (form.redisL2Enabled) {
    Object.assign(config, {
      REDIS_URL: form.redisUrl,
      REDIS_KEY_PREFIX: form.redisKeyPrefix,
    })
  }

  if (form.aclApiToken) config.ACL_API_TOKEN = form.aclApiToken
  if (form.searchApiToken) config.SEARCH_API_TOKEN = form.searchApiToken

  if (form.upstreamCaCert) config.UPSTREAM_CA_CERT = form.upstreamCaCert
  if (form.upstreamHttp2Enabled) config.UPSTREAM_HTTP2_ENABLED = 'true'
  if (form.preserveHeaderCase) config.HTTP_PRESERVE_HEADER_CASE = 'true'

  if (form.threatScoreEnabled) {
    Object.assign(config, {
      THREAT_SCORE_ENABLED: 'true',
      THREAT_SCORE_POLL_URL: form.threatScorePollUrl,
      THREAT_SCORE_POLL_INTERVAL_SECS: form.threatScorePollInterval,
      THREAT_SCORE_BLOCK_THRESHOLD: form.threatScoreBlockThreshold,
      THREAT_SCORE_WARN_THRESHOLD: form.threatScoreWarnThreshold,
    })
  }

  if (form.hierarchyPeersPath) config.HIERARCHY_PEERS_PATH = form.hierarchyPeersPath
  if (form.icpServerEnabled) {
    config.ICP_SERVER_ENABLED = 'true'
    config.ICP_BIND = form.icpBind
  }
  if (form.htcpServerEnabled) {
    config.HTCP_SERVER_ENABLED = 'true'
    config.HTCP_BIND = form.htcpBind
  }
  if (form.peerDiscoveryEnabled) {
    config.PEER_DISCOVERY_ENABLED = 'true'
    config.PEER_DISCOVERY_MULTICAST = form.peerDiscoveryMulticast
  }

  if (form.rateLimitEnabled) {
    config.RATE_LIMIT_ENABLED = 'true'
    config.RATE_LIMIT_MAX_KEYS = form.rateLimitMaxKeys
  }

  if (form.ebpfXdpEnabled) {
    Object.assign(config, {
      EBPF_XDP_ENABLED: 'true',
      EBPF_XDP_IFACE: form.ebpfXdpIface,
      EBPF_XDP_MODE: form.ebpfXdpMode,
    })
  }

  if (form.wasmEnabled) {
    Object.assign(config, {
      WASM_ENABLED: 'true',
      WASM_MODULE_PATH: form.wasmModulePath,
      WASM_FAIL_OPEN: String(form.wasmFailOpen),
      WASM_FUEL: form.wasmFuel,
    })
  }

  if (form.controlGrpcEnabled) {
    config.CONTROL_GRPC_ENABLED = 'true'
    config.CONTROL_GRPC_BIND = form.controlGrpcBind
  }
  if (form.controlApiToken) config.CONTROL_API_TOKEN = form.controlApiToken

  if (form.reverseProxyEnabled) {
    Object.assign(config, {
      REVERSE_PROXY_UPSTREAM: form.reverseProxyUpstream,
      OIDC_CLIENT_ID: form.oidcClientId,
      OIDC_CLIENT_SECRET: form.oidcClientSecret,
      OIDC_ISSUER_URL: form.oidcIssuerUrl,
      OIDC_REDIRECT_URI: form.oidcRedirectUri,
    })
  }

  return config
}

/** Masked values returned by control plane for secrets — never write back. */
export function isMaskedSecret(value: string): boolean {
  const v = value.trim()
  return v === '***' || v === '****' || v === '[redacted]' || v === 'REDACTED'
}

function isSecretEnvKey(key: string): boolean {
  const u = key.toUpperCase()
  return (
    u.includes('TOKEN') ||
    u.includes('PASSWORD') ||
    u.includes('SECRET') ||
    u.includes('API_KEY') ||
    u.endsWith('_KEY')
  )
}

function normalizeEnvValue(value: string): string {
  return value.trim()
}

/**
 * Build a **delta** env map for POST /api/config/apply.
 *
 * Full `collectConfig(form)` includes every form field with UI defaults. Applying
 * that wholesale overwrites pilot/runtime paths (e.g. ACL_RULES_PATH, HTTP_PORT)
 * and enables features that were never set on the node. With a live baseline
 * from GET /api/config we only send keys that actually changed (or intentional
 * non-default additions), and we never send masked secrets.
 */
export function collectConfigDelta(
  form: ConfigFormState,
  baseline: Record<string, string> | null | undefined,
): Record<string, string> {
  const full = collectConfig(form)
  const defaults = collectConfig(defaultFormState)
  const delta: Record<string, string> = {}

  for (const [key, raw] of Object.entries(full)) {
    const value = String(raw ?? '')
    if (isMaskedSecret(value)) continue
    if (isSecretEnvKey(key) && value === '') continue

    if (baseline && Object.keys(baseline).length > 0) {
      if (Object.prototype.hasOwnProperty.call(baseline, key)) {
        const baseVal = baseline[key] ?? ''
        // Server may mask secrets as ***; treat as "unchanged" if form empty/masked
        if (isMaskedSecret(baseVal)) {
          if (value && !isMaskedSecret(value)) delta[key] = value
          continue
        }
        if (normalizeEnvValue(baseVal) !== normalizeEnvValue(value)) {
          delta[key] = value
        }
      } else {
        // Key not on server: only push if operator changed it away from UI default
        const def = defaults[key] ?? ''
        if (normalizeEnvValue(value) !== normalizeEnvValue(def) && value !== '') {
          delta[key] = value
        }
      }
    } else {
      // No baseline: still avoid shipping pure defaults (pilot-safe partial apply)
      const def = defaults[key] ?? ''
      if (normalizeEnvValue(value) !== normalizeEnvValue(def)) {
        delta[key] = value
      }
    }
  }

  return delta
}

/** Paths that commonly break pilot if Apply rewrites them to UI defaults. */
export const PILOT_SENSITIVE_ENV_KEYS = [
  'ACL_RULES_PATH',
  'CONFIG_ENV_PATH',
  'HTTP_PORT',
  'METRICS_PORT',
  'AGENT_DEVICES_PATH',
  'PINNING_EXCEPTIONS_PATH',
  'ADMIN_CONSOLE_DIR',
] as const

export function describeEnvDelta(
  delta: Record<string, string>,
  baseline: Record<string, string> | null | undefined,
): { changed: string[]; sensitive: string[] } {
  const changed = Object.keys(delta).sort()
  const sensitive = changed.filter((k) =>
    (PILOT_SENSITIVE_ENV_KEYS as readonly string[]).includes(k),
  )
  if (baseline) {
    // also flag if delta would change a sensitive key
  }
  return { changed, sensitive }
}

export function cacheMetadataEstimate(capacity: string): string {
  const cap = parseInt(capacity, 10) || 10000
  const memoryMB = ((cap * 120) / 1024 / 1024).toFixed(2)
  return `${cap.toLocaleString()} entries ≈ ${memoryMB} MB metadata`
}
