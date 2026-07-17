import type { ConfigFormState, ProxyConfig } from './types'

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

  if (form.redisL2Enabled) {
    Object.assign(config, {
      REDIS_L2_ENABLED: 'true',
      REDIS_URL: form.redisUrl,
      REDIS_KEY_PREFIX: form.redisKeyPrefix,
    })
  }

  if (form.aclApiToken) config.ACL_API_TOKEN = form.aclApiToken
  if (form.searchApiToken) config.SEARCH_API_TOKEN = form.searchApiToken

  return config
}

export function cacheMetadataEstimate(capacity: string): string {
  const cap = parseInt(capacity, 10) || 10000
  const memoryMB = ((cap * 120) / 1024 / 1024).toFixed(2)
  return `${cap.toLocaleString()} entries ≈ ${memoryMB} MB metadata`
}
