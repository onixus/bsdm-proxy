import { useCallback, useState } from 'react'
import { Download, Eye, FlaskConical, Upload } from 'lucide-react'
import type { ConfigFormState } from '../lib/config/types'
import { defaultFormState } from '../lib/config/types'
import { cacheMetadataEstimate } from '../lib/config/collect'
import { formatEnv, generateAclRules, generateDockerCompose, downloadFile } from '../lib/config/export'
import { importEnvFile, loadSavedForm, saveFormState } from '../lib/config/import'
import { loadApiSettings, saveApiSettings, type ApiSettings } from '../api/settings'
import { isDemoMode, setDemoMode } from '../api/source'
import { fetchProxyStats, formatUptime } from '../api/metrics'
import { fetchUpstreamTls } from '../api/node'
import { useSourcedQuery } from '../hooks/useSourced'
import { useQuery } from '@tanstack/react-query'
import { Button } from '../components/ui/Button'
import { Checkbox, FormGrid, FormSection, Input, Select } from '../components/ui/Form'
import { CodePreview, CopyButton, Modal } from '../components/ui/Modal'
import { Panel } from '../components/dashboard/MetricWidget'
import { useToast } from '../components/ui/Toast'

type SettingsTab =
  | 'general'
  | 'cache'
  | 'auth'
  | 'filtering'
  | 'threat'
  | 'network'
  | 'security'
  | 'events'
  | 'api'

const tabs: { id: SettingsTab; label: string }[] = [
  { id: 'general', label: 'General' },
  { id: 'cache', label: 'Cache' },
  { id: 'auth', label: 'Auth' },
  { id: 'filtering', label: 'Filtering' },
  { id: 'threat', label: 'Threat / ML' },
  { id: 'network', label: 'Hierarchy / TLS' },
  { id: 'security', label: 'Rate limit / eBPF / Wasm' },
  { id: 'events', label: 'Events / Storage' },
  { id: 'api', label: 'Console API' },
]

export function SettingsPage() {
  const { toast } = useToast()
  const [form, setForm] = useState<ConfigFormState>(() => loadSavedForm())
  const [apiSettings, setApiSettings] = useState<ApiSettings>(() => loadApiSettings())
  const [tab, setTab] = useState<SettingsTab>('general')
  const [preview, setPreview] = useState<{ title: string; content: string } | null>(null)
  const [demoEnabled, setDemoEnabled] = useState(isDemoMode)

  const update = useCallback(<K extends keyof ConfigFormState>(key: K, value: ConfigFormState[K]) => {
    setForm((prev) => {
      const next = { ...prev, [key]: value }
      saveFormState(next)
      return next
    })
  }, [])

  const updateApi = useCallback(<K extends keyof ApiSettings>(key: K, value: ApiSettings[K]) => {
    setApiSettings((prev) => {
      const next = { ...prev, [key]: value }
      saveApiSettings(next)
      return next
    })
  }, [])

  const handleImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      const next = importEnvFile(String(reader.result ?? ''), form)
      setForm(next)
      saveFormState(next)
      toast('success', `Imported configuration from ${file.name}`)
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Settings</h1>
        <p className="text-sm text-text-secondary">
          Configuration generator (.env / compose / ACL) and console API endpoints
        </p>
      </div>

      <LiveNodePanel />

      <div className="flex gap-1 overflow-x-auto border-b border-border pb-px">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`touch-target shrink-0 rounded-t-md px-3 py-2 text-sm font-medium transition-colors ${
              tab === t.id
                ? 'border-b-2 border-accent text-accent'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-border bg-surface-1 p-4 sm:p-6">
        {tab === 'general' && <GeneralTab form={form} update={update} />}
        {tab === 'cache' && <CacheTab form={form} update={update} />}
        {tab === 'auth' && <AuthTab form={form} update={update} />}
        {tab === 'filtering' && <FilteringTab form={form} update={update} />}
        {tab === 'threat' && <ThreatTab form={form} update={update} />}
        {tab === 'network' && <NetworkTab form={form} update={update} />}
        {tab === 'security' && <SecurityTab form={form} update={update} />}
        {tab === 'events' && <EventsTab form={form} update={update} />}
        {tab === 'api' && (
          <ApiTab
            settings={apiSettings}
            update={updateApi}
            demoEnabled={demoEnabled}
            onDemoChange={(v) => {
              setDemoEnabled(v)
              setDemoMode(v)
              toast('info', v ? 'Demo mode ON — unreachable APIs now render sample data marked “Demo”.' : 'Demo mode OFF — failures show real error states.')
            }}
          />
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        <Button onClick={() => setPreview({ title: 'bsdm-proxy.env', content: formatEnv(form) })}>
          <Eye className="size-4" /> Preview .env
        </Button>
        <Button variant="secondary" onClick={() => downloadFile('bsdm-proxy.env', formatEnv(form))}>
          <Download className="size-4" /> Export .env
        </Button>
        <Button variant="secondary" onClick={() => downloadFile('docker-compose.yml', generateDockerCompose(form))}>
          <Download className="size-4" /> Export compose
        </Button>
        <Button
          variant="secondary"
          onClick={() => {
            const rules = generateAclRules(form)
            if (!rules) {
              toast('warning', 'Enable ACL on the Filtering tab first')
              return
            }
            downloadFile('acl-rules.json', JSON.stringify(rules, null, 2) + '\n')
          }}
        >
          <Download className="size-4" /> Export ACL
        </Button>
        <label className="touch-target inline-flex cursor-pointer items-center justify-center gap-2 rounded-md border border-border bg-surface-2 px-4 py-2 text-sm font-semibold hover:bg-surface-3">
          <Upload className="size-4" /> Import .env
          <input type="file" accept=".env,text/plain" className="hidden" onChange={handleImport} />
        </label>
        <Button
          variant="ghost"
          onClick={() => {
            setForm(defaultFormState)
            saveFormState(defaultFormState)
            toast('info', 'Form reset to defaults')
          }}
        >
          Reset defaults
        </Button>
      </div>

      <Modal
        open={!!preview}
        onClose={() => setPreview(null)}
        title={preview?.title ?? ''}
        footer={preview && <CopyButton text={preview.content} />}
        wide
      >
        {preview && <CodePreview content={preview.content} />}
      </Modal>
    </div>
  )
}

/** What this node is actually running with right now (real control-plane endpoints). */
function LiveNodePanel() {
  const stats = useQuery({ queryKey: ['settings-stats'], queryFn: fetchProxyStats, refetchInterval: 30_000 })
  const tls = useSourcedQuery(['upstream-tls'], fetchUpstreamTls)
  const s = stats.data

  return (
    <Panel title="Live node state (read from the running proxy)">
      {!s && (
        <p className="text-sm text-text-secondary">
          Control API unreachable — the generator below still works offline, but values shown here would confirm what
          the node actually runs with.
        </p>
      )}
      {s && (
        <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-xs text-text-secondary">Service</dt>
            <dd className="font-mono text-xs text-text-primary">{s.service}</dd>
          </div>
          <div>
            <dt className="text-xs text-text-secondary">Uptime</dt>
            <dd className="text-text-primary">{formatUptime(s.uptime_secs)}</dd>
          </div>
          <div>
            <dt className="text-xs text-text-secondary">L1 cache</dt>
            <dd className="tabular-nums text-text-primary">
              {s.cache.entries.toLocaleString()}/{s.cache.capacity.toLocaleString()} · {s.cache.shards} shards
            </dd>
          </div>
          <div>
            <dt className="text-xs text-text-secondary">Upstream TLS</dt>
            <dd className="truncate font-mono text-xs text-text-primary" title={tls.data ? JSON.stringify(tls.data.data) : ''}>
              {tls.data ? summarizeTls(tls.data.data) : tls.isError ? 'unavailable' : '…'}
            </dd>
          </div>
        </dl>
      )}
    </Panel>
  )
}

function summarizeTls(tls: Record<string, unknown>): string {
  const entries = Object.entries(tls).slice(0, 3)
  if (entries.length === 0) return 'default'
  return entries.map(([k, v]) => `${k}=${String(v)}`).join(' · ')
}

type UpdateFn = <K extends keyof ConfigFormState>(key: K, value: ConfigFormState[K]) => void
interface TabProps {
  form: ConfigFormState
  update: UpdateFn
}

function GeneralTab({ form, update }: TabProps) {
  return (
    <FormSection title="General">
      <FormGrid>
        <Input label="HTTP proxy port" type="number" value={form.httpPort} onChange={(e) => update('httpPort', e.target.value)} />
        <Input label="Metrics / ACL API port" type="number" value={form.metricsPort} onChange={(e) => update('metricsPort', e.target.value)} />
      </FormGrid>
      <FormGrid>
        <Select
          label="RUST_LOG"
          value={form.logLevel}
          onChange={(e) => update('logLevel', e.target.value)}
          options={[
            { value: 'warn', label: 'warn' },
            { value: 'info,bsdm_proxy=info', label: 'info,bsdm_proxy=info' },
            { value: 'info,bsdm_proxy=debug', label: 'info,bsdm_proxy=debug' },
            { value: 'debug', label: 'debug' },
          ]}
        />
        <Input label="Worker count" type="number" value={form.workerCount} onChange={(e) => update('workerCount', e.target.value)} hint="0 = number of CPU cores" />
      </FormGrid>
      <Checkbox label="MITM_ENABLED (HTTPS interception)" checked={form.mitmEnabled} onChange={(v) => update('mitmEnabled', v)} hint="Requires /certs/ca.key and ca.crt" />
      <Checkbox label="PERF_FAST_CACHE_HIT" checked={form.perfFastCacheHit} onChange={(v) => update('perfFastCacheHit', v)} hint="Skip per-hit bookkeeping on the hot path" />
      <Checkbox label="STREAMING_MISS_ENABLED" checked={form.streamingMissEnabled} onChange={(v) => update('streamingMissEnabled', v)} />
    </FormSection>
  )
}

function CacheTab({ form, update }: TabProps) {
  return (
    <div className="space-y-6">
      <FormSection title="L1 cache">
        <Input label="CACHE_CAPACITY" type="number" value={form.cacheCapacity} onChange={(e) => update('cacheCapacity', e.target.value)} hint={cacheMetadataEstimate(form.cacheCapacity)} />
        <FormGrid>
          <Input label="CACHE_TTL_SECONDS" type="number" value={form.cacheTtl} onChange={(e) => update('cacheTtl', e.target.value)} />
          <Input label="CACHE_SHARDS" type="number" value={form.cacheShards} onChange={(e) => update('cacheShards', e.target.value)} />
        </FormGrid>
        <FormGrid>
          <Input label="Max cache body (MB)" type="number" value={form.maxBodySizeMb} onChange={(e) => update('maxBodySizeMb', e.target.value)} />
          <Input label="Spill threshold (KB)" type="number" value={form.spillThresholdKb} onChange={(e) => update('spillThresholdKb', e.target.value)} />
        </FormGrid>
        <Checkbox label="CACHE_HONOR_CACHE_CONTROL" checked={form.cacheHonorCacheControl} onChange={(v) => update('cacheHonorCacheControl', v)} />
        <Checkbox label="NEGATIVE_CACHE_ENABLED" checked={form.negativeCacheEnabled} onChange={(v) => update('negativeCacheEnabled', v)} />
        {form.negativeCacheEnabled && (
          <Input label="NEGATIVE_CACHE_TTL_SECONDS" type="number" value={form.negativeCacheTtl} onChange={(e) => update('negativeCacheTtl', e.target.value)} />
        )}
      </FormSection>
      <FormSection title="Redis L2">
        <Checkbox label="REDIS_L2_ENABLED" checked={form.redisL2Enabled} onChange={(v) => update('redisL2Enabled', v)} />
        {form.redisL2Enabled && (
          <FormGrid>
            <Input label="REDIS_URL" value={form.redisUrl} onChange={(e) => update('redisUrl', e.target.value)} />
            <Input label="REDIS_KEY_PREFIX" value={form.redisKeyPrefix} onChange={(e) => update('redisKeyPrefix', e.target.value)} />
          </FormGrid>
        )}
      </FormSection>
    </div>
  )
}

function AuthTab({ form, update }: TabProps) {
  return (
    <div className="space-y-4">
      <Checkbox label="AUTH_ENABLED" checked={form.authEnabled} onChange={(v) => update('authEnabled', v)} />
      {form.authEnabled && (
        <>
          <FormGrid>
            <Select
              label="AUTH_BACKEND"
              value={form.authBackend}
              onChange={(e) => update('authBackend', e.target.value)}
              options={[
                { value: 'basic', label: 'basic' },
                { value: 'ldap', label: 'ldap' },
                { value: 'ntlm', label: 'ntlm' },
              ]}
            />
            <Input label="AUTH_CACHE_TTL" type="number" value={form.authCacheTtl} onChange={(e) => update('authCacheTtl', e.target.value)} />
          </FormGrid>
          <Input label="AUTH_REALM" value={form.authRealm} onChange={(e) => update('authRealm', e.target.value)} />
          {form.authBackend === 'ldap' && (
            <>
              <FormGrid>
                <Input label="LDAP_SERVERS" value={form.ldapServers} onChange={(e) => update('ldapServers', e.target.value)} />
                <Input label="LDAP_BASE_DN" value={form.ldapBaseDn} onChange={(e) => update('ldapBaseDn', e.target.value)} />
              </FormGrid>
              <FormGrid>
                <Input label="LDAP_BIND_DN" value={form.ldapBindDn} onChange={(e) => update('ldapBindDn', e.target.value)} />
                <Input label="LDAP_BIND_PASSWORD" type="password" value={form.ldapBindPassword} onChange={(e) => update('ldapBindPassword', e.target.value)} hint="Session-only, never persisted" />
              </FormGrid>
              <Input label="LDAP_USER_FILTER" value={form.ldapUserFilter} onChange={(e) => update('ldapUserFilter', e.target.value)} />
              <Checkbox label="LDAP_USE_TLS" checked={form.ldapUseTls} onChange={(v) => update('ldapUseTls', v)} />
            </>
          )}
          {form.authBackend === 'ntlm' && (
            <FormGrid>
              <Input label="NTLM_DOMAIN" value={form.ntlmDomain} onChange={(e) => update('ntlmDomain', e.target.value)} />
              <Input label="NTLM_WORKSTATION" value={form.ntlmWorkstation} onChange={(e) => update('ntlmWorkstation', e.target.value)} />
            </FormGrid>
          )}
        </>
      )}
    </div>
  )
}

function FilteringTab({ form, update }: TabProps) {
  return (
    <div className="space-y-6">
      <FormSection title="ACL">
        <Checkbox label="ACL_ENABLED" checked={form.aclEnabled} onChange={(v) => update('aclEnabled', v)} />
        {form.aclEnabled && (
          <>
            <FormGrid>
              <Select
                label="ACL_DEFAULT_ACTION"
                value={form.aclDefaultAction}
                onChange={(e) => update('aclDefaultAction', e.target.value)}
                options={[
                  { value: 'allow', label: 'allow' },
                  { value: 'deny', label: 'deny' },
                ]}
              />
              <Input label="ACL_API_TOKEN" type="password" value={form.aclApiToken} onChange={(e) => update('aclApiToken', e.target.value)} hint="Session-only, never persisted" />
            </FormGrid>
            <FormGrid>
              <Input label="ACL_RULES_PATH" value={form.aclRulesPath} onChange={(e) => update('aclRulesPath', e.target.value)} />
              <Input label="ACL_RELOAD_INTERVAL" type="number" value={form.aclReloadInterval} onChange={(e) => update('aclReloadInterval', e.target.value)} />
            </FormGrid>
            <Checkbox label="ACL_AUTO_RELOAD" checked={form.aclAutoReload} onChange={(v) => update('aclAutoReload', v)} />
            <div className="space-y-2">
              <p className="text-sm font-medium text-text-primary">Quick category rules</p>
              <Checkbox label="Block malware" checked={form.aclBlockMalware} onChange={(v) => update('aclBlockMalware', v)} />
              <Checkbox label="Block phishing" checked={form.aclBlockPhishing} onChange={(v) => update('aclBlockPhishing', v)} />
              <Checkbox label="Block gambling" checked={form.aclBlockGambling} onChange={(v) => update('aclBlockGambling', v)} />
              <Checkbox label="Block adult" checked={form.aclBlockAdult} onChange={(v) => update('aclBlockAdult', v)} />
            </div>
          </>
        )}
      </FormSection>
      <FormSection title="Categorization sources">
        <Checkbox label="CATEGORIZATION_ENABLED" checked={form.categorizationEnabled} onChange={(v) => update('categorizationEnabled', v)} />
        {form.categorizationEnabled && (
          <>
            <Input label="CATEGORIZATION_CACHE_TTL" type="number" value={form.categorizationCacheTtl} onChange={(e) => update('categorizationCacheTtl', e.target.value)} />
            <Checkbox label="UT1 blacklists" checked={form.ut1Enabled} onChange={(v) => update('ut1Enabled', v)} />
            {form.ut1Enabled && <Input label="UT1_PATH" value={form.ut1Path} onChange={(e) => update('ut1Path', e.target.value)} />}
            <Checkbox label="URLhaus online lookups" checked={form.urlhausEnabled} onChange={(v) => update('urlhausEnabled', v)} />
            <Checkbox label="PhishTank online lookups" checked={form.phishtankEnabled} onChange={(v) => update('phishtankEnabled', v)} />
            {form.phishtankEnabled && (
              <Input label="PHISHTANK_API_KEY" type="password" value={form.phishtankApiKey} onChange={(e) => update('phishtankApiKey', e.target.value)} hint="Session-only, never persisted" />
            )}
            <Checkbox label="Custom category DB" checked={form.customDbEnabled} onChange={(v) => update('customDbEnabled', v)} />
            {form.customDbEnabled && <Input label="CUSTOM_DB_PATH" value={form.customDbPath} onChange={(e) => update('customDbPath', e.target.value)} />}
          </>
        )}
      </FormSection>
    </div>
  )
}

function ThreatTab({ form, update }: TabProps) {
  return (
    <FormSection title="Threat score enforcement (ml-worker write-back)">
      <Checkbox
        label="THREAT_SCORE_ENABLED"
        checked={form.threatScoreEnabled}
        onChange={(v) => update('threatScoreEnabled', v)}
        hint="Proxy polls the ml-worker snapshot and enforces thresholds on the request path (O(1) in-memory lookup)"
      />
      {form.threatScoreEnabled && (
        <>
          <Input label="THREAT_SCORE_POLL_URL" value={form.threatScorePollUrl} onChange={(e) => update('threatScorePollUrl', e.target.value)} />
          <FormGrid>
            <Input label="Poll interval (s)" type="number" value={form.threatScorePollInterval} onChange={(e) => update('threatScorePollInterval', e.target.value)} />
            <Input label="Block threshold (0–1)" value={form.threatScoreBlockThreshold} onChange={(e) => update('threatScoreBlockThreshold', e.target.value)} />
          </FormGrid>
          <Input label="Warn threshold (0–1)" value={form.threatScoreWarnThreshold} onChange={(e) => update('threatScoreWarnThreshold', e.target.value)} hint="Scores ≥ warn are logged/enriched; ≥ block are denied" />
        </>
      )}
    </FormSection>
  )
}

function NetworkTab({ form, update }: TabProps) {
  return (
    <div className="space-y-6">
      <FormSection title="Cache hierarchy (ICP / HTCP)">
        <Input label="HIERARCHY_PEERS_PATH" value={form.hierarchyPeersPath} onChange={(e) => update('hierarchyPeersPath', e.target.value)} hint="JSON file with parent/sibling peers; empty disables the hierarchy" />
        <Checkbox label="ICP_SERVER_ENABLED" checked={form.icpServerEnabled} onChange={(v) => update('icpServerEnabled', v)} />
        {form.icpServerEnabled && <Input label="ICP_BIND" value={form.icpBind} onChange={(e) => update('icpBind', e.target.value)} />}
        <Checkbox label="HTCP_SERVER_ENABLED" checked={form.htcpServerEnabled} onChange={(v) => update('htcpServerEnabled', v)} />
        {form.htcpServerEnabled && <Input label="HTCP_BIND" value={form.htcpBind} onChange={(e) => update('htcpBind', e.target.value)} />}
        <Checkbox label="PEER_DISCOVERY_ENABLED (multicast)" checked={form.peerDiscoveryEnabled} onChange={(v) => update('peerDiscoveryEnabled', v)} />
        {form.peerDiscoveryEnabled && (
          <Input label="PEER_DISCOVERY_MULTICAST" value={form.peerDiscoveryMulticast} onChange={(e) => update('peerDiscoveryMulticast', e.target.value)} />
        )}
      </FormSection>
      <FormSection title="Upstream TLS / HTTP">
        <Input label="UPSTREAM_CA_CERT" value={form.upstreamCaCert} onChange={(e) => update('upstreamCaCert', e.target.value)} hint="Path to an extra CA bundle for upstream verification (corporate MITM chains)" />
        <Checkbox label="UPSTREAM_HTTP2_ENABLED" checked={form.upstreamHttp2Enabled} onChange={(v) => update('upstreamHttp2Enabled', v)} />
        <Checkbox label="HTTP_PRESERVE_HEADER_CASE" checked={form.preserveHeaderCase} onChange={(v) => update('preserveHeaderCase', v)} />
      </FormSection>
    </div>
  )
}

function SecurityTab({ form, update }: TabProps) {
  return (
    <div className="space-y-6">
      <FormSection title="Rate limiting">
        <Checkbox label="RATE_LIMIT_ENABLED" checked={form.rateLimitEnabled} onChange={(v) => update('rateLimitEnabled', v)} />
        {form.rateLimitEnabled && (
          <Input label="RATE_LIMIT_MAX_KEYS" type="number" value={form.rateLimitMaxKeys} onChange={(e) => update('rateLimitMaxKeys', e.target.value)} />
        )}
      </FormSection>
      <FormSection title="eBPF / XDP kernel drop">
        <Checkbox label="EBPF_XDP_ENABLED" checked={form.ebpfXdpEnabled} onChange={(v) => update('ebpfXdpEnabled', v)} hint="Requires CAP_BPF and a supported NIC driver" />
        {form.ebpfXdpEnabled && (
          <FormGrid>
            <Input label="EBPF_XDP_IFACE" value={form.ebpfXdpIface} onChange={(e) => update('ebpfXdpIface', e.target.value)} />
            <Select
              label="EBPF_XDP_MODE"
              value={form.ebpfXdpMode}
              onChange={(e) => update('ebpfXdpMode', e.target.value)}
              options={[
                { value: 'driver', label: 'driver (native)' },
                { value: 'skb', label: 'skb (generic)' },
                { value: 'hw', label: 'hw (offload)' },
              ]}
            />
          </FormGrid>
        )}
      </FormSection>
      <FormSection title="Wasm request hooks">
        <Checkbox label="WASM_ENABLED" checked={form.wasmEnabled} onChange={(v) => update('wasmEnabled', v)} />
        {form.wasmEnabled && (
          <>
            <Input label="WASM_MODULE_PATH" value={form.wasmModulePath} onChange={(e) => update('wasmModulePath', e.target.value)} />
            <FormGrid>
              <Input label="WASM_FUEL" type="number" value={form.wasmFuel} onChange={(e) => update('wasmFuel', e.target.value)} />
              <div className="pt-6">
                <Checkbox label="WASM_FAIL_OPEN" checked={form.wasmFailOpen} onChange={(v) => update('wasmFailOpen', v)} hint="Allow traffic if the module traps" />
              </div>
            </FormGrid>
          </>
        )}
      </FormSection>
      <FormSection title="gRPC control plane">
        <Checkbox label="CONTROL_GRPC_ENABLED" checked={form.controlGrpcEnabled} onChange={(v) => update('controlGrpcEnabled', v)} />
        {form.controlGrpcEnabled && (
          <Input label="CONTROL_GRPC_BIND" value={form.controlGrpcBind} onChange={(e) => update('controlGrpcBind', e.target.value)} />
        )}
        <Input label="CONTROL_API_TOKEN" type="password" value={form.controlApiToken} onChange={(e) => update('controlApiToken', e.target.value)} hint="Protects /api/stats, /api/cache/purge, hierarchy and TLS endpoints. Session-only." />
      </FormSection>
    </div>
  )
}

function EventsTab({ form, update }: TabProps) {
  return (
    <div className="space-y-6">
      <FormSection title="Kafka event pipeline">
        <FormGrid>
          <Input label="KAFKA_BROKERS" value={form.kafkaBrokers} onChange={(e) => update('kafkaBrokers', e.target.value)} />
          <Input label="KAFKA_TOPIC" value={form.kafkaTopic} onChange={(e) => update('kafkaTopic', e.target.value)} />
        </FormGrid>
        <FormGrid>
          <Input label="KAFKA_SAMPLE_RATE" value={form.kafkaSampleRate} onChange={(e) => update('kafkaSampleRate', e.target.value)} hint="0 = log every request, N = 1-in-N sampling" />
          <Input label="KAFKA_QUEUE_CAPACITY" type="number" value={form.kafkaQueueCapacity} onChange={(e) => update('kafkaQueueCapacity', e.target.value)} />
        </FormGrid>
        <FormGrid>
          <Input label="KAFKA_ACKS" value={form.kafkaAcks} onChange={(e) => update('kafkaAcks', e.target.value)} />
          <Input label="METRICS_SAMPLE_RATE" value={form.metricsSampleRate} onChange={(e) => update('metricsSampleRate', e.target.value)} />
        </FormGrid>
      </FormSection>
      <FormSection title="ClickHouse (search index)">
        <Input label="CLICKHOUSE_URL" value={form.clickhouseUrl} onChange={(e) => update('clickhouseUrl', e.target.value)} />
        <FormGrid>
          <Input label="CLICKHOUSE_DATABASE" value={form.clickhouseDatabase} onChange={(e) => update('clickhouseDatabase', e.target.value)} />
          <Input label="CLICKHOUSE_TABLE" value={form.clickhouseTable} onChange={(e) => update('clickhouseTable', e.target.value)} />
        </FormGrid>
        <Input label="SEARCH_API_TOKEN" type="password" value={form.searchApiToken} onChange={(e) => update('searchApiToken', e.target.value)} hint="Session-only, never persisted" />
      </FormSection>
      <FormSection title="Observability stack (compose export)">
        <Checkbox label="Include Prometheus" checked={form.prometheusEnabled} onChange={(v) => update('prometheusEnabled', v)} />
        <Checkbox label="Include Grafana" checked={form.grafanaEnabled} onChange={(v) => update('grafanaEnabled', v)} />
      </FormSection>
    </div>
  )
}

function ApiTab({
  settings,
  update,
  demoEnabled,
  onDemoChange,
}: {
  settings: ApiSettings
  update: <K extends keyof ApiSettings>(key: K, value: ApiSettings[K]) => void
  demoEnabled: boolean
  onDemoChange: (v: boolean) => void
}) {
  return (
    <div className="space-y-6">
      <FormSection title="API endpoints">
        <p className="text-sm text-text-secondary">
          Leave blank to use Vite dev proxy paths. Set full base URLs in production.
        </p>
        <Input label="Search API base URL" placeholder="http://127.0.0.1:8080" value={settings.searchBaseUrl} onChange={(e) => update('searchBaseUrl', e.target.value)} />
        <Input label="ACL API base URL" placeholder="http://127.0.0.1:9090" value={settings.aclBaseUrl} onChange={(e) => update('aclBaseUrl', e.target.value)} />
        <Input label="Metrics base URL" placeholder="http://127.0.0.1:9090" value={settings.metricsBaseUrl} onChange={(e) => update('metricsBaseUrl', e.target.value)} />
        <Input label="ML worker base URL" placeholder="http://127.0.0.1:8091" value={settings.mlBaseUrl} onChange={(e) => update('mlBaseUrl', e.target.value)} />
        <FormGrid>
          <Input label="Search API token" type="password" value={settings.searchToken} onChange={(e) => update('searchToken', e.target.value)} />
          <Input label="ACL API token" type="password" value={settings.aclToken} onChange={(e) => update('aclToken', e.target.value)} />
        </FormGrid>
      </FormSection>
      <FormSection title="Demo mode">
        <div className="flex items-start gap-3 rounded-md border border-border bg-surface-0 p-4">
          <FlaskConical className="mt-0.5 size-5 shrink-0 text-warning" />
          <div className="flex-1">
            <Checkbox
              label="Serve sample data when APIs are unreachable"
              checked={demoEnabled}
              onChange={onDemoChange}
              hint="Off (default): failures show error states — no fake numbers, ever. On: panels render illustrative data clearly marked with a “Demo” badge."
            />
          </div>
        </div>
      </FormSection>
    </div>
  )
}
