import { useCallback, useState } from 'react'
import { Download, Eye, Upload } from 'lucide-react'
import type { ConfigFormState } from '../lib/config/types'
import { defaultFormState } from '../lib/config/types'
import { cacheMetadataEstimate } from '../lib/config/collect'
import { formatEnv, generateAclRules, generateDockerCompose, downloadFile } from '../lib/config/export'
import { importEnvFile, loadSavedForm, saveFormState } from '../lib/config/import'
import { loadApiSettings, saveApiSettings, type ApiSettings } from '../api/settings'
import { Button } from '../components/ui/Button'
import { Checkbox, FormGrid, FormSection, Input, Select } from '../components/ui/Form'
import { CodePreview, CopyButton, Modal } from '../components/ui/Modal'

type SettingsTab = 'general' | 'cache' | 'auth' | 'acl' | 'api'

const tabs: { id: SettingsTab; label: string }[] = [
  { id: 'general', label: 'General' },
  { id: 'cache', label: 'Cache' },
  { id: 'auth', label: 'Auth' },
  { id: 'acl', label: 'ACL' },
  { id: 'api', label: 'API' },
]

export function SettingsPage() {
  const [form, setForm] = useState<ConfigFormState>(() => loadSavedForm())
  const [apiSettings, setApiSettings] = useState<ApiSettings>(() => loadApiSettings())
  const [tab, setTab] = useState<SettingsTab>('general')
  const [preview, setPreview] = useState<{ title: string; content: string } | null>(null)

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
      alert(`Imported configuration`)
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Settings</h1>
        <p className="text-sm text-text-secondary">
          Proxy configuration generator (migrated from web-config)
        </p>
      </div>

      <div className="flex gap-1 overflow-x-auto border-b border-border pb-px">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`touch-target shrink-0 rounded-t-md px-4 py-2 text-sm font-medium transition-colors ${
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
        {tab === 'acl' && <AclTab form={form} update={update} />}
        {tab === 'api' && <ApiTab settings={apiSettings} update={updateApi} />}
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
            if (!rules) return alert('Enable ACL first')
            downloadFile('acl-rules.json', JSON.stringify(rules, null, 2) + '\n')
          }}
        >
          <Download className="size-4" /> Export ACL
        </Button>
        <label className="touch-target inline-flex cursor-pointer items-center justify-center gap-2 rounded-md border border-border bg-surface-2 px-4 py-2 text-sm font-semibold hover:bg-surface-3">
          <Upload className="size-4" /> Import .env
          <input type="file" accept=".env,text/plain" className="hidden" onChange={handleImport} />
        </label>
        <Button variant="ghost" onClick={() => { setForm(defaultFormState); saveFormState(defaultFormState) }}>
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

type UpdateFn = <K extends keyof ConfigFormState>(key: K, value: ConfigFormState[K]) => void

function GeneralTab({ form, update }: { form: ConfigFormState; update: UpdateFn }) {
  return (
    <FormSection title="General">
      <FormGrid>
        <Input label="HTTP proxy port" type="number" value={form.httpPort} onChange={(e) => update('httpPort', e.target.value)} />
        <Input label="Metrics / ACL API port" type="number" value={form.metricsPort} onChange={(e) => update('metricsPort', e.target.value)} />
      </FormGrid>
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
      <Checkbox label="MITM_ENABLED (HTTPS interception)" checked={form.mitmEnabled} onChange={(v) => update('mitmEnabled', v)} hint="Requires /certs/ca.key and ca.crt" />
    </FormSection>
  )
}

function CacheTab({ form, update }: { form: ConfigFormState; update: UpdateFn }) {
  return (
    <div className="space-y-6">
      <FormSection title="L1 cache">
        <Input label="CACHE_CAPACITY" type="number" value={form.cacheCapacity} onChange={(e) => update('cacheCapacity', e.target.value)} hint={cacheMetadataEstimate(form.cacheCapacity)} />
        <FormGrid>
          <Input label="CACHE_TTL_SECONDS" type="number" value={form.cacheTtl} onChange={(e) => update('cacheTtl', e.target.value)} />
          <Input label="CACHE_SHARDS" type="number" value={form.cacheShards} onChange={(e) => update('cacheShards', e.target.value)} />
        </FormGrid>
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

function AuthTab({ form, update }: { form: ConfigFormState; update: UpdateFn }) {
  return (
    <div className="space-y-4">
      <Checkbox label="AUTH_ENABLED" checked={form.authEnabled} onChange={(v) => update('authEnabled', v)} />
      {form.authEnabled && (
        <>
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
          {form.authBackend === 'ldap' && (
            <FormGrid>
              <Input label="LDAP_SERVERS" value={form.ldapServers} onChange={(e) => update('ldapServers', e.target.value)} />
              <Input label="LDAP_BASE_DN" value={form.ldapBaseDn} onChange={(e) => update('ldapBaseDn', e.target.value)} />
            </FormGrid>
          )}
        </>
      )}
    </div>
  )
}

function AclTab({ form, update }: { form: ConfigFormState; update: UpdateFn }) {
  return (
    <div className="space-y-4">
      <Checkbox label="ACL_ENABLED" checked={form.aclEnabled} onChange={(v) => update('aclEnabled', v)} />
      {form.aclEnabled && (
        <>
          <Select
            label="ACL_DEFAULT_ACTION"
            value={form.aclDefaultAction}
            onChange={(e) => update('aclDefaultAction', e.target.value)}
            options={[
              { value: 'allow', label: 'allow' },
              { value: 'deny', label: 'deny' },
            ]}
          />
          <Input label="ACL_API_TOKEN" type="password" value={form.aclApiToken} onChange={(e) => update('aclApiToken', e.target.value)} />
          <div className="space-y-2">
            <p className="text-sm font-medium text-text-primary">Quick category rules</p>
            <Checkbox label="Block malware" checked={form.aclBlockMalware} onChange={(v) => update('aclBlockMalware', v)} />
            <Checkbox label="Block phishing" checked={form.aclBlockPhishing} onChange={(v) => update('aclBlockPhishing', v)} />
            <Checkbox label="Block gambling" checked={form.aclBlockGambling} onChange={(v) => update('aclBlockGambling', v)} />
            <Checkbox label="Block adult" checked={form.aclBlockAdult} onChange={(v) => update('aclBlockAdult', v)} />
          </div>
        </>
      )}
    </div>
  )
}

function ApiTab({ settings, update }: { settings: ApiSettings; update: <K extends keyof ApiSettings>(key: K, value: ApiSettings[K]) => void }) {
  return (
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
  )
}
