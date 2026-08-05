import { useEffect, useState } from 'react'
import {
  CheckCircle2,
  CircleDashed,
  FlaskConical,
  RefreshCw,
  ShieldAlert,
  WifiOff,
} from 'lucide-react'
import type { ApiSettings } from '../../../api/settings'
import { checkApiHealth, type ApiHealthResult } from '../../../api/health'
import { Button } from '../../../components/ui/Button'
import { Checkbox, FormGrid, FormSection, Input } from '../../../components/ui/Form'

export function ApiTab({
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
  const [health, setHealth] = useState<ApiHealthResult[] | null>(null)
  const [checking, setChecking] = useState(false)

  useEffect(() => {
    setHealth(null)
  }, [settings])

  const runHealthCheck = async () => {
    setChecking(true)
    try {
      setHealth(await checkApiHealth(settings))
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="space-y-6">
      <FormSection title="Connection">
        <p className="text-sm text-text-secondary">
          Prefer <strong className="text-text-primary">single endpoint</strong> on the control plane
          (:9090). Search is same-origin via the proxy when <code className="text-xs">SEARCH_UPSTREAM_URL</code>{' '}
          is set. Leave the URL blank for local same-origin / Vite.
        </p>
        <div className="grid gap-3 sm:grid-cols-2" role="radiogroup" aria-label="API connection mode">
          <ConnectionModeCard
            title="Single endpoint"
            description="Recommended: one gateway URL and token for every Admin Console API."
            selected={settings.connectionMode === 'single'}
            onClick={() => update('connectionMode', 'single')}
          />
          <ConnectionModeCard
            title="Advanced split deployment"
            description="Configure Search, ACL, Control, and ML services independently."
            selected={settings.connectionMode === 'advanced'}
            onClick={() => update('connectionMode', 'advanced')}
          />
        </div>

        {settings.connectionMode === 'single' ? (
          <>
            <Input
              label="Control Plane base URL"
              placeholder="https://proxy.example.com"
              value={settings.controlPlaneBaseUrl}
              onChange={(e) => update('controlPlaneBaseUrl', e.target.value)}
              hint="Gateway should expose /api/search, /api/acl, /api/stats, /api/dns/*, /metrics on this origin."
            />
            <Input
              label="Control Plane token"
              type="password"
              value={settings.controlPlaneToken}
              onChange={(e) => update('controlPlaneToken', e.target.value)}
              hint="Kept in memory for this browser tab; never persisted to localStorage."
            />
          </>
        ) : (
          <>
            <p className="rounded-md border border-warning/30 bg-warning/10 p-3 text-xs text-warning">
              Advanced mode is for deployments without a unified gateway. Verify every service below.
            </p>
            <Input
              label="Search API base URL"
              placeholder="http://127.0.0.1:8080"
              value={settings.searchBaseUrl}
              onChange={(e) => update('searchBaseUrl', e.target.value)}
            />
            <Input
              label="ACL API base URL"
              placeholder="http://127.0.0.1:9090"
              value={settings.aclBaseUrl}
              onChange={(e) => update('aclBaseUrl', e.target.value)}
            />
            <Input
              label="Control / Metrics base URL"
              placeholder="http://127.0.0.1:9090"
              value={settings.metricsBaseUrl}
              onChange={(e) => update('metricsBaseUrl', e.target.value)}
            />
            <Input
              label="ML worker base URL"
              placeholder="http://127.0.0.1:8091"
              value={settings.mlBaseUrl}
              onChange={(e) => update('mlBaseUrl', e.target.value)}
            />
            <FormGrid>
              <Input
                label="Search API token"
                type="password"
                value={settings.searchToken}
                onChange={(e) => update('searchToken', e.target.value)}
              />
              <Input
                label="ACL API token"
                type="password"
                value={settings.aclToken}
                onChange={(e) => update('aclToken', e.target.value)}
              />
              <Input
                label="Control API token"
                type="password"
                value={settings.controlToken}
                onChange={(e) => update('controlToken', e.target.value)}
              />
            </FormGrid>
          </>
        )}
      </FormSection>

      <FormSection title="Service health">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-text-secondary">
            Read-only checks show whether each dependency is connected, unauthorized, or unreachable.
          </p>
          <Button variant="secondary" onClick={runHealthCheck} disabled={checking}>
            <RefreshCw className={`size-4 ${checking ? 'animate-spin' : ''}`} />
            {checking ? 'Checking…' : 'Test connection'}
          </Button>
        </div>
        <div className="grid gap-3 sm:grid-cols-2" aria-live="polite">
          {(
            health ?? [
              { id: 'control', name: 'Control / Metrics' },
              { id: 'acl', name: 'ACL' },
              { id: 'search', name: 'Search' },
              { id: 'ml', name: 'ML worker' },
            ]
          ).map((service) => (
            <HealthCard
              key={service.id}
              result={'status' in service ? (service as ApiHealthResult) : null}
              name={service.name}
              checking={checking}
            />
          ))}
        </div>
      </FormSection>
      <FormSection title="Demo mode">
        <div className="flex items-start gap-3 rounded-md border border-border bg-surface-0 p-4">
          <FlaskConical className="mt-0.5 size-5 shrink-0 text-warning" />
          <div className="flex-1">
            <Checkbox
              label="Serve sample data when APIs are unreachable"
              checked={demoEnabled}
              onChange={onDemoChange}
              hint="Off (default): failures show error states. On: panels render sample data marked “Demo”."
            />
          </div>
        </div>
      </FormSection>
    </div>
  )
}

function ConnectionModeCard({
  title,
  description,
  selected,
  onClick,
}: {
  title: string
  description: string
  selected: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      onClick={onClick}
      className={`rounded-lg border p-4 text-left transition-colors ${
        selected
          ? 'border-accent/60 bg-accent/10'
          : 'border-border bg-surface-0 hover:border-accent/30 hover:bg-surface-2'
      }`}
    >
      <span className={`block text-sm font-semibold ${selected ? 'text-accent' : 'text-text-primary'}`}>
        {title}
      </span>
      <span className="mt-1 block text-xs leading-relaxed text-text-secondary">{description}</span>
    </button>
  )
}

function HealthCard({
  name,
  result,
  checking,
}: {
  name: string
  result: ApiHealthResult | null
  checking: boolean
}) {
  const state = checking
    ? { icon: RefreshCw, label: 'Checking…', color: 'text-text-secondary', border: 'border-border' }
    : result?.status === 'healthy'
      ? { icon: CheckCircle2, label: result.detail, color: 'text-success', border: 'border-success/30' }
      : result?.status === 'unauthorized'
        ? { icon: ShieldAlert, label: result.detail, color: 'text-warning', border: 'border-warning/30' }
        : result?.status === 'unreachable'
          ? { icon: WifiOff, label: result.detail, color: 'text-danger', border: 'border-danger/30' }
          : { icon: CircleDashed, label: 'Not checked', color: 'text-text-secondary', border: 'border-border' }
  const Icon = state.icon

  return (
    <div className={`rounded-lg border bg-surface-0 p-3.5 ${state.border}`}>
      <div className="flex items-center gap-2">
        <Icon className={`size-4 shrink-0 ${state.color} ${checking ? 'animate-spin' : ''}`} />
        <span className="text-sm font-semibold text-text-primary">{name}</span>
      </div>
      <p className={`mt-1.5 text-xs ${state.color}`}>{state.label}</p>
      {result && (
        <p className="mt-1 truncate font-mono text-[10px] text-text-secondary" title={result.endpoint}>
          {result.endpoint}
        </p>
      )}
    </div>
  )
}
