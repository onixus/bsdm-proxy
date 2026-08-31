import { useCallback, useEffect, useState } from 'react'
import {
  Laptop,
  RefreshCw,
  ShieldOff,
  Send,
  Shield,
  Activity,
} from 'lucide-react'
import {
  fetchDevices,
  revokeDevice,
  fetchAgentPolicy,
  pushAgentPolicy,
  fetchAgentCrl,
  fetchAgentEventsRecent,
  type AgentDevice,
  type AgentPolicyDocument,
  type AgentCrlDocument,
  type AgentRecentEvent,
} from '../api/agent'
import { Button } from '../components/ui/Button'
import { Panel } from '../components/dashboard/MetricWidget'
import { useToast } from '../components/ui/Toast'
import { useLanguage, translations } from '../lib/i18n'

function formatTs(ts?: number | null): string {
  if (!ts) return '—'
  try {
    return new Date(ts * 1000).toLocaleString()
  } catch {
    return String(ts)
  }
}

function statusClass(status: string): string {
  switch (status) {
    case 'Secured':
      return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
    case 'Flagged':
      return 'bg-amber-500/15 text-amber-400 border-amber-500/30'
    case 'Revoked':
      return 'bg-red-500/15 text-red-400 border-red-500/30'
    default:
      return 'bg-surface-2 text-text-secondary border-border'
  }
}

function StatCard({
  label,
  value,
  icon: Icon,
  tone = 'accent',
}: {
  label: string
  value: number | string
  icon: typeof Laptop
  tone?: 'accent' | 'ok' | 'danger'
}) {
  const toneClass =
    tone === 'ok'
      ? 'bg-emerald-500/15 text-emerald-400'
      : tone === 'danger'
        ? 'bg-red-500/15 text-red-400'
        : 'bg-accent/15 text-accent'
  return (
    <article className="rounded-xl border border-border/80 bg-surface-1/90 p-4 shadow-sm">
      <div className="flex items-center gap-3">
        <div className={`flex size-9 items-center justify-center rounded-lg ${toneClass}`}>
          <Icon className="size-4" />
        </div>
        <div>
          <p className="text-xs uppercase tracking-wider text-text-secondary">{label}</p>
          <p className="text-xl font-bold text-text-primary">{value}</p>
        </div>
      </div>
    </article>
  )
}

export function DevicesPage() {
  const [lang] = useLanguage()
  const t = translations[lang].devicesPage
  const { toast } = useToast()

  const [devices, setDevices] = useState<AgentDevice[]>([])
  const [policy, setPolicy] = useState<AgentPolicyDocument | null>(null)
  const [crl, setCrl] = useState<AgentCrlDocument | null>(null)
  const [events, setEvents] = useState<AgentRecentEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [pushing, setPushing] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [devs, pol, crlDoc, recent] = await Promise.all([
        fetchDevices(),
        fetchAgentPolicy().catch(() => null),
        fetchAgentCrl().catch(() => null),
        fetchAgentEventsRecent().catch(() => ({ events: [] as AgentRecentEvent[] })),
      ])
      setDevices(devs ?? [])
      setPolicy(pol)
      setCrl(crlDoc)
      setEvents(recent?.events ?? [])
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t.loadError
      setError(message)
    } finally {
      setLoading(false)
    }
  }, [t.loadError])

  useEffect(() => {
    void load()
  }, [load])

  const handleRevoke = async (device: AgentDevice) => {
    if (device.status === 'Revoked') return
    if (!window.confirm(t.revokeConfirm.replace('{id}', device.id))) return
    setBusyId(device.id)
    try {
      await revokeDevice(device.id)
      toast('success', t.revokeSuccess.replace('{id}', device.id))
      await load()
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t.revokeError
      toast('error', message)
    } finally {
      setBusyId(null)
    }
  }

  const handlePush = async () => {
    setPushing(true)
    try {
      const result = await pushAgentPolicy({
        reason: 'admin-console',
        actor: 'admin-console',
      })
      toast('success', t.pushSuccess.replace('{version}', result.policy_version))
      await load()
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t.pushError
      toast('error', message)
    } finally {
      setPushing(false)
    }
  }

  if (loading && devices.length === 0) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <div className="text-text-secondary">{t.loading}</div>
      </div>
    )
  }

  if (error && devices.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-6">
        <div className="text-danger">{error}</div>
        <Button variant="secondary" onClick={() => void load()}>
          <RefreshCw className="size-4" />
          {t.refresh}
        </Button>
      </div>
    )
  }

  const secured = devices.filter((d) => d.status === 'Secured').length
  const revoked = devices.filter((d) => d.status === 'Revoked').length

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{t.title}</h1>
          <p className="mt-1 max-w-2xl text-sm text-text-secondary">{t.subtitle}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={`size-4 ${loading ? 'animate-spin' : ''}`} />
            {t.refresh}
          </Button>
          <Button variant="primary" onClick={() => void handlePush()} isLoading={pushing}>
            <Send className="size-4" />
            {t.pushPolicy}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label={t.statDevices} value={devices.length} icon={Laptop} />
        <StatCard label={t.statSecured} value={secured} icon={Shield} tone="ok" />
        <StatCard label={t.statRevoked} value={revoked} icon={ShieldOff} tone="danger" />
        <StatCard label={t.statCrl} value={crl?.count ?? 0} icon={Activity} />
      </div>

      {policy && (
        <Panel title={t.policyTitle} icon={Shield}>
          <p className="font-mono text-xs text-text-secondary">
            {t.policyVersion}: {policy.policy_version}
            {policy.policy_mode ? ` · ${policy.policy_mode}` : ''}
          </p>
          {policy.sni_deny_patterns && policy.sni_deny_patterns.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1">
              {policy.sni_deny_patterns.slice(0, 8).map((p) => (
                <span
                  key={p}
                  className="rounded border border-border bg-surface-2 px-2 py-0.5 font-mono text-[11px] text-text-secondary"
                >
                  {p}
                </span>
              ))}
            </div>
          )}
        </Panel>
      )}

      <Panel title={t.devicesTable} icon={Laptop}>
        <div className="-mx-5 -mb-5 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-y border-border bg-surface-0/80 text-xs uppercase tracking-wider text-text-secondary">
              <tr>
                <th className="px-4 py-3 font-medium">{t.colId}</th>
                <th className="px-4 py-3 font-medium">{t.colName}</th>
                <th className="px-4 py-3 font-medium">{t.colPlatform}</th>
                <th className="px-4 py-3 font-medium">{t.colStatus}</th>
                <th className="px-4 py-3 font-medium">{t.colTrust}</th>
                <th className="px-4 py-3 font-medium">{t.colLastSeen}</th>
                <th className="px-4 py-3 font-medium text-right">{t.colActions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {devices.map((device) => (
                <tr key={device.id} className="hover:bg-surface-2/40">
                  <td className="px-4 py-3 font-mono text-xs text-text-primary">{device.id}</td>
                  <td className="px-4 py-3 text-text-primary">
                    <div>{device.name || '—'}</div>
                    {device.userIdentity && (
                      <div className="text-xs text-text-secondary">{device.userIdentity}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-text-secondary">
                    {device.platform || device.type || '—'}
                    {device.agentVersion ? (
                      <span className="ml-1 font-mono text-[11px] opacity-70">
                        v{device.agentVersion}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-col gap-1 items-start">
                      <span
                        className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-medium ${statusClass(device.status)}`}
                      >
                        {device.status}
                      </span>
                      {policy && device.policyVersion && device.policyVersion !== policy.policy_version && (
                        <span className="inline-flex rounded border border-amber-500/30 bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-400">
                          Drift: {device.policyVersion}
                        </span>
                      )}
                      {device.systemProxyEnforced && (
                        <span className="inline-flex rounded border border-emerald-500/30 bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-400">
                          OS Proxy Active
                        </span>
                      )}
                      {device.activeTunnel && (
                        <span className="inline-flex rounded border border-sky-500/30 bg-sky-500/15 px-1.5 py-0.5 text-[10px] font-medium text-sky-400">
                          {device.activeTunnel}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-text-secondary">
                    {device.trustScore != null ? device.trustScore : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-text-secondary">
                    {formatTs(device.lastSeen)}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Button
                      variant="danger"
                      className="!px-2 !py-1 text-xs"
                      disabled={device.status === 'Revoked' || busyId === device.id}
                      isLoading={busyId === device.id}
                      onClick={() => void handleRevoke(device)}
                    >
                      <ShieldOff className="size-3.5" />
                      {t.revoke}
                    </Button>
                  </td>
                </tr>
              ))}
              {devices.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-text-secondary">
                    {t.noDevices}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title={t.eventsTitle} icon={Activity}>
          <div className="-mx-5 -mb-5 max-h-72 overflow-y-auto">
            {events.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-text-secondary">{t.noEvents}</p>
            ) : (
              <ul className="divide-y divide-border">
                {events.slice(0, 25).map((ev, i) => (
                  <li key={`${ev.device_id}-${i}`} className="px-5 py-2.5 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-text-primary">{ev.device_id}</span>
                      <span className="rounded bg-surface-2 px-1.5 py-0.5 text-text-secondary">
                        {ev.action ?? '—'}
                      </span>
                      {ev.domain && <span className="text-text-secondary">{ev.domain}</span>}
                    </div>
                    <div className="mt-0.5 text-text-secondary">
                      {ev.decision_source ?? ''}
                      {ev.reason ? ` · ${ev.reason}` : ''}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Panel>

        <Panel
          title={t.crlTitle}
          icon={ShieldOff}
          action={
            crl ? (
              <span className="font-mono text-[11px] text-text-secondary">
                #{crl.crl_number} · {crl.count} {t.entries}
              </span>
            ) : undefined
          }
        >
          <div className="-mx-5 -mb-5 max-h-72 overflow-y-auto">
            {!crl || crl.entries.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-text-secondary">{t.noCrl}</p>
            ) : (
              <ul className="divide-y divide-border">
                {crl.entries.map((e) => (
                  <li key={`${e.fingerprint}-${e.revoked_at}`} className="px-5 py-2.5 text-xs">
                    <div className="font-mono text-text-primary">{e.device_id}</div>
                    <div className="mt-0.5 truncate text-text-secondary" title={e.fingerprint}>
                      fp {e.fingerprint.slice(0, 16)}…
                      {e.reason ? ` · ${e.reason}` : ''}
                    </div>
                    <div className="text-text-secondary">{formatTs(e.revoked_at)}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Panel>
      </div>
    </div>
  )
}
