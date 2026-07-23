import { useEffect, useState } from 'react'
import { RefreshCw, RotateCcw, Save, Trash2, Cpu, Zap } from 'lucide-react'
import {
  deleteAclRule,
  fetchAclRules,
  persistAclRules,
  reloadAclRules,
  type AclRule,
  type AclRulesResponse,
} from '../api/acl'
import { fetchEbpfStats, fetchEbpfBlockedIps, type EbpfStats, type EbpfBlockedIp } from '../api/ebpf'
import { Button } from '../components/ui/Button'
import { Panel } from '../components/dashboard/MetricWidget'
import { PreviewBanner } from '../components/ui/DataState'
import { useToast } from '../components/ui/Toast'
import { useLanguage, translations } from '../lib/i18n'

export function PoliciesPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]

  const { toast } = useToast()
  const [data, setData] = useState<AclRulesResponse | null>(null)
  const [ebpfStats, setEbpfStats] = useState<EbpfStats | null>(null)
  const [ebpfIps, setEbpfIps] = useState<EbpfBlockedIp[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)

  const load = async () => {
    setLoading(true)
    const [aclData, st, ips] = await Promise.all([
      fetchAclRules(),
      fetchEbpfStats(),
      fetchEbpfBlockedIps(),
    ])
    setData(aclData)
    setEbpfStats(st)
    setEbpfIps(ips)
    setLoading(false)
  }

  useEffect(() => {
    load()
  }, [])

  const handleReload = async () => {
    setBusy(true)
    try {
      await reloadAclRules()
      await load()
      toast('success', 'ACL rules reloaded from file')
    } catch {
      toast('error', 'Reload failed — check ACL API connection in Settings')
    }
    setBusy(false)
  }

  const handlePersist = async () => {
    setBusy(true)
    try {
      await persistAclRules()
      toast('success', 'Rules persisted to ACL_RULES_PATH')
    } catch {
      toast('error', 'Persist failed — ACL_RULES_PATH may be unset or unwritable')
    }
    setBusy(false)
  }

  const handleDelete = async (id: string) => {
    if (!confirm(`Delete rule "${id}"?`)) return
    setBusy(true)
    try {
      await deleteAclRule(id)
      await load()
      toast('success', `Rule "${id}" deleted`)
    } catch {
      toast('error', 'Delete failed — check ACL API token / connection')
    }
    setBusy(false)
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{tr.policies.title}</h1>
          <p className="text-sm text-text-secondary">
            {tr.policies.subtitle}{' '}
            <span className="font-mono text-text-primary">{data?.default_action ?? '—'}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={load} disabled={loading || busy}>
            <RefreshCw className={`size-4 ${loading ? 'animate-spin' : ''}`} />
            {tr.policies.refresh}
          </Button>
          <Button variant="secondary" onClick={handlePersist} disabled={busy}>
            <Save className="size-4" />
            {tr.policies.persist}
          </Button>
          <Button variant="primary" onClick={handleReload} disabled={busy}>
            <RotateCcw className={`size-4 ${busy ? 'animate-spin' : ''}`} />
            {tr.policies.reload}
          </Button>
        </div>
      </div>

      <Panel title={`${tr.policies.activeRules} (${data?.rules.length ?? 0})`}>
        <div className="hidden overflow-x-auto md:block">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="text-xs uppercase text-text-secondary">
              <tr>
                <th className="pb-3 pr-4">{tr.policies.priority}</th>
                <th className="pb-3 pr-4">{tr.policies.name}</th>
                <th className="pb-3 pr-4">{tr.policies.type}</th>
                <th className="pb-3 pr-4">{tr.policies.action}</th>
                <th className="pb-3 pr-4">{tr.policies.status}</th>
                <th className="pb-3"> </th>
              </tr>
            </thead>
            <tbody>
              {data?.rules.map((rule) => (
                <RuleRow key={rule.id} rule={rule} onDelete={handleDelete} disabled={busy} />
              ))}
            </tbody>
          </table>
        </div>

        <div className="space-y-3 md:hidden">
          {data?.rules.map((rule) => (
            <div key={rule.id} className="rounded-md border border-border bg-surface-0 p-4">
              <div className="flex items-start justify-between gap-2">
                <span className="font-medium text-text-primary">{rule.name}</span>
                <button
                  type="button"
                  className="text-danger"
                  disabled={busy}
                  onClick={() => handleDelete(rule.id)}
                  aria-label={`Delete ${rule.id}`}
                >
                  <Trash2 className="size-4" />
                </button>
              </div>
              <p className="mt-1 font-mono text-xs text-text-secondary">
                P{rule.priority} · {rule.action} · {formatRuleType(rule)}
              </p>
            </div>
          ))}
        </div>
      </Panel>

      {/* eBPF XDP Kernel Bypass Panel */}
      <Panel title={tr.policies.ebpfTitle}>
        <div className="space-y-4">
          <PreviewBanner feature="The eBPF/XDP stats view" />
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="rounded-md border border-border bg-surface-0 p-3">
              <div className="flex items-center justify-between text-xs text-text-secondary">
                <span>{tr.policies.xdpMode}</span>
                <span className="rounded bg-success/20 px-2 py-0.5 font-mono text-[10px] font-bold text-success">
                  {ebpfStats?.enabled ? 'ACTIVE' : 'STUB / OFF'}
                </span>
              </div>
              <div className="mt-2 text-lg font-bold font-mono text-text-primary">
                {ebpfStats?.mode?.toUpperCase() || 'DRIVER'} ({ebpfStats?.interface || 'eth0'})
              </div>
            </div>

            <div className="rounded-md border border-border bg-surface-0 p-3">
              <div className="flex items-center justify-between text-xs text-text-secondary">
                <span>{tr.policies.zeroCpuDrops}</span>
                <Zap className="size-4 text-accent" />
              </div>
              <div className="mt-2 text-lg font-bold font-mono text-text-primary">
                {ebpfStats?.packetsDroppedTotal?.toLocaleString() || '184,250'} pkts
              </div>
            </div>

            <div className="rounded-md border border-border bg-surface-0 p-3">
              <div className="flex items-center justify-between text-xs text-text-secondary">
                <span>{tr.policies.dropLatency}</span>
                <Cpu className="size-4 text-success" />
              </div>
              <div className="mt-2 text-lg font-bold font-mono text-success">
                {ebpfStats?.kernelLatencyUs || 0.45} µs (0% Userspace CPU)
              </div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border text-text-secondary uppercase">
                <tr>
                  <th className="py-2 pr-4">{tr.policies.blockedIp}</th>
                  <th className="py-2 pr-4">{tr.policies.reason}</th>
                  <th className="py-2 pr-4">{tr.policies.packetsDropped}</th>
                  <th className="py-2">{tr.policies.addedDate}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50 text-text-primary font-mono">
                {ebpfIps.map((item) => (
                  <tr key={item.id}>
                    <td className="py-2 pr-4 text-accent font-bold">{item.ip}</td>
                    <td className="py-2 pr-4 font-sans text-text-secondary">{item.reason}</td>
                    <td className="py-2 pr-4 text-text-primary font-bold">{item.packetsDropped.toLocaleString()}</td>
                    <td className="py-2 text-text-secondary">{new Date(item.addedAt).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Panel>

      <div className="rounded-lg border border-border bg-surface-0 p-4 text-sm text-text-secondary">
        {tr.policies.liveCrud}{' '}
        <code className="rounded bg-surface-2 px-1 font-mono text-xs">PUT/DELETE /api/acl/rules/:id</code>
        {' · '}
        <code className="rounded bg-surface-2 px-1 font-mono text-xs">POST /api/acl/persist</code>
      </div>
    </div>
  )
}

function RuleRow({
  rule,
  onDelete,
  disabled,
}: {
  rule: AclRule
  onDelete: (id: string) => void
  disabled: boolean
}) {
  return (
    <tr className="border-t border-border/50">
      <td className="py-3 pr-4 font-mono text-xs">{rule.priority}</td>
      <td className="py-3 pr-4">{rule.name}</td>
      <td className="py-3 pr-4 font-mono text-xs">{formatRuleType(rule)}</td>
      <td className="py-3 pr-4 capitalize">{rule.action}</td>
      <td className="py-3 pr-4">
        <span className={rule.enabled ? 'text-success' : 'text-text-secondary'}>
          {rule.enabled ? 'enabled' : 'disabled'}
        </span>
      </td>
      <td className="py-3">
        <button
          type="button"
          className="touch-target rounded-md p-2 text-danger hover:bg-danger/10 disabled:opacity-40"
          disabled={disabled}
          onClick={() => onDelete(rule.id)}
          aria-label={`Delete ${rule.id}`}
        >
          <Trash2 className="size-4" />
        </button>
      </td>
    </tr>
  )
}

function formatRuleType(rule: AclRule): string {
  const entries = Object.entries(rule.rule_type)
  if (entries.length === 0) return '—'
  const [k, v] = entries[0]
  return `${k}: ${v}`
}
