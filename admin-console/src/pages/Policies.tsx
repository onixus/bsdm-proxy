import { useEffect, useState } from 'react'
import { RefreshCw, RotateCcw } from 'lucide-react'
import { fetchAclRules, reloadAclRules, type AclRule, type AclRulesResponse } from '../api/acl'
import { Button } from '../components/ui/Button'
import { Panel } from '../components/dashboard/MetricWidget'

export function PoliciesPage() {
  const [data, setData] = useState<AclRulesResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [reloading, setReloading] = useState(false)

  const load = async () => {
    setLoading(true)
    setData(await fetchAclRules())
    setLoading(false)
  }

  useEffect(() => {
    load()
  }, [])

  const handleReload = async () => {
    setReloading(true)
    try {
      await reloadAclRules()
      await load()
    } catch {
      alert('Reload failed — check ACL API connection in Settings')
    }
    setReloading(false)
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Policies</h1>
          <p className="text-sm text-text-secondary">
            Runtime ACL rules · default action:{' '}
            <span className="font-mono text-text-primary">{data?.default_action ?? '—'}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={load} disabled={loading}>
            <RefreshCw className={`size-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button variant="primary" onClick={handleReload} disabled={reloading}>
            <RotateCcw className={`size-4 ${reloading ? 'animate-spin' : ''}`} />
            Reload rules
          </Button>
        </div>
      </div>

      <Panel title={`Active rules (${data?.rules.length ?? 0})`}>
        {/* Desktop table */}
        <div className="hidden overflow-x-auto md:block">
          <table className="w-full min-w-[600px] text-left text-sm">
            <thead className="text-xs uppercase text-text-secondary">
              <tr>
                <th className="pb-3 pr-4">Priority</th>
                <th className="pb-3 pr-4">Name</th>
                <th className="pb-3 pr-4">Type</th>
                <th className="pb-3 pr-4">Action</th>
                <th className="pb-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {data?.rules.map((rule) => (
                <RuleRow key={rule.id} rule={rule} />
              ))}
            </tbody>
          </table>
        </div>

        {/* Mobile cards */}
        <div className="space-y-3 md:hidden">
          {data?.rules.map((rule) => (
            <div key={rule.id} className="rounded-md border border-border bg-surface-0 p-4">
              <div className="flex items-start justify-between gap-2">
                <span className="font-medium text-text-primary">{rule.name}</span>
                <span className={`text-xs ${rule.enabled ? 'text-success' : 'text-text-secondary'}`}>
                  {rule.enabled ? 'enabled' : 'disabled'}
                </span>
              </div>
              <p className="mt-1 font-mono text-xs text-text-secondary">
                P{rule.priority} · {rule.action} · {formatRuleType(rule)}
              </p>
            </div>
          ))}
        </div>
      </Panel>

      <div className="rounded-lg border border-border bg-surface-0 p-4 text-sm text-text-secondary">
        Export full ACL JSON from Settings → Export ACL. Live edits via{' '}
        <code className="rounded bg-surface-2 px-1 font-mono text-xs">POST /api/acl/rules</code>.
      </div>
    </div>
  )
}

function RuleRow({ rule }: { rule: AclRule }) {
  return (
    <tr className="border-t border-border/50">
      <td className="py-3 pr-4 font-mono text-xs">{rule.priority}</td>
      <td className="py-3 pr-4">{rule.name}</td>
      <td className="py-3 pr-4 font-mono text-xs">{formatRuleType(rule)}</td>
      <td className="py-3 pr-4 capitalize">{rule.action}</td>
      <td className="py-3">
        <span className={rule.enabled ? 'text-success' : 'text-text-secondary'}>
          {rule.enabled ? 'enabled' : 'disabled'}
        </span>
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
