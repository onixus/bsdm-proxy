import { useEffect, useState } from 'react'
import { Shield, Save, Trash2, Plus } from 'lucide-react'
import {
  fetchCasbDomains,
  saveCasbDomains,
  fetchDlpPatterns,
  saveDlpPatterns,
  type DlpPatternDto,
} from '../api/security'
import { Button } from '../components/ui/Button'
import { Panel } from '../components/dashboard/MetricWidget'
import { useToast } from '../components/ui/Toast'

export function DataSecurityPage() {
  const { toast } = useToast()
  
  // CASB state
  const [casbDomains, setCasbDomains] = useState<string[]>([])
  const [newDomain, setNewDomain] = useState('')
  
  // DLP state
  const [dlpPatterns, setDlpPatterns] = useState<DlpPatternDto[]>([])
  const [newPattern, setNewPattern] = useState('')
  const [newDescription, setNewDescription] = useState('')

  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)

  const load = async () => {
    setLoading(true)
    const [domains, patterns] = await Promise.all([
      fetchCasbDomains(),
      fetchDlpPatterns(),
    ])
    setCasbDomains(domains)
    setDlpPatterns(patterns)
    setLoading(false)
  }

  useEffect(() => {
    load()
  }, [])

  const handleSaveCasb = async () => {
    setBusy(true)
    try {
      await saveCasbDomains(casbDomains)
      toast('success', 'CASB domains updated successfully')
    } catch {
      toast('error', 'Failed to update CASB domains')
    }
    setBusy(false)
  }

  const handleAddDomain = () => {
    if (!newDomain.trim()) return
    if (casbDomains.includes(newDomain.trim())) {
      toast('error', 'Domain already exists')
      return
    }
    setCasbDomains((prev) => [...prev, newDomain.trim()].sort())
    setNewDomain('')
  }

  const handleRemoveDomain = (domain: string) => {
    setCasbDomains((prev) => prev.filter((d) => d !== domain))
  }

  const handleSaveDlp = async () => {
    setBusy(true)
    try {
      await saveDlpPatterns(dlpPatterns)
      toast('success', 'DLP patterns updated successfully')
    } catch {
      toast('error', 'Failed to update DLP patterns')
    }
    setBusy(false)
  }

  const handleAddPattern = () => {
    if (!newPattern.trim() || !newDescription.trim()) {
      toast('error', 'Pattern and description are required')
      return
    }
    if (dlpPatterns.some((p) => p.pattern === newPattern.trim())) {
      toast('error', 'Pattern already exists')
      return
    }
    setDlpPatterns((prev) => [
      ...prev,
      { pattern: newPattern.trim(), description: newDescription.trim() },
    ])
    setNewPattern('')
    setNewDescription('')
  }

  const handleRemovePattern = (pattern: string) => {
    setDlpPatterns((prev) => prev.filter((p) => p.pattern !== pattern))
  }

  if (loading) {
    return <div className="p-8 text-center text-text-secondary animate-pulse">Loading security config...</div>
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Shield className="size-6 text-accent" />
          Data Security (CASB & DLP)
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          Manage inline data leak prevention and cloud application access policies.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="GenAI CASB Providers">
          <div className="text-xs text-text-secondary mb-4">
            Monitored LLM provider domains. Traffic to these domains will be intercepted 
            and analyzed by the local CASB engine.
          </div>
          
          <div className="space-y-4">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="e.g. api.openai.com"
                className="flex-1 rounded-md border border-border bg-surface-0 px-3 py-1.5 text-sm outline-none focus:border-accent focus:ring-1 focus:ring-accent/50"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAddDomain()}
                disabled={busy}
              />
              <Button variant="secondary" onClick={handleAddDomain} disabled={busy || !newDomain.trim()}>
                <Plus className="size-4" /> Add
              </Button>
            </div>

            <div className="max-h-[300px] overflow-y-auto rounded-md border border-border">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-surface-1 text-xs uppercase text-text-secondary border-b border-border">
                  <tr>
                    <th className="py-2 pl-4">Domain</th>
                    <th className="py-2 pr-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50 bg-surface-0">
                  {casbDomains.length === 0 ? (
                    <tr>
                      <td colSpan={2} className="py-4 text-center text-text-secondary italic text-xs">
                        No domains monitored
                      </td>
                    </tr>
                  ) : casbDomains.map((domain) => (
                    <tr key={domain}>
                      <td className="py-2 pl-4 font-mono text-text-primary">{domain}</td>
                      <td className="py-2 pr-4 text-right">
                        <button
                          type="button"
                          className="text-danger hover:text-danger/80 p-1"
                          onClick={() => handleRemoveDomain(domain)}
                          disabled={busy}
                          title="Remove domain"
                        >
                          <Trash2 className="size-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex justify-end pt-2">
              <Button variant="primary" onClick={handleSaveCasb} disabled={busy}>
                <Save className="size-4" />
                Apply CASB Rules
              </Button>
            </div>
          </div>
        </Panel>

        <Panel title="Inline DLP Patterns">
          <div className="text-xs text-text-secondary mb-4">
            Aho-Corasick patterns to block sensitive data leakage in HTTP request bodies 
            (e.g., POST/PUT requests) to untrusted upstreams or CASB providers.
          </div>
          
          <div className="space-y-4">
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                type="text"
                placeholder="String Pattern (e.g. sk-proj-)"
                className="w-full sm:w-1/3 rounded-md border border-border bg-surface-0 px-3 py-1.5 text-sm outline-none focus:border-accent focus:ring-1 focus:ring-accent/50 font-mono"
                value={newPattern}
                onChange={(e) => setNewPattern(e.target.value)}
                disabled={busy}
              />
              <input
                type="text"
                placeholder="Description"
                className="flex-1 rounded-md border border-border bg-surface-0 px-3 py-1.5 text-sm outline-none focus:border-accent focus:ring-1 focus:ring-accent/50"
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAddPattern()}
                disabled={busy}
              />
              <Button variant="secondary" onClick={handleAddPattern} disabled={busy || !newPattern.trim() || !newDescription.trim()}>
                <Plus className="size-4" /> Add
              </Button>
            </div>

            <div className="max-h-[300px] overflow-y-auto rounded-md border border-border">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-surface-1 text-xs uppercase text-text-secondary border-b border-border">
                  <tr>
                    <th className="py-2 pl-4">Pattern</th>
                    <th className="py-2 pl-4">Description</th>
                    <th className="py-2 pr-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50 bg-surface-0">
                  {dlpPatterns.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="py-4 text-center text-text-secondary italic text-xs">
                        No DLP patterns active
                      </td>
                    </tr>
                  ) : dlpPatterns.map((p) => (
                    <tr key={p.pattern}>
                      <td className="py-2 pl-4 font-mono text-text-primary break-all max-w-[150px]">{p.pattern}</td>
                      <td className="py-2 pl-4 text-text-secondary text-xs">{p.description}</td>
                      <td className="py-2 pr-4 text-right">
                        <button
                          type="button"
                          className="text-danger hover:text-danger/80 p-1"
                          onClick={() => handleRemovePattern(p.pattern)}
                          disabled={busy}
                          title="Remove pattern"
                        >
                          <Trash2 className="size-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex justify-end pt-2">
              <Button variant="primary" onClick={handleSaveDlp} disabled={busy}>
                <Save className="size-4" />
                Apply DLP Patterns
              </Button>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}
