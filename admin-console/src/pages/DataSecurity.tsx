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
import { useLanguage, translations } from '../lib/i18n'

export function DataSecurityPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]

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
      toast('success', tr.dataSecurity.casbSuccess)
    } catch {
      toast('error', tr.dataSecurity.casbError)
    }
    setBusy(false)
  }

  const handleAddDomain = () => {
    if (!newDomain.trim()) return
    if (casbDomains.includes(newDomain.trim())) {
      toast('error', tr.dataSecurity.domainExists)
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
      toast('success', tr.dataSecurity.dlpSuccess)
    } catch {
      toast('error', tr.dataSecurity.dlpError)
    }
    setBusy(false)
  }

  const handleAddPattern = () => {
    if (!newPattern.trim() || !newDescription.trim()) {
      toast('error', tr.dataSecurity.dlpRequired)
      return
    }
    if (dlpPatterns.some((p) => p.pattern === newPattern.trim())) {
      toast('error', tr.dataSecurity.patternExists)
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
    return <div className="p-8 text-center text-text-secondary animate-pulse">{tr.dataSecurity.loading}</div>
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Shield className="size-6 text-accent" />
          {tr.dataSecurity.title}
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          {tr.dataSecurity.subtitle}
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title={tr.dataSecurity.casbTitle}>
          <div className="text-xs text-text-secondary mb-4">
            {tr.dataSecurity.casbDesc}
          </div>
          
          <div className="space-y-4">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder={tr.dataSecurity.domainPlaceholder}
                className="flex-1 rounded-md border border-border bg-surface-0 px-3 py-1.5 text-sm outline-none focus:border-accent focus:ring-1 focus:ring-accent/50"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAddDomain()}
                disabled={busy}
              />
              <Button variant="secondary" onClick={handleAddDomain} disabled={busy || !newDomain.trim()}>
                <Plus className="size-4" /> {tr.dataSecurity.add}
              </Button>
            </div>

            <div className="max-h-[300px] overflow-y-auto rounded-md border border-border">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-surface-1 text-xs uppercase text-text-secondary border-b border-border">
                  <tr>
                    <th className="py-2 pl-4">{tr.dataSecurity.domain}</th>
                    <th className="py-2 pr-4 text-right">{tr.dataSecurity.action}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50 bg-surface-0">
                  {casbDomains.length === 0 ? (
                    <tr>
                      <td colSpan={2} className="py-4 text-center text-text-secondary italic text-xs">
                        {tr.dataSecurity.noDomains}
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
                {tr.dataSecurity.applyCasb}
              </Button>
            </div>
          </div>
        </Panel>

        <Panel title={tr.dataSecurity.dlpTitle}>
          <div className="text-xs text-text-secondary mb-4">
            {tr.dataSecurity.dlpDesc}
          </div>
          
          <div className="space-y-4">
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                type="text"
                placeholder={tr.dataSecurity.patternPlaceholder}
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
                    <th className="py-2 pl-4">{tr.dataSecurity.pattern}</th>
                    <th className="py-2 pl-4">{tr.dataSecurity.description}</th>
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
                {tr.dataSecurity.applyDlp}
              </Button>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}
