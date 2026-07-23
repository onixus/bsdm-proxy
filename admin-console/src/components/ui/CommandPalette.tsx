import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  LayoutDashboard,
  ScrollText,
  Shield,
  Settings,
  Brain,
  BarChart3,
  Radio,
  Cpu,
  Network,
  Sparkles,
  User,
  Command,
  ArrowRight,
} from 'lucide-react'
import { useLanguage, translations } from '../../lib/i18n'

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const navigate = useNavigate()
  const [lang] = useLanguage()
  const t = translations[lang]

  const items = [
    { to: '/', title: t.nav.dashboard, desc: 'Overview, RED metrics, system status', icon: LayoutDashboard },
    { to: '/logs', title: t.nav.logs, desc: 'Real-time proxy traffic logs & XAI analysis', icon: ScrollText },
    { to: '/analytics', title: t.nav.analytics, desc: 'Aggregations, status mix, top upstreams', icon: BarChart3 },
    { to: '/threat-scores', title: t.nav.threatScores, desc: 'ML write-back score distribution', icon: Brain },
    { to: '/security', title: t.nav.security, desc: 'Security policies & DLP rules', icon: Shield },
    { to: '/policies', title: t.nav.policies, desc: 'ACL configuration rules & IP blocks', icon: Shield },
    { to: '/rpz', title: t.nav.rpz, desc: 'Response Policy Zone DNS filtering', icon: Radio },
    { to: '/wasm', title: t.nav.wasm, desc: 'Wasm plugin manager & dynamic extensions', icon: Cpu },
    { to: '/cluster', title: t.nav.cluster, desc: 'Cluster Mesh topology & peer synchronization', icon: Network },
    { to: '/ai-cache', title: t.nav.aiCache, desc: 'AI Semantic caching & LLM token stats', icon: Sparkles },
    { to: '/users', title: t.nav.users, desc: 'Active Directory users & proxy permissions', icon: User },
    { to: '/settings', title: t.nav.settings, desc: 'Live node configuration & export options', icon: Settings },
  ]

  useEffect(() => {
    if (!open) setQuery('')
  }, [open])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        if (open) onClose()
        else {
          window.dispatchEvent(new CustomEvent('toggle-command-palette'))
        }
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [open, onClose])

  if (!open) return null

  const filtered = items.filter(
    (item) =>
      item.title.toLowerCase().includes(query.toLowerCase()) ||
      item.desc.toLowerCase().includes(query.toLowerCase()) ||
      item.to.toLowerCase().includes(query.toLowerCase())
  )

  const handleSelect = (to: string) => {
    navigate(to)
    onClose()
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 backdrop-blur-sm p-4 pt-16 sm:pt-24"
      onClick={onClose}
    >
      <div
        className="animate-modal-pop flex w-full max-w-xl flex-col overflow-hidden rounded-xl border border-border bg-surface-1 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-border px-4 py-3 bg-surface-0/50">
          <Search className="size-5 text-text-secondary shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command or search page... (e.g. logs, settings, security)"
            className="w-full bg-transparent text-sm text-text-primary placeholder:text-text-secondary outline-none"
          />
          <kbd className="hidden sm:inline-flex items-center gap-0.5 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] font-mono text-text-secondary">
            ESC
          </kbd>
        </div>

        <div className="max-h-96 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-sm text-text-secondary">No matching sections found</div>
          ) : (
            filtered.map((item) => {
              const Icon = item.icon
              return (
                <button
                  key={item.to}
                  type="button"
                  onClick={() => handleSelect(item.to)}
                  className="w-full flex items-center justify-between gap-3 rounded-lg p-2.5 text-left hover:bg-surface-2 hover:border-accent/20 transition-colors group cursor-pointer"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex size-8 items-center justify-center rounded-lg bg-surface-2 text-text-secondary group-hover:bg-accent/15 group-hover:text-accent transition-colors shrink-0">
                      <Icon className="size-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-text-primary group-hover:text-accent transition-colors">
                        {item.title}
                      </p>
                      <p className="text-xs text-text-secondary truncate">{item.desc}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 text-xs text-text-secondary group-hover:text-accent shrink-0">
                    <span className="font-mono text-[10px] opacity-70">{item.to}</span>
                    <ArrowRight className="size-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                </button>
              )
            })
          )}
        </div>

        <div className="flex items-center justify-between border-t border-border px-4 py-2 text-[11px] text-text-secondary bg-surface-0/30">
          <div className="flex items-center gap-1.5">
            <Command className="size-3" />
            <span>Navigation Shortcut</span>
          </div>
          <span>Press Enter to select</span>
        </div>
      </div>
    </div>
  )
}
