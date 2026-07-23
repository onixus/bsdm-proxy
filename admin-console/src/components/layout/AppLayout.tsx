import { useState, useEffect, type ReactNode } from 'react'
import { useLocation } from 'react-router-dom'
import { Menu, Search, Command, ShieldCheck, ChevronRight } from 'lucide-react'
import { Sidebar } from './Sidebar'
import { CommandPalette } from '../ui/CommandPalette'

interface AppLayoutProps {
  children: ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [cmdOpen, setCmdOpen] = useState(false)
  const location = useLocation()

  useEffect(() => {
    const handleToggle = () => setCmdOpen((prev) => !prev)
    window.addEventListener('toggle-command-palette', handleToggle)
    return () => window.removeEventListener('toggle-command-palette', handleToggle)
  }, [])

  const routeConfig: Record<string, { title: string; category: string }> = {
    '/': { title: 'Dashboard', category: 'Monitoring' },
    '/logs': { title: 'Proxy Logs', category: 'Monitoring' },
    '/analytics': { title: 'Analytics', category: 'Monitoring' },
    '/threat-scores': { title: 'Threat Scores', category: 'Monitoring' },
    '/security': { title: 'Data Security (DLP)', category: 'Security' },
    '/policies': { title: 'ACL Policies', category: 'Security' },
    '/rpz': { title: 'RPZ DNS', category: 'Security' },
    '/wasm': { title: 'Wasm Plugins', category: 'Extensions' },
    '/cluster': { title: 'Cluster Mesh', category: 'Extensions' },
    '/ai-cache': { title: 'AI Semantic Cache', category: 'Extensions' },
    '/users': { title: 'Active Directory Users', category: 'System' },
    '/settings': { title: 'Console Settings', category: 'System' },
  }

  const currentRoute = routeConfig[location.pathname] || { title: 'BSDM Console', category: 'System' }

  return (
    <div className="flex min-h-screen bg-surface-0 font-sans">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Header bar (Desktop & Mobile) */}
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-surface-1/80 px-4 sm:px-6 backdrop-blur-xl transition-all">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="touch-target flex items-center justify-center rounded-lg p-2 text-text-primary hover:bg-surface-2 lg:hidden cursor-pointer"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open menu"
            >
              <Menu className="size-6" />
            </button>

            <div className="flex items-center gap-2">
              <span className="hidden sm:inline font-bold text-xs uppercase tracking-wider px-2 py-0.5 rounded-md bg-surface-2 text-text-secondary border border-border">
                {currentRoute.category}
              </span>
              <ChevronRight className="size-3.5 text-text-secondary hidden sm:inline" />
              <span className="font-bold text-text-primary text-sm sm:text-base tracking-tight">{currentRoute.title}</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-success/30 bg-success/10 text-success text-xs font-semibold">
              <ShieldCheck className="size-3.5" />
              <span>Node Protected</span>
            </div>

            <button
              type="button"
              onClick={() => setCmdOpen(true)}
              className="flex items-center gap-2.5 rounded-lg border border-border/80 bg-surface-0/70 px-3 py-1.5 text-xs text-text-secondary hover:bg-surface-2 hover:text-text-primary hover:border-accent/50 transition-all cursor-pointer shadow-sm hover:shadow-glow-accent"
            >
              <Search className="size-3.5 text-accent" />
              <span className="hidden md:inline font-medium">Quick Navigation...</span>
              <kbd className="inline-flex items-center gap-0.5 rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] font-bold text-text-primary">
                <Command className="size-2.5" />K
              </kbd>
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">{children}</main>
      </div>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  )
}


