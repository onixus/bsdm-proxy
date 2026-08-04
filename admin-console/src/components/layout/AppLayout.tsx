import { useState, useEffect, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Menu, Search, Command, ShieldAlert, ChevronRight, KeyRound, ShieldCheck, FlaskConical } from 'lucide-react'
import { Sidebar } from './Sidebar'
import { CommandPalette } from '../ui/CommandPalette'
import { API_CREDENTIALS_CHANGED_EVENT, hasApiCredentials } from '../../api/settings'
import { resolveRouteScope } from '../../lib/routeScope'

interface AppLayoutProps {
  children: ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [cmdOpen, setCmdOpen] = useState(false)
  const [credentialsAttached, setCredentialsAttached] = useState(hasApiCredentials)
  const location = useLocation()

  useEffect(() => {
    const handleToggle = () => setCmdOpen((prev) => !prev)
    window.addEventListener('toggle-command-palette', handleToggle)
    return () => window.removeEventListener('toggle-command-palette', handleToggle)
  }, [])

  useEffect(() => {
    const refreshCredentials = () => setCredentialsAttached(hasApiCredentials())
    window.addEventListener(API_CREDENTIALS_CHANGED_EVENT, refreshCredentials)
    return () => window.removeEventListener(API_CREDENTIALS_CHANGED_EVENT, refreshCredentials)
  }, [])

  const currentRoute = resolveRouteScope(location.pathname)
  const isFrozen = currentRoute.maturity === 'frozen'

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
            {isFrozen && (
              <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-danger/35 bg-danger/10 text-danger text-xs font-semibold">
                <FlaskConical className="size-3.5" />
                <span>Frozen</span>
              </div>
            )}
            {credentialsAttached ? (
              <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-success/30 bg-success/10 text-success text-xs font-semibold">
                <ShieldCheck className="size-3.5" />
                <span>API token attached</span>
              </div>
            ) : (
              <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-warning/30 bg-warning/10 text-warning text-xs font-semibold">
                <ShieldAlert className="size-3.5" />
                <span>Read-only (no token)</span>
              </div>
            )}

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

        {!credentialsAttached && (
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-warning/30 bg-warning/10 px-4 py-2.5 text-sm text-warning sm:px-6">
            <div className="flex items-center gap-2">
              <KeyRound className="size-4 shrink-0" />
              <span>
                <strong>Read-only safety mode.</strong> Mutating API requests are blocked until a token is attached.
              </span>
            </div>
            <Link
              to="/settings?tab=api"
              className="rounded-md border border-warning/40 bg-warning/10 px-3 py-1.5 text-xs font-bold text-warning transition-colors hover:bg-warning/20"
            >
              Attach API token
            </Link>
          </div>
        )}

        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">{children}</main>
      </div>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  )
}
