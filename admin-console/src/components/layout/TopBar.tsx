import { useNavigate } from 'react-router-dom'
import { Command, Search, Menu, ChevronRight } from 'lucide-react'
import { resolveRouteScope } from '../../lib/routeScope'
import { StatusPill } from '../ui/StatusPill'

interface TopBarProps {
  onMenuOpen: () => void
  onCommandOpen: () => void
  credentialsAttached: boolean
  pathname: string
}

export function TopBar({ onMenuOpen, onCommandOpen, credentialsAttached, pathname }: TopBarProps) {
  const navigate = useNavigate()
  const route = resolveRouteScope(pathname)

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-surface-1/80 px-4 backdrop-blur-xl sm:px-6">
      <div className="flex items-center gap-3">
        <button
          type="button"
          className="touch-target flex items-center justify-center rounded-lg p-2 text-text-primary hover:bg-surface-2 lg:hidden"
          onClick={onMenuOpen}
          aria-label="Open menu"
        >
          <Menu className="size-6" />
        </button>

        <div className="flex items-center gap-2">
          <span className="hidden rounded-md border border-border bg-surface-2 px-2 py-0.5 text-xs font-bold uppercase text-text-secondary sm:inline">
            {route.category}
          </span>
          <ChevronRight className="hidden size-3.5 text-text-secondary sm:inline" />
          <span className="text-sm font-bold text-text-primary sm:text-base">{route.title}</span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <StatusPill tone={credentialsAttached ? 'success' : 'warning'}>
          {credentialsAttached ? 'API token attached' : 'Read-only'}
        </StatusPill>

        <button
          type="button"
          onClick={() => navigate('/settings?tab=api')}
          className="hidden rounded-lg border border-border bg-surface-0 px-3 py-1.5 text-xs text-text-secondary transition-colors hover:border-accent/50 hover:text-text-primary md:inline-flex"
        >
          <Search className="mr-2 size-3.5 text-accent" />
          Settings
        </button>

        <button
          type="button"
          onClick={onCommandOpen}
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-surface-0 px-3 py-1.5 text-xs text-text-secondary hover:border-accent/50"
        >
          <Search className="size-3.5 text-accent" />
          <kbd className="hidden rounded border border-border bg-surface-2 px-1 font-mono sm:inline">
            <Command className="inline size-3" />K
          </kbd>
        </button>
      </div>
    </header>
  )
}
