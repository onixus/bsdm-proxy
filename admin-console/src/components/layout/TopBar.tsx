import { useNavigate } from 'react-router-dom'
import { ChevronRight, Command, Menu, Search, Settings } from 'lucide-react'
import { useLanguage } from '../../lib/i18n'
import { localizedRouteScope } from '../../lib/routeCopy'
import { StatusPill } from '../ui/StatusPill'

interface TopBarProps {
  onMenuOpen: () => void
  onCommandOpen: () => void
  credentialsAttached: boolean
  pathname: string
}

export function TopBar({ onMenuOpen, onCommandOpen, credentialsAttached, pathname }: TopBarProps) {
  const navigate = useNavigate()
  const [lang] = useLanguage()
  const { route, title, category, t } = localizedRouteScope(pathname, lang)

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-border bg-surface-1/80 px-4 backdrop-blur-xl sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <button
          type="button"
          className="touch-target flex shrink-0 items-center justify-center rounded-lg p-2 text-text-primary hover:bg-surface-2 lg:hidden"
          onClick={onMenuOpen}
          aria-label={t.topbar.openMenu}
        >
          <Menu className="size-6" />
        </button>

        <nav className="flex min-w-0 items-center gap-2" aria-label="Breadcrumb">
          <span className="hidden shrink-0 rounded-md border border-border bg-surface-2 px-2 py-0.5 text-xs font-bold uppercase text-text-secondary sm:inline">
            {category}
          </span>
          <ChevronRight className="hidden size-3.5 shrink-0 text-text-secondary sm:inline" />
          <span className="truncate text-sm font-bold text-text-primary sm:text-base" title={title}>
            {title}
          </span>
          {route.maturity === 'frozen' && (
            <StatusPill tone="danger" className="hidden shrink-0 md:inline-flex">
              {t.routes.categories.experimental}
            </StatusPill>
          )}
        </nav>
      </div>

      <div className="flex shrink-0 items-center gap-2 sm:gap-3">
        <StatusPill
          tone={credentialsAttached ? 'success' : 'warning'}
          className="max-w-[9rem] truncate sm:max-w-none"
        >
          <span className="hidden sm:inline">
            {credentialsAttached ? t.topbar.tokenAttached : t.topbar.readOnly}
          </span>
          <span className="sm:hidden">{credentialsAttached ? 'API' : 'RO'}</span>
        </StatusPill>

        <button
          type="button"
          onClick={() => navigate('/settings?tab=api')}
          className="touch-target hidden items-center gap-2 rounded-lg border border-border bg-surface-0 px-3 text-xs text-text-secondary transition-colors hover:border-accent/50 hover:text-text-primary md:inline-flex"
        >
          <Settings className="size-3.5 text-accent" />
          {t.topbar.settings}
        </button>

        <button
          type="button"
          onClick={onCommandOpen}
          aria-label={t.topbar.openPalette}
          title={t.topbar.openPalette}
          className="touch-target inline-flex items-center gap-2 rounded-lg border border-border bg-surface-0 px-3 text-xs text-text-secondary transition-colors hover:border-accent/50 hover:text-text-primary"
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
