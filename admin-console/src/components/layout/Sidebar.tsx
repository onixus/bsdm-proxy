import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  Activity,
  ChevronRight,
  FlaskConical,
  Languages,
  Moon,
  Sun,
  User,
  X,
} from 'lucide-react'
import { isDemoMode } from '../../api/source'
import { APP_VERSION } from '../../lib/build'
import { useLanguage, translations } from '../../lib/i18n'
import { applyTheme, loadTheme, type Theme } from '../../lib/theme'
import { getNavigationGroups } from '../../navigation/menu'
import { UserProfileModal } from './UserProfileModal'

interface SidebarProps {
  open: boolean
  onClose: () => void
}

export function Sidebar({ open, onClose }: SidebarProps) {
  const [theme, setTheme] = useState<Theme>(loadTheme)
  const [demoOn, setDemoOn] = useState(isDemoMode)
  const [profileOpen, setProfileOpen] = useState(false)
  const [lang, setLang] = useLanguage()

  const t = translations[lang]
  const navGroups = getNavigationGroups(lang)

  useEffect(() => {
    const onDemo = (event: Event) => setDemoOn(Boolean((event as CustomEvent).detail))
    window.addEventListener('bsdm-demo-mode', onDemo)
    return () => window.removeEventListener('bsdm-demo-mode', onDemo)
  }, [])

  useEffect(() => {
    if (!open) return

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [open, onClose])

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    applyTheme(next)
  }

  const toggleLanguage = () => {
    setLang(lang === 'ru' ? 'en' : 'ru')
  }

  return (
    <>
      <button
        type="button"
        className={`fixed inset-0 z-40 bg-black/60 backdrop-blur-xs transition-opacity lg:hidden ${open ? 'opacity-100' : 'pointer-events-none opacity-0'}`}
        onClick={onClose}
        aria-label={t.profile.closeMenu}
        tabIndex={open ? 0 : -1}
      />

      <aside
        id="sidebar-navigation"
        className={`surface-panel fixed inset-y-0 left-0 z-50 flex w-[17.5rem] max-w-[85vw] flex-col border-r border-border transition-transform duration-200 lg:static lg:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}
        aria-label={t.profile.mainNav}
      >
        <div className="flex h-14 items-center justify-between border-b border-border px-4">
          <div className="flex min-w-0 items-center gap-2.5">
            <div className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-accent/30 bg-accent/15 text-accent shadow-glow-accent">
              <Activity className="size-5" />
            </div>
            <div className="min-w-0">
              <span className="block truncate text-sm font-bold tracking-tight text-text-primary">BSDM Console</span>
              <span className="block truncate font-mono text-[10px] leading-none text-text-secondary">
                v{APP_VERSION} · admin-console
              </span>
            </div>
          </div>

          <div className="flex items-center gap-1">
            <button
              type="button"
              className="interactive-surface flex items-center gap-1 rounded-md border border-border bg-surface-0 px-2 py-1 text-xs font-bold text-accent hover:border-accent/40 hover:bg-surface-2"
              onClick={toggleLanguage}
              title={t.header.switchLang}
              aria-label={t.header.switchLang}
            >
              <Languages className="size-3.5" />
              <span>{lang.toUpperCase()}</span>
            </button>

            <button
              type="button"
              className="interactive-surface flex items-center justify-center rounded-md p-1.5 text-text-secondary hover:bg-surface-2 hover:text-text-primary"
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? t.profile.lightThemeSwitch : t.profile.darkThemeSwitch}
              title={theme === 'dark' ? t.profile.lightTheme : t.profile.darkTheme}
            >
              {theme === 'dark' ? <Sun className="size-4 text-warning" /> : <Moon className="size-4 text-accent" />}
            </button>

            <button
              type="button"
              className="touch-target interactive-surface flex items-center justify-center rounded-md p-2 text-text-secondary hover:bg-surface-2 lg:hidden"
              onClick={onClose}
              aria-label={t.profile.closeMenu}
            >
              <X className="size-5" />
            </button>
          </div>
        </div>

        <nav className="scrollbar-stable flex-1 space-y-5 overflow-y-auto p-3">
          {navGroups.map((group) => (
            <section key={group.id} aria-labelledby={`nav-group-${group.id}`} className="space-y-1">
              <h2
                id={`nav-group-${group.id}`}
                className="px-3 text-[11px] font-bold uppercase tracking-wider text-text-secondary/70"
              >
                {group.title}
              </h2>

              {group.items.map(({ to, label, description, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  onClick={onClose}
                  title={description}
                  className={({ isActive }) =>
                    `interactive-surface group relative flex min-h-[var(--touch-min)] items-center gap-3 rounded-lg border px-3 py-2 text-left text-sm font-medium ${
                      isActive
                        ? 'border-accent/20 bg-accent/15 font-semibold text-accent shadow-sm'
                        : 'border-transparent text-text-secondary hover:bg-surface-2 hover:text-text-primary'
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <span className="absolute bottom-2 left-0 top-2 w-1 rounded-r-full bg-accent shadow-glow-accent" />
                      )}
                      <Icon
                        className={`size-[1.125rem] shrink-0 transition-transform group-hover:scale-105 ${
                          isActive ? 'text-accent' : 'text-text-secondary group-hover:text-text-primary'
                        }`}
                      />
                      <span className="min-w-0 leading-snug">{label}</span>
                    </>
                  )}
                </NavLink>
              ))}
            </section>
          ))}
        </nav>

        <div className="space-y-2 border-t border-border p-3">
          <button
            type="button"
            onClick={() => setProfileOpen(true)}
            className="interactive-surface group flex w-full items-center justify-between gap-3 rounded-lg border border-border/80 bg-surface-0/60 p-2.5 text-left hover:border-accent/40 hover:bg-surface-2"
          >
            <div className="flex min-w-0 items-center gap-2.5">
              <div className="flex size-8 shrink-0 items-center justify-center rounded-full border border-accent/30 bg-accent/20 text-accent shadow-glow-accent">
                <User className="size-4" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-bold text-text-primary">
                  {t.profile.localConsole}
                </p>
                <p className="truncate text-[10px] text-warning">
                  {t.profile.noSession}
                </p>
              </div>
            </div>
            <ChevronRight className="size-4 shrink-0 text-text-secondary transition-transform group-hover:translate-x-0.5 group-hover:text-accent" />
          </button>

          {demoOn && (
            <div className="flex items-center gap-2 rounded-md border border-warning/40 bg-warning/10 px-2.5 py-1.5 text-xs font-semibold text-warning">
              <FlaskConical className="size-3.5" />
              {t.header.demoMode}
            </div>
          )}
        </div>
      </aside>

      <UserProfileModal open={profileOpen} onClose={() => setProfileOpen(false)} />
    </>
  )
}
