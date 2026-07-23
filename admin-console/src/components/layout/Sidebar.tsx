import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  ScrollText,
  Shield,
  Settings,
  X,
  Activity,
  BarChart3,
  Brain,
  FlaskConical,
  Radio,
  Cpu,
  Network,
  Sparkles,
  Sun,
  Moon,
  User,
  ChevronRight,
  Languages,
  ShieldAlert,
} from 'lucide-react'
import { isDemoMode } from '../../api/source'
import { applyTheme, loadTheme, type Theme } from '../../lib/theme'
import { useLanguage, translations } from '../../lib/i18n'
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

  const navGroups = [
    {
      title: lang === 'ru' ? 'Мониторинг' : 'Monitoring',
      items: [
        { to: '/', label: t.nav.dashboard, icon: LayoutDashboard, end: true },
        { to: '/logs', label: t.nav.logs, icon: ScrollText },
        { to: '/analytics', label: t.nav.analytics, icon: BarChart3 },
        { to: '/threat-scores', label: t.nav.threatScores, icon: Brain },
      ],
    },
    {
      title: lang === 'ru' ? 'Безопасность' : 'Security & ACL',
      items: [
        { to: '/security', label: t.nav.security, icon: ShieldAlert },
        { to: '/policies', label: t.nav.policies, icon: Shield },
        { to: '/rpz', label: t.nav.rpz, icon: Radio },
      ],
    },
    {
      title: lang === 'ru' ? 'Расширения & Кластер' : 'Extensions & Mesh',
      items: [
        { to: '/wasm', label: t.nav.wasm, icon: Cpu },
        { to: '/cluster', label: t.nav.cluster, icon: Network },
        { to: '/ai-cache', label: t.nav.aiCache, icon: Sparkles },
      ],
    },
    {
      title: lang === 'ru' ? 'Система' : 'System',
      items: [
        { to: '/users', label: t.nav.users, icon: User },
        { to: '/settings', label: t.nav.settings, icon: Settings },
      ],
    },
  ] as const

  useEffect(() => {
    const onDemo = (e: Event) => setDemoOn(Boolean((e as CustomEvent).detail))
    window.addEventListener('bsdm-demo-mode', onDemo)
    return () => window.removeEventListener('bsdm-demo-mode', onDemo)
  }, [])

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
      {/* Mobile overlay */}
      <div
        className={`fixed inset-0 z-40 bg-black/60 backdrop-blur-xs transition-opacity lg:hidden ${open ? 'opacity-100' : 'pointer-events-none opacity-0'}`}
        onClick={onClose}
        aria-hidden={!open}
      />

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-border bg-surface-1/95 backdrop-blur-md transition-transform duration-200 lg:static lg:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}
        aria-label="Main navigation"
      >
        <div className="flex h-14 items-center justify-between border-b border-border px-4">
          <div className="flex items-center gap-2.5">
            <div className="relative flex items-center justify-center size-8 rounded-lg bg-accent/15 border border-accent/30 text-accent shadow-glow-accent">
              <Activity className="size-5" />
              <span className="absolute -top-0.5 -right-0.5 flex size-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75"></span>
                <span className="relative inline-flex size-2 rounded-full bg-success"></span>
              </span>
            </div>
            <div>
              <span className="font-bold text-text-primary text-sm tracking-tight block">BSDM Console</span>
              <span className="text-[10px] text-text-secondary font-mono leading-none">v0.6 · proxy-node</span>
            </div>
          </div>
          <div className="flex items-center gap-1">
            {/* Language Switcher */}
            <button
              type="button"
              className="flex items-center gap-1 rounded-md px-2 py-1 text-xs font-bold border border-border bg-surface-0 text-accent hover:bg-surface-2 hover:border-accent/40 transition-all cursor-pointer"
              onClick={toggleLanguage}
              title={t.header.switchLang}
            >
              <Languages className="size-3.5" />
              <span>{lang.toUpperCase()}</span>
            </button>

            {/* Theme Toggle */}
            <button
              type="button"
              className="flex items-center justify-center rounded-md p-1.5 text-text-secondary hover:bg-surface-2 hover:text-text-primary transition-colors cursor-pointer"
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              title={theme === 'dark' ? 'Light theme' : 'Dark theme'}
            >
              {theme === 'dark' ? <Sun className="size-4 text-warning" /> : <Moon className="size-4 text-accent" />}
            </button>
            <button
              type="button"
              className="touch-target flex items-center justify-center rounded-md p-2 text-text-secondary hover:bg-surface-2 lg:hidden"
              onClick={onClose}
              aria-label="Close menu"
            >
              <X className="size-5" />
            </button>
          </div>
        </div>

        <nav className="flex-1 space-y-4 overflow-y-auto p-3">
          {navGroups.map((group) => (
            <div key={group.title} className="space-y-1">
              <h3 className="px-3 text-[11px] font-bold uppercase tracking-wider text-text-secondary/70">
                {group.title}
              </h3>
              {group.items.map(({ to, label, icon: Icon, ...rest }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={'end' in rest ? rest.end : false}
                  onClick={onClose}
                  className={({ isActive }) =>
                    `group relative flex min-h-[var(--touch-min)] items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-accent/15 text-accent shadow-sm font-semibold border border-accent/20'
                        : 'text-text-secondary hover:bg-surface-2 hover:text-text-primary border border-transparent'
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <span className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-accent shadow-[0_0_10px_rgba(233,69,96,0.8)]" />
                      )}
                      <Icon className={`size-4.5 shrink-0 transition-transform group-hover:scale-110 ${isActive ? 'text-accent' : 'text-text-secondary group-hover:text-text-primary'}`} />
                      <span className="truncate">{label}</span>
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* User Profile & Node Info Widget */}
        <div className="border-t border-border p-3 space-y-2">
          <button
            type="button"
            onClick={() => setProfileOpen(true)}
            className="w-full flex items-center justify-between gap-3 rounded-lg border border-border/80 bg-surface-0/60 p-2.5 hover:bg-surface-2 hover:border-accent/40 transition-all text-left group cursor-pointer"
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="flex size-8 items-center justify-center rounded-full bg-accent/20 text-accent font-bold text-xs shrink-0 border border-accent/30 shadow-glow-accent">
                <User className="size-4" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-bold text-text-primary truncate">admin.user</p>
                <p className="text-[10px] text-text-secondary truncate">{t.header.activeDirectory}</p>
              </div>
            </div>
            <ChevronRight className="size-4 text-text-secondary group-hover:text-accent shrink-0 transition-transform group-hover:translate-x-0.5" />
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

