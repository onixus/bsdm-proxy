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
  Moon,
  Radio,
  Cpu,
  Network,
  Sparkles,
  Sun,
} from 'lucide-react'
import { isDemoMode } from '../../api/source'
import { applyTheme, loadTheme, type Theme } from '../../lib/theme'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/logs', label: 'Logs', icon: ScrollText },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/threat-scores', label: 'Threat scores', icon: Brain },
  { to: '/security', label: 'Data Security', icon: Shield },
  { to: '/policies', label: 'Policies', icon: Shield },
  { to: '/rpz', label: 'RPZ Sinkhole', icon: Radio },
  { to: '/wasm', label: 'Wasm Plugins', icon: Cpu },
  { to: '/cluster', label: 'Cluster Mesh', icon: Network },
  { to: '/ai-cache', label: 'AI Cache', icon: Sparkles },
  { to: '/settings', label: 'Settings', icon: Settings },
] as const

interface SidebarProps {
  open: boolean
  onClose: () => void
}

export function Sidebar({ open, onClose }: SidebarProps) {
  const [theme, setTheme] = useState<Theme>(loadTheme)
  const [demoOn, setDemoOn] = useState(isDemoMode)

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

  return (
    <>
      {/* Mobile overlay */}
      <div
        className={`fixed inset-0 z-40 bg-black/60 transition-opacity lg:hidden ${open ? 'opacity-100' : 'pointer-events-none opacity-0'}`}
        onClick={onClose}
        aria-hidden={!open}
      />

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-border bg-surface-1 transition-transform duration-200 lg:static lg:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}
        aria-label="Main navigation"
      >
        <div className="flex h-14 items-center justify-between border-b border-border px-4">
          <div className="flex items-center gap-2">
            <Activity className="size-6 text-accent" />
            <span className="font-bold text-text-primary">BSDM Console</span>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              className="flex items-center justify-center rounded-md p-2 text-text-secondary hover:bg-surface-2 hover:text-text-primary"
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              title={theme === 'dark' ? 'Light theme' : 'Dark theme'}
            >
              {theme === 'dark' ? <Sun className="size-4" /> : <Moon className="size-4" />}
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

        <nav className="flex-1 space-y-1 overflow-y-auto p-3">
          {navItems.map(({ to, label, icon: Icon, ...rest }) => (
            <NavLink
              key={to}
              to={to}
              end={'end' in rest ? rest.end : false}
              onClick={onClose}
              className={({ isActive }) =>
                `flex min-h-[var(--touch-min)] items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-accent/15 text-accent'
                    : 'text-text-secondary hover:bg-surface-2 hover:text-text-primary'
                }`
              }
            >
              <Icon className="size-5 shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="space-y-2 border-t border-border p-4">
          {demoOn && (
            <div className="flex items-center gap-2 rounded-md border border-warning/40 bg-warning/10 px-2.5 py-1.5 text-xs font-semibold text-warning">
              <FlaskConical className="size-3.5" />
              Demo mode — sample data may render
            </div>
          )}
          <p className="text-xs text-text-secondary">Single pane of glass · v0.6</p>
        </div>
      </aside>
    </>
  )
}
