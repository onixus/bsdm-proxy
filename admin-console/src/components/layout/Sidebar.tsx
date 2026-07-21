import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  ScrollText,
  Shield,
  Settings,
  X,
  Activity,
  Brain,
  Radio,
  Cpu,
} from 'lucide-react'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/logs', label: 'Logs', icon: ScrollText },
  { to: '/threat-scores', label: 'Threat scores', icon: Brain },
  { to: '/policies', label: 'Policies', icon: Shield },
  { to: '/rpz', label: 'RPZ Sinkhole', icon: Radio },
  { to: '/wasm', label: 'Wasm Plugins', icon: Cpu },
  { to: '/settings', label: 'Settings', icon: Settings },
] as const

interface SidebarProps {
  open: boolean
  onClose: () => void
}

export function Sidebar({ open, onClose }: SidebarProps) {
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
          <button
            type="button"
            className="touch-target flex items-center justify-center rounded-md p-2 text-text-secondary hover:bg-surface-2 lg:hidden"
            onClick={onClose}
            aria-label="Close menu"
          >
            <X className="size-5" />
          </button>
        </div>

        <nav className="flex-1 space-y-1 p-3">
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

        <div className="border-t border-border p-4 text-xs text-text-secondary">
          Single pane of glass · v0.5
        </div>
      </aside>
    </>
  )
}
