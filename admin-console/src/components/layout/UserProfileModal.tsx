import { useState } from 'react'
import {
  User,
  ShieldCheck,
  Key,
  Globe,
  Clock,
  LogOut,
  Moon,
  Sun,
  CheckCircle2,
  Lock,
  ShieldAlert,
} from 'lucide-react'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'
import { loadTheme, applyTheme, type Theme } from '../../lib/theme'

interface UserProfileModalProps {
  open: boolean
  onClose: () => void
}

export function UserProfileModal({ open, onClose }: UserProfileModalProps) {
  const [theme, setTheme] = useState<Theme>(loadTheme)

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    applyTheme(next)
  }

  // Simulated active user identity info extracted from current session/headers
  const user = {
    username: 'admin.user',
    displayName: 'Администратор Безопасности (AD User)',
    email: 'admin.security@company.local',
    domain: 'CORP.LOCAL',
    authMethod: 'Active Directory / NTLM & OIDC',
    role: 'System Administrator (Full Access)',
    ipAddress: '127.0.0.1',
    sessionCreated: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    permissions: [
      'ZTNA / IAP Reverse Proxy Control',
      'Active Directory / LDAP Sync',
      'ACL & Content Filtering Engine',
      'ML Threat & UEBA Score Management',
      'Kernel eBPF & Wasm Hooks',
      'Kafka / ClickHouse Analytics Access',
    ],
  }

  const handleLogout = () => {
    document.cookie = 'bsdm_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'
    window.location.reload()
  }

  return (
    <Modal open={open} onClose={onClose} title="Профиль пользователя & Сессия" wide>
      <div className="space-y-6">
        {/* User Card Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 rounded-xl border border-accent/30 bg-accent/10 p-4">
          <div className="flex items-center gap-4">
            <div className="flex size-14 items-center justify-center rounded-full bg-accent/20 text-accent font-bold text-xl border border-accent/40 shadow-inner">
              <User className="size-7" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-text-primary">{user.displayName}</h3>
                <span className="rounded-full bg-accent/20 px-2 py-0.5 text-xs font-semibold text-accent border border-accent/30">
                  AD / SSO Active
                </span>
              </div>
              <p className="text-xs text-text-secondary">
                {user.email} · <span className="font-mono">{user.domain}</span>
              </p>
            </div>
          </div>
          <Button
            type="button"
            variant="secondary"
            className="text-xs shrink-0"
            onClick={toggleTheme}
          >
            {theme === 'dark' ? (
              <>
                <Sun className="size-4 text-warning" /> Светлая тема
              </>
            ) : (
              <>
                <Moon className="size-4 text-accent" /> Тёмная тема
              </>
            )}
          </Button>
        </div>

        {/* Grid Session Info */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="rounded-lg border border-border bg-surface-1 p-3.5 space-y-1">
            <div className="flex items-center gap-2 text-xs font-semibold text-text-secondary">
              <Key className="size-3.5 text-accent" /> Метод аутентификации
            </div>
            <p className="text-sm font-medium text-text-primary">{user.authMethod}</p>
          </div>
          <div className="rounded-lg border border-border bg-surface-1 p-3.5 space-y-1">
            <div className="flex items-center gap-2 text-xs font-semibold text-text-secondary">
              <ShieldCheck className="size-3.5 text-accent" /> Роль в системе
            </div>
            <p className="text-sm font-medium text-text-primary">{user.role}</p>
          </div>
          <div className="rounded-lg border border-border bg-surface-1 p-3.5 space-y-1">
            <div className="flex items-center gap-2 text-xs font-semibold text-text-secondary">
              <Globe className="size-3.5 text-accent" /> IP-адрес клиента
            </div>
            <p className="font-mono text-sm font-medium text-text-primary">{user.ipAddress}</p>
          </div>
          <div className="rounded-lg border border-border bg-surface-1 p-3.5 space-y-1">
            <div className="flex items-center gap-2 text-xs font-semibold text-text-secondary">
              <Clock className="size-3.5 text-accent" /> Время старта сессии
            </div>
            <p className="text-sm font-medium text-text-primary">{user.sessionCreated} (Активна)</p>
          </div>
        </div>

        {/* Granted Permissions List */}
        <div className="space-y-3 rounded-xl border border-border bg-surface-1 p-4">
          <h4 className="flex items-center gap-2 text-sm font-bold text-text-primary">
            <Lock className="size-4 text-accent" /> Назначенные привилегии и разрешения
          </h4>
          <div className="grid gap-2 sm:grid-cols-2 text-xs">
            {user.permissions.map((perm, idx) => (
              <div key={idx} className="flex items-center gap-2 rounded-md bg-surface-0 px-3 py-2 border border-border/50 text-text-primary">
                <CheckCircle2 className="size-4 shrink-0 text-accent" />
                <span>{perm}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-border pt-4">
          <span className="text-xs text-text-secondary flex items-center gap-1">
            <ShieldAlert className="size-3.5 text-accent" /> BSDM ZTNA Security Subsystem v0.6
          </span>
          <Button variant="danger" onClick={handleLogout} className="text-xs">
            <LogOut className="size-4" /> Завершить сессию (Logout)
          </Button>
        </div>
      </div>
    </Modal>
  )
}
