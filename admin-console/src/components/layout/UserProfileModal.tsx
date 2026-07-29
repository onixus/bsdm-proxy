import { useState } from 'react'
import { KeyRound, MonitorCog, Moon, Settings, ShieldAlert, Sun } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { loadApiSettings } from '../../api/settings'
import { APP_VERSION } from '../../lib/build'
import { useLanguage } from '../../lib/i18n'
import { applyTheme, loadTheme, type Theme } from '../../lib/theme'
import { Button } from '../ui/Button'
import { Modal } from '../ui/Modal'

interface UserProfileModalProps {
  open: boolean
  onClose: () => void
}

export function UserProfileModal({ open, onClose }: UserProfileModalProps) {
  const [theme, setTheme] = useState<Theme>(loadTheme)
  const [lang] = useLanguage()
  const navigate = useNavigate()
  const settings = loadApiSettings()
  const hasApiCredentials = Boolean(settings.searchToken || settings.aclToken || settings.controlToken)
  const ru = lang === 'ru'

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    applyTheme(next)
  }

  const openSettings = () => {
    onClose()
    navigate('/settings')
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={ru ? 'Доступ к консоли' : 'Console access'}
      wide
    >
      <div className="space-y-5">
        <div className="flex flex-col items-start justify-between gap-4 rounded-xl border border-warning/40 bg-warning/10 p-4 sm:flex-row sm:items-center">
          <div className="flex items-center gap-4">
            <div className="flex size-12 shrink-0 items-center justify-center rounded-full border border-warning/40 bg-warning/15 text-warning">
              <ShieldAlert className="size-6" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-lg font-bold text-text-primary">
                  {ru ? 'Локальная консоль' : 'Local console'}
                </h3>
                <span className="rounded-full border border-warning/40 bg-warning/15 px-2 py-0.5 text-xs font-semibold text-warning">
                  {ru ? 'Без аутентификации' : 'Unauthenticated'}
                </span>
              </div>
              <p className="mt-1 text-xs text-text-secondary">
                {ru
                  ? 'Backend не предоставляет этой UI подтверждённую личность пользователя или роль.'
                  : 'The backend does not provide this UI with a verified user identity or role.'}
              </p>
            </div>
          </div>
          <Button type="button" variant="secondary" className="shrink-0 text-xs" onClick={toggleTheme}>
            {theme === 'dark' ? (
              <>
                <Sun className="size-4 text-warning" /> {ru ? 'Светлая тема' : 'Light theme'}
              </>
            ) : (
              <>
                <Moon className="size-4 text-accent" /> {ru ? 'Тёмная тема' : 'Dark theme'}
              </>
            )}
          </Button>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <StatusCard
            icon={MonitorCog}
            label={ru ? 'Режим доступа' : 'Access mode'}
            value={ru ? 'Локальная browser-сессия' : 'Local browser session'}
          />
          <StatusCard
            icon={KeyRound}
            label={ru ? 'API credentials' : 'API credentials'}
            value={
              hasApiCredentials
                ? (ru ? 'Заданы для этой вкладки' : 'Configured for this tab')
                : (ru ? 'Не заданы' : 'Not configured')
            }
            warning={!hasApiCredentials}
          />
          <StatusCard
            icon={Settings}
            label={ru ? 'Версия продукта' : 'Product version'}
            value={`v${APP_VERSION}`}
          />
        </div>

        <div className="rounded-lg border border-border bg-surface-1 p-4 text-sm text-text-secondary">
          {ru
            ? 'API-токены авторизуют отдельные запросы к сервисам, но не создают пользовательскую сессию в Admin Console. Не публикуйте консоль в недоверенную сеть без внешнего access gateway.'
            : 'API tokens authorize individual service requests; they do not create an Admin Console user session. Do not expose the console to an untrusted network without an external access gateway.'}
        </div>

        <div className="flex items-center justify-between border-t border-border pt-4">
          <span className="text-xs text-text-secondary">BSDM Admin Console v{APP_VERSION}</span>
          <Button variant="primary" onClick={openSettings} className="text-xs">
            <Settings className="size-4" />
            {ru ? 'Открыть настройки API' : 'Open API settings'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

function StatusCard({
  icon: Icon,
  label,
  value,
  warning = false,
}: {
  icon: typeof MonitorCog
  label: string
  value: string
  warning?: boolean
}) {
  return (
    <div className="space-y-1 rounded-lg border border-border bg-surface-1 p-3.5">
      <div className="flex items-center gap-2 text-xs font-semibold text-text-secondary">
        <Icon className={`size-3.5 ${warning ? 'text-warning' : 'text-accent'}`} />
        {label}
      </div>
      <p className={`text-sm font-medium ${warning ? 'text-warning' : 'text-text-primary'}`}>{value}</p>
    </div>
  )
}
