import { useState } from 'react'
import { KeyRound, MonitorCog, Moon, Settings, ShieldAlert, Sun } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { loadApiSettings } from '../../api/settings'
import { APP_VERSION } from '../../lib/build'
import { useT } from '../../lib/i18n'
import { applyTheme, loadTheme, type Theme } from '../../lib/theme'
import { Button } from '../ui/Button'
import { Modal } from '../ui/Modal'

interface UserProfileModalProps {
  open: boolean
  onClose: () => void
}

export function UserProfileModal({ open, onClose }: UserProfileModalProps) {
  const [theme, setTheme] = useState<Theme>(loadTheme)
  const t = useT()
  const navigate = useNavigate()
  const settings = loadApiSettings()
  const hasApiCredentials = Boolean(
    settings.controlPlaneToken || settings.searchToken || settings.aclToken || settings.controlToken,
  )
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
      title={t.profile.title}
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
                  {t.profile.localConsole}
                </h3>
                <span className="rounded-full border border-warning/40 bg-warning/15 px-2 py-0.5 text-xs font-semibold text-warning">
                  {t.profile.unauthenticated}
                </span>
              </div>
              <p className="mt-1 text-xs text-text-secondary">
                {t.profile.noIdentity}
              </p>
            </div>
          </div>
          <Button type="button" variant="secondary" className="shrink-0 text-xs" onClick={toggleTheme}>
            {theme === 'dark' ? (
              <>
                <Sun className="size-4 text-warning" /> {t.profile.lightTheme}
              </>
            ) : (
              <>
                <Moon className="size-4 text-accent" /> {t.profile.darkTheme}
              </>
            )}
          </Button>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <StatusCard
            icon={MonitorCog}
            label={t.profile.accessMode}
            value={t.profile.browserSession}
          />
          <StatusCard
            icon={KeyRound}
            label={t.profile.apiCredentials}
            value={
              hasApiCredentials
                ? t.profile.credentialsSet
                : t.profile.credentialsUnset
            }
            warning={!hasApiCredentials}
          />
          <StatusCard
            icon={Settings}
            label={t.profile.productVersion}
            value={`v${APP_VERSION}`}
          />
        </div>

        <div className="rounded-lg border border-border bg-surface-1 p-4 text-sm text-text-secondary">
          {t.profile.tokenNotice}
        </div>

        <div className="flex items-center justify-between border-t border-border pt-4">
          <span className="text-xs text-text-secondary">BSDM Admin Console v{APP_VERSION}</span>
          <Button variant="primary" onClick={openSettings} className="text-xs">
            <Settings className="size-4" />
            {t.profile.openApiSettings}
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
