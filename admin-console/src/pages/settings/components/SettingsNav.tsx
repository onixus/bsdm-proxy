import { SETTINGS_TAB_GROUPS, SETTINGS_TABS, type SettingsTabId } from '../types'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function SettingsNav({ tab, onChange, tr }: { tab: SettingsTabId; onChange: (id: SettingsTabId) => void; tr: any }) {
  return (
    <div className="space-y-3">
      {SETTINGS_TAB_GROUPS.map((group) => {
        const items = SETTINGS_TABS.filter((t) => t.group === group.id)
        if (items.length === 0) return null
        return (
          <div key={group.id}>
            <p className="mb-1.5 px-1 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
              {group.label}
            </p>
            <div className="flex gap-1 overflow-x-auto pb-px">
              {items.map((t) => {
                const i18nKey = `tab${t.id.charAt(0).toUpperCase()}${t.id.slice(1)}` as keyof typeof tr.settings
                const label = tr.settings[i18nKey] || t.label
                const active = tab === t.id
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => onChange(t.id)}
                    className={`touch-target flex shrink-0 items-center gap-1.5 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                      active
                        ? 'bg-accent/15 text-accent ring-1 ring-accent/40'
                        : 'text-text-secondary hover:bg-surface-2 hover:text-text-primary'
                    }`}
                  >
                    {label}
                    {t.badge === 'frozen' && (
                      <span className="rounded bg-warning/15 px-1 py-0.5 text-[9px] font-bold uppercase text-warning">
                        frozen
                      </span>
                    )}
                    {t.badge === 'pilot' && (
                      <span className="rounded bg-accent/15 px-1 py-0.5 text-[9px] font-bold uppercase text-accent">
                        pilot
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>
        )
      })}
    </div>
  )
}
