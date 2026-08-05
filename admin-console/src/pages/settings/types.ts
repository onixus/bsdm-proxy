import type { ConfigFormState } from '../../lib/config/types'

export type SettingsTabId =
  | 'general'
  | 'cache'
  | 'auth'
  | 'filtering'
  | 'threat'
  | 'events'
  | 'network'
  | 'security'
  | 'api'

export type SettingsTabGroup = 'core' | 'policy' | 'observability' | 'advanced' | 'console'

export interface SettingsTabDef {
  id: SettingsTabId
  label: string
  group: SettingsTabGroup
  /** Shown as subtle badge next to the tab label */
  badge?: 'frozen' | 'pilot'
}

export const SETTINGS_TAB_GROUPS: { id: SettingsTabGroup; label: string }[] = [
  { id: 'core', label: 'Core' },
  { id: 'policy', label: 'Policy' },
  { id: 'observability', label: 'Observability' },
  { id: 'advanced', label: 'Advanced' },
  { id: 'console', label: 'Console' },
]

export const SETTINGS_TABS: SettingsTabDef[] = [
  { id: 'general', label: 'General', group: 'core' },
  { id: 'cache', label: 'Cache', group: 'core' },
  { id: 'auth', label: 'Auth', group: 'policy' },
  { id: 'filtering', label: 'Filtering', group: 'policy', badge: 'pilot' },
  { id: 'threat', label: 'Threat / ML', group: 'observability' },
  { id: 'events', label: 'Events / Storage', group: 'observability' },
  { id: 'network', label: 'Hierarchy / TLS', group: 'advanced' },
  { id: 'security', label: 'Security & frozen', group: 'advanced', badge: 'frozen' },
  { id: 'api', label: 'Console API', group: 'console', badge: 'pilot' },
]

export type FormUpdateFn = <K extends keyof ConfigFormState>(
  key: K,
  value: ConfigFormState[K],
) => void

export interface FormTabProps {
  form: ConfigFormState
  update: FormUpdateFn
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tr: any
}

export function isSettingsTab(value: string | null): value is SettingsTabId {
  return SETTINGS_TABS.some((tab) => tab.id === value)
}
