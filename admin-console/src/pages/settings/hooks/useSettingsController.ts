import { useCallback, useEffect, useState } from 'react'
import type { ConfigFormState } from '../../../lib/config/types'
import { defaultFormState } from '../../../lib/config/types'
import { collectConfigDelta, describeEnvDelta } from '../../../lib/config/collect'
import { generateAclRules } from '../../../lib/config/export'
import { applyEnvToForm, importEnvFile, loadSavedForm, saveFormState } from '../../../lib/config/import'
import { applyNodeConfig, fetchNodeConfig } from '../../../api/config'
import { loadApiSettings, saveApiSettings, type ApiSettings } from '../../../api/settings'
import { isDemoMode, setDemoMode } from '../../../api/source'
import type { LiveLoadState } from '../components/LiveConfigPanel'

export function useSettingsController(toast: (kind: 'success' | 'error' | 'info' | 'warning', msg: string) => void) {
  const [form, setForm] = useState<ConfigFormState>(() => loadSavedForm())
  const [apiSettings, setApiSettings] = useState<ApiSettings>(() => loadApiSettings())
  const [demoEnabled, setDemoEnabled] = useState(isDemoMode)
  const [applying, setApplying] = useState(false)
  const [liveEnv, setLiveEnv] = useState<Record<string, string> | null>(null)
  const [liveEnvPath, setLiveEnvPath] = useState<string | null>(null)
  const [liveLoadState, setLiveLoadState] = useState<LiveLoadState>('idle')
  const [rewriteAclFromForm, setRewriteAclFromForm] = useState(false)

  const reloadLiveConfig = useCallback(async () => {
    if (isDemoMode()) {
      const snapshot = await fetchNodeConfig()
      setLiveEnv(snapshot.env)
      setLiveEnvPath(snapshot.env_path)
      setForm((prev) => applyEnvToForm(snapshot.env, prev))
      setLiveLoadState('ok')
      return
    }
    setLiveLoadState('loading')
    try {
      const snapshot = await fetchNodeConfig()
      setLiveEnv(snapshot.env)
      setLiveEnvPath(snapshot.env_path)
      setForm((prev) => {
        const next = applyEnvToForm(snapshot.env, prev)
        saveFormState(next)
        return next
      })
      setLiveLoadState('ok')
    } catch {
      setLiveLoadState('error')
    }
  }, [])

  useEffect(() => {
    void reloadLiveConfig()
  }, [reloadLiveConfig])

  const update = useCallback(<K extends keyof ConfigFormState>(key: K, value: ConfigFormState[K]) => {
    setForm((prev) => {
      const next = { ...prev, [key]: value }
      saveFormState(next)
      return next
    })
  }, [])

  const updateApi = useCallback(<K extends keyof ApiSettings>(key: K, value: ApiSettings[K]) => {
    setApiSettings((prev) => {
      const next = { ...prev, [key]: value }
      saveApiSettings(next)
      return next
    })
  }, [])

  const handleImport = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (!file) return
      const reader = new FileReader()
      reader.onload = () => {
        const next = importEnvFile(String(reader.result ?? ''), form)
        setForm(next)
        saveFormState(next)
        toast('success', `Imported configuration from ${file.name}`)
      }
      reader.readAsText(file)
      e.target.value = ''
    },
    [form, toast],
  )

  const handleApply = useCallback(async () => {
    const env = collectConfigDelta(form, liveEnv)
    const { changed, sensitive } = describeEnvDelta(env, liveEnv)
    if (changed.length === 0 && !rewriteAclFromForm) {
      toast('info', 'No configuration changes vs live node — nothing to apply.')
      return
    }
    if (sensitive.length > 0) {
      const ok = window.confirm(
        `This will change pilot-sensitive paths/ports:\n\n${sensitive
          .map((k) => `• ${k}=${env[k]}`)
          .join('\n')}\n\nContinue?`,
      )
      if (!ok) return
    }
    let aclRules: ReturnType<typeof generateAclRules> = null
    if (rewriteAclFromForm) {
      if (!form.aclEnabled) {
        toast('warning', 'Enable ACL on the Filtering tab before rewriting rules.')
        return
      }
      aclRules = generateAclRules(form)
    }

    setApplying(true)
    try {
      const result = await applyNodeConfig({
        env,
        acl_rules: aclRules,
        restart: true,
      })
      saveFormState(form)
      await reloadLiveConfig()
      const n = changed.length
      toast(
        'success',
        `${result.message}${n ? ` (${n} env key${n === 1 ? '' : 's'})` : ''}${
          rewriteAclFromForm ? ' · ACL file rewritten' : ''
        }`,
      )
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to apply configuration'
      toast('error', message)
    } finally {
      setApplying(false)
    }
  }, [form, liveEnv, rewriteAclFromForm, reloadLiveConfig, toast])

  const handleReset = useCallback(() => {
    setForm(defaultFormState)
    saveFormState(defaultFormState)
    toast('info', 'Form reset to defaults')
  }, [toast])

  const handleDemoChange = useCallback(
    (v: boolean) => {
      setDemoEnabled(v)
      setDemoMode(v)
      toast(
        'info',
        v
          ? 'Demo mode ON — unreachable APIs now render sample data marked “Demo”.'
          : 'Demo mode OFF — failures show real error states.',
      )
    },
    [toast],
  )

  return {
    form,
    setForm,
    apiSettings,
    demoEnabled,
    applying,
    liveEnv,
    liveEnvPath,
    liveLoadState,
    rewriteAclFromForm,
    setRewriteAclFromForm,
    update,
    updateApi,
    handleImport,
    handleApply,
    handleReset,
    handleDemoChange,
    reloadLiveConfig,
  }
}
