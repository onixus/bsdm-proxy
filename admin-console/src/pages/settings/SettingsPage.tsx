import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CodePreview, CopyButton, Modal } from '../../components/ui/Modal'
import { useToast } from '../../components/ui/Toast'
import { isDemoMode } from '../../api/source'
import { translations, useLanguage } from '../../lib/i18n'
import { LiveConfigPanel } from './components/LiveConfigPanel'
import { LiveNodePanel } from './components/LiveNodePanel'
import { SettingsActions } from './components/SettingsActions'
import { SettingsNav } from './components/SettingsNav'
import { useSettingsController } from './hooks/useSettingsController'
import { ApiTab } from './tabs/ApiTab'
import { AuthTab } from './tabs/AuthTab'
import { CacheTab } from './tabs/CacheTab'
import { EventsTab } from './tabs/EventsTab'
import { FilteringTab } from './tabs/FilteringTab'
import { GeneralTab } from './tabs/GeneralTab'
import { NetworkTab } from './tabs/NetworkTab'
import { SecurityTab } from './tabs/SecurityTab'
import { ThreatTab } from './tabs/ThreatTab'
import { isSettingsTab, type SettingsTabId } from './types'

export function SettingsPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]
  const { toast } = useToast()
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedTab = searchParams.get('tab')
  const [tab, setTab] = useState<SettingsTabId>(() =>
    isSettingsTab(requestedTab) ? requestedTab : 'general',
  )
  const [preview, setPreview] = useState<{ title: string; content: string } | null>(null)
  const ctrl = useSettingsController(toast)

  useEffect(() => {
    if (isSettingsTab(requestedTab)) setTab(requestedTab)
  }, [requestedTab])

  const changeTab = (nextTab: SettingsTabId) => {
    setTab(nextTab)
    const nextParams = new URLSearchParams(searchParams)
    nextParams.set('tab', nextTab)
    setSearchParams(nextParams, { replace: true })
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{tr.settings.title}</h1>
        <p className="text-sm text-text-secondary">{tr.settings.subtitle}</p>
      </div>

      <LiveNodePanel tr={tr} />

      <LiveConfigPanel
        liveLoadState={ctrl.liveLoadState}
        liveEnvPath={ctrl.liveEnvPath}
        liveEnv={ctrl.liveEnv}
        rewriteAclFromForm={ctrl.rewriteAclFromForm}
        onRewriteAclChange={ctrl.setRewriteAclFromForm}
        reloading={ctrl.liveLoadState === 'loading'}
        onReload={() => {
          void ctrl.reloadLiveConfig().then(() => {
            if (!isDemoMode()) toast('info', 'Reloaded live configuration')
          })
        }}
      />

      <SettingsNav tab={tab} onChange={changeTab} tr={tr} />

      <div className="rounded-xl border border-border bg-surface-1 p-6 shadow-sm">
        {tab === 'general' && <GeneralTab form={ctrl.form} update={ctrl.update} tr={tr} />}
        {tab === 'cache' && <CacheTab form={ctrl.form} update={ctrl.update} tr={tr} />}
        {tab === 'auth' && <AuthTab form={ctrl.form} update={ctrl.update} tr={tr} />}
        {tab === 'filtering' && <FilteringTab form={ctrl.form} update={ctrl.update} tr={tr} />}
        {tab === 'threat' && <ThreatTab form={ctrl.form} update={ctrl.update} tr={tr} />}
        {tab === 'events' && <EventsTab form={ctrl.form} update={ctrl.update} tr={tr} />}
        {tab === 'network' && <NetworkTab form={ctrl.form} update={ctrl.update} tr={tr} />}
        {tab === 'security' && <SecurityTab form={ctrl.form} update={ctrl.update} tr={tr} />}
        {tab === 'api' && (
          <ApiTab
            settings={ctrl.apiSettings}
            update={ctrl.updateApi}
            demoEnabled={ctrl.demoEnabled}
            onDemoChange={ctrl.handleDemoChange}
          />
        )}
      </div>

      <SettingsActions
        form={ctrl.form}
        applying={ctrl.applying}
        labels={{
          applying: tr.settings.applying,
          saveApply: tr.settings.saveApply,
          previewEnv: tr.settings.previewEnv,
          exportEnv: tr.settings.exportEnv,
          exportCompose: tr.settings.exportCompose,
          exportAcl: tr.settings.exportAcl,
          importEnv: tr.settings.importEnv,
          resetSettings: tr.settings.resetSettings,
        }}
        onApply={() => void ctrl.handleApply()}
        onPreviewEnv={(content) => setPreview({ title: 'bsdm-proxy.env', content })}
        onImport={ctrl.handleImport}
        onReset={ctrl.handleReset}
        onMissingAcl={() => toast('warning', 'Enable ACL on the Filtering tab first')}
      />

      <Modal
        open={Boolean(preview)}
        onClose={() => setPreview(null)}
        title={preview?.title ?? ''}
        footer={preview ? <CopyButton text={preview.content} /> : undefined}
        wide
      >
        {preview && <CodePreview content={preview.content} />}
      </Modal>
    </div>
  )
}
