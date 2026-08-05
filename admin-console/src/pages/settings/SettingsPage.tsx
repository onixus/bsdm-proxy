import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Download, Eye, Save, Upload } from 'lucide-react'
import { defaultFormState } from '../../lib/config/types'
import { formatEnv, generateAclRules, generateDockerCompose, downloadFile } from '../../lib/config/export'
import { Button } from '../../components/ui/Button'
import { CodePreview, CopyButton, Modal } from '../../components/ui/Modal'
import { useToast } from '../../components/ui/Toast'
import { useLanguage, translations } from '../../lib/i18n'
import { isDemoMode } from '../../api/source'
import { LiveNodePanel } from './components/LiveNodePanel'
import { LiveConfigPanel } from './components/LiveConfigPanel'
import { SettingsNav } from './components/SettingsNav'
import { useSettingsController } from './hooks/useSettingsController'
import { isSettingsTab, type SettingsTabId } from './types'
import { GeneralTab } from './tabs/GeneralTab'
import { CacheTab } from './tabs/CacheTab'
import { AuthTab } from './tabs/AuthTab'
import { FilteringTab } from './tabs/FilteringTab'
import { ThreatTab } from './tabs/ThreatTab'
import { EventsTab } from './tabs/EventsTab'
import { NetworkTab } from './tabs/NetworkTab'
import { SecurityTab } from './tabs/SecurityTab'
import { ApiTab } from './tabs/ApiTab'

export function SettingsPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]
  const { toast } = useToast()
  const [searchParams] = useSearchParams()
  const requestedTab = searchParams.get('tab')
  const [tab, setTab] = useState<SettingsTabId>(() =>
    isSettingsTab(requestedTab) ? requestedTab : 'general',
  )
  const [preview, setPreview] = useState<{ title: string; content: string } | null>(null)

  const ctrl = useSettingsController(toast)

  useEffect(() => {
    if (isSettingsTab(requestedTab)) setTab(requestedTab)
  }, [requestedTab])

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

      <SettingsNav tab={tab} onChange={setTab} tr={tr} />

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

      {/* Sticky-feel action row */}
      <div className="sticky bottom-4 z-10 flex flex-wrap gap-2 rounded-xl border border-border/80 bg-surface-1/95 p-3 shadow-lg backdrop-blur">
        <Button onClick={() => void ctrl.handleApply()} disabled={ctrl.applying}>
          <Save className="size-4" /> {ctrl.applying ? tr.settings.applying : tr.settings.saveApply}
        </Button>
        <Button onClick={() => setPreview({ title: 'bsdm-proxy.env', content: formatEnv(ctrl.form) })}>
          <Eye className="size-4" /> {tr.settings.previewEnv}
        </Button>
        <Button
          variant="secondary"
          onClick={() => downloadFile('bsdm-proxy.env', formatEnv(ctrl.form))}
        >
          <Download className="size-4" /> {tr.settings.exportEnv}
        </Button>
        <Button
          variant="secondary"
          onClick={() => downloadFile('docker-compose.yml', generateDockerCompose(ctrl.form))}
        >
          <Download className="size-4" /> {tr.settings.exportCompose}
        </Button>
        <Button
          variant="secondary"
          onClick={() => {
            const rules = generateAclRules(ctrl.form)
            if (!rules) {
              toast('warning', 'Enable ACL on the Filtering tab first')
              return
            }
            downloadFile('acl-rules.json', JSON.stringify(rules, null, 2) + '\n')
          }}
        >
          <Download className="size-4" /> {tr.settings.exportAcl}
        </Button>
        <label className="touch-target inline-flex cursor-pointer items-center justify-center gap-2 rounded-md border border-border bg-surface-2 px-4 py-2 text-sm font-semibold hover:bg-surface-3">
          <Upload className="size-4" /> {tr.settings.importEnv}
          <input type="file" accept=".env,text/plain" className="hidden" onChange={ctrl.handleImport} />
        </label>
        <Button
          variant="ghost"
          onClick={() => {
            ctrl.handleReset()
            // ensure defaultFormState path still works if handleReset only sets form
            void defaultFormState
          }}
        >
          {tr.settings.resetSettings}
        </Button>
      </div>

      <Modal
        open={!!preview}
        onClose={() => setPreview(null)}
        title={preview?.title ?? ''}
        footer={preview && <CopyButton text={preview.content} />}
        wide
      >
        {preview && <CodePreview content={preview.content} />}
      </Modal>
    </div>
  )
}
