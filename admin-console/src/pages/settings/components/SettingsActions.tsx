import type { ChangeEvent } from 'react'
import { Download, Eye, Save, Upload } from 'lucide-react'
import type { ConfigFormState } from '../../../lib/config/types'
import { downloadFile, formatEnv, generateAclRules, generateDockerCompose } from '../../../lib/config/export'
import { Button } from '../../../components/ui/Button'

interface SettingsActionsProps {
  form: ConfigFormState
  applying: boolean
  labels: {
    applying: string
    saveApply: string
    previewEnv: string
    exportEnv: string
    exportCompose: string
    exportAcl: string
    importEnv: string
    resetSettings: string
  }
  onApply: () => void
  onPreviewEnv: (content: string) => void
  onImport: (event: ChangeEvent<HTMLInputElement>) => void
  onReset: () => void
  onMissingAcl: () => void
}

export function SettingsActions({
  form,
  applying,
  labels,
  onApply,
  onPreviewEnv,
  onImport,
  onReset,
  onMissingAcl,
}: SettingsActionsProps) {
  const exportAcl = () => {
    const rules = generateAclRules(form)
    if (!rules) {
      onMissingAcl()
      return
    }
    downloadFile('acl-rules.json', `${JSON.stringify(rules, null, 2)}\n`)
  }

  return (
    <div className="sticky bottom-4 z-10 flex flex-wrap gap-2 rounded-xl border border-border/80 bg-surface-1/95 p-3 shadow-lg backdrop-blur">
      <Button onClick={onApply} disabled={applying}>
        <Save className="size-4" /> {applying ? labels.applying : labels.saveApply}
      </Button>
      <Button onClick={() => onPreviewEnv(formatEnv(form))}>
        <Eye className="size-4" /> {labels.previewEnv}
      </Button>
      <Button variant="secondary" onClick={() => downloadFile('bsdm-proxy.env', formatEnv(form))}>
        <Download className="size-4" /> {labels.exportEnv}
      </Button>
      <Button
        variant="secondary"
        onClick={() => downloadFile('docker-compose.yml', generateDockerCompose(form))}
      >
        <Download className="size-4" /> {labels.exportCompose}
      </Button>
      <Button variant="secondary" onClick={exportAcl}>
        <Download className="size-4" /> {labels.exportAcl}
      </Button>
      <label className="touch-target inline-flex cursor-pointer items-center justify-center gap-2 rounded-md border border-border bg-surface-2 px-4 py-2 text-sm font-semibold hover:bg-surface-3">
        <Upload className="size-4" /> {labels.importEnv}
        <input type="file" accept=".env,text/plain" className="hidden" onChange={onImport} />
      </label>
      <Button variant="ghost" onClick={onReset}>
        {labels.resetSettings}
      </Button>
    </div>
  )
}
