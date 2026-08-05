import { RefreshCw } from 'lucide-react'
import { Button } from '../../../components/ui/Button'
import { Panel } from '../../../components/dashboard/MetricWidget'

export type LiveLoadState = 'idle' | 'loading' | 'ok' | 'error'

export function LiveConfigPanel({
  liveLoadState,
  liveEnvPath,
  liveEnv,
  rewriteAclFromForm,
  onRewriteAclChange,
  onReload,
  reloading,
}: {
  liveLoadState: LiveLoadState
  liveEnvPath: string | null
  liveEnv: Record<string, string> | null
  rewriteAclFromForm: boolean
  onRewriteAclChange: (v: boolean) => void
  onReload: () => void
  reloading: boolean
}) {
  return (
    <Panel title="Live node config">
      <div className="space-y-2 text-sm text-text-secondary">
        <p>
          Apply sends only a <strong className="text-text-primary">delta</strong> vs the last successful{' '}
          <code className="text-xs">GET /api/config</code> — not full form defaults (avoids overwriting{' '}
          <code className="text-xs">ACL_RULES_PATH</code>, <code className="text-xs">HTTP_PORT</code>, etc.).
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <span
            className={
              liveLoadState === 'ok'
                ? 'text-success'
                : liveLoadState === 'error'
                  ? 'text-danger'
                  : 'text-text-muted'
            }
          >
            {liveLoadState === 'loading' && 'Loading live env…'}
            {liveLoadState === 'ok' && `Loaded · ${liveEnvPath ?? 'env'}`}
            {liveLoadState === 'error' &&
              'Live config unavailable — export still works; Apply uses non-default fields only.'}
            {liveLoadState === 'idle' && 'Not loaded'}
          </span>
          <Button type="button" variant="secondary" disabled={reloading} onClick={onReload}>
            <RefreshCw className={`size-4 ${reloading ? 'animate-spin' : ''}`} /> Reload from node
          </Button>
        </div>
        {liveEnv && (
          <p className="font-mono text-xs text-text-muted">
            ACL_RULES_PATH={liveEnv.ACL_RULES_PATH ?? '—'} · HTTP_PORT={liveEnv.HTTP_PORT ?? '—'} ·
            CONFIG_ENV_PATH={liveEnv.CONFIG_ENV_PATH ?? liveEnvPath ?? '—'}
          </p>
        )}
        <label className="flex items-start gap-2 pt-1 text-text-secondary">
          <input
            type="checkbox"
            className="mt-1"
            checked={rewriteAclFromForm}
            onChange={(e) => onRewriteAclChange(e.target.checked)}
          />
          <span>
            Also rewrite <code className="text-xs">ACL_RULES_PATH</code> from Filtering-tab category
            checkboxes only (destructive — drops custom/domain rules managed under Policies). Off by
            default.
          </span>
        </label>
      </div>
    </Panel>
  )
}
