import { Checkbox, FormGrid, FormSection, Input, Select } from '../../../components/ui/Form'
import type { FormTabProps } from '../types'

/** ACL paths + category export helpers. Live rule CRUD lives under Policies. */
export function FilteringTab({ form, update, tr }: FormTabProps) {
  return (
    <div className="space-y-6">
      <FormSection title={tr.settings.tabFiltering}>
        <p className="mb-3 text-xs text-text-secondary">
          Runtime rules are managed on the <strong className="text-text-primary">Policies</strong> page.
          Paths below control where the proxy loads/persists ACL JSON. Category checkboxes only feed
          Settings → Apply when “rewrite ACL file” is opted in.
        </p>
        <Checkbox label="ACL_ENABLED" checked={form.aclEnabled} onChange={(v) => update('aclEnabled', v)} />
        {form.aclEnabled && (
          <>
            <FormGrid>
              <Select
                label="ACL_DEFAULT_ACTION"
                value={form.aclDefaultAction}
                onChange={(e) => update('aclDefaultAction', e.target.value)}
                options={[
                  { value: 'allow', label: 'allow' },
                  { value: 'deny', label: 'deny' },
                ]}
              />
              <Input
                label="ACL_API_TOKEN"
                type="password"
                value={form.aclApiToken}
                onChange={(e) => update('aclApiToken', e.target.value)}
                hint="Session-only, never persisted"
              />
            </FormGrid>
            <FormGrid>
              <Input
                label="ACL_RULES_PATH"
                value={form.aclRulesPath}
                onChange={(e) => update('aclRulesPath', e.target.value)}
                hint="Must be writable (directory mount, not single-file :ro)"
              />
              <Input
                label="ACL_RELOAD_INTERVAL"
                type="number"
                value={form.aclReloadInterval}
                onChange={(e) => update('aclReloadInterval', e.target.value)}
              />
            </FormGrid>
            <Checkbox
              label="ACL_AUTO_RELOAD"
              checked={form.aclAutoReload}
              onChange={(v) => update('aclAutoReload', v)}
            />
            <div className="space-y-2 rounded-md border border-border/80 bg-surface-0 p-3">
              <p className="text-sm font-medium text-text-primary">Quick category rules (export / opt-in rewrite)</p>
              <Checkbox
                label="Block Malware"
                checked={form.aclBlockMalware}
                onChange={(v) => update('aclBlockMalware', v)}
              />
              <Checkbox
                label="Block Phishing"
                checked={form.aclBlockPhishing}
                onChange={(v) => update('aclBlockPhishing', v)}
              />
              <Checkbox
                label="Block Adult"
                checked={form.aclBlockAdult}
                onChange={(v) => update('aclBlockAdult', v)}
              />
              <Checkbox
                label="Block Gambling"
                checked={form.aclBlockGambling}
                onChange={(v) => update('aclBlockGambling', v)}
              />
              <Checkbox
                label="Block RKN Registry (Zapret-info)"
                checked={form.aclBlockRkn}
                onChange={(v) => update('aclBlockRkn', v)}
              />
            </div>
          </>
        )}
      </FormSection>
      <FormSection title="Categorization sources">
        <Checkbox
          label="CATEGORIZATION_ENABLED"
          checked={form.categorizationEnabled}
          onChange={(v) => update('categorizationEnabled', v)}
        />
        {form.categorizationEnabled && (
          <>
            <Input
              label="CATEGORIZATION_CACHE_TTL"
              type="number"
              value={form.categorizationCacheTtl}
              onChange={(e) => update('categorizationCacheTtl', e.target.value)}
            />
            <Checkbox label="UT1 blacklists" checked={form.ut1Enabled} onChange={(v) => update('ut1Enabled', v)} />
            {form.ut1Enabled && (
              <Input label="UT1_PATH" value={form.ut1Path} onChange={(e) => update('ut1Path', e.target.value)} />
            )}
            <Checkbox
              label="URLhaus online lookups"
              checked={form.urlhausEnabled}
              onChange={(v) => update('urlhausEnabled', v)}
            />
            <Checkbox
              label="PhishTank online lookups"
              checked={form.phishtankEnabled}
              onChange={(v) => update('phishtankEnabled', v)}
            />
            {form.phishtankEnabled && (
              <Input
                label="PHISHTANK_API_KEY"
                type="password"
                value={form.phishtankApiKey}
                onChange={(e) => update('phishtankApiKey', e.target.value)}
                hint="Session-only, never persisted"
              />
            )}
            <Checkbox
              label="CUSTOM_DB_ENABLED"
              checked={form.customDbEnabled}
              onChange={(v) => update('customDbEnabled', v)}
            />
            {form.customDbEnabled && (
              <Input
                label="CUSTOM_DB_PATH"
                value={form.customDbPath}
                onChange={(e) => update('customDbPath', e.target.value)}
              />
            )}
            <Checkbox
              label="RKN_SYNC_ENABLED (Roskomnadzor daily dump)"
              checked={form.rknSyncEnabled}
              onChange={(v) => update('rknSyncEnabled', v)}
            />
            {form.rknSyncEnabled && (
              <Input
                label="RKN_SYNC_URL"
                value={form.rknSyncUrl}
                onChange={(e) => update('rknSyncUrl', e.target.value)}
                hint="Zapret-info dump.csv mirror (SourceForge)"
              />
            )}
          </>
        )}
      </FormSection>
    </div>
  )
}
