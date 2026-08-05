import { Checkbox, FormGrid, FormSection, Input } from '../../../components/ui/Form'
import type { FormTabProps } from '../types'

export function ThreatTab({ form, update, tr }: FormTabProps) {
  return (
    <FormSection title={tr.settings.tabThreat}>
      <Checkbox
        label="THREAT_SCORE_ENABLED"
        checked={form.threatScoreEnabled}
        onChange={(v) => update('threatScoreEnabled', v)}
        hint="Proxy polls the ml-worker snapshot and enforces thresholds on the request path (O(1) in-memory lookup)"
      />
      {form.threatScoreEnabled && (
        <>
          <Input
            label="THREAT_SCORE_POLL_URL"
            value={form.threatScorePollUrl}
            onChange={(e) => update('threatScorePollUrl', e.target.value)}
          />
          <FormGrid>
            <Input
              label="Poll interval (s)"
              type="number"
              value={form.threatScorePollInterval}
              onChange={(e) => update('threatScorePollInterval', e.target.value)}
            />
            <Input
              label="Block threshold (0–1)"
              value={form.threatScoreBlockThreshold}
              onChange={(e) => update('threatScoreBlockThreshold', e.target.value)}
            />
          </FormGrid>
          <Input
            label="Warn threshold (0–1)"
            value={form.threatScoreWarnThreshold}
            onChange={(e) => update('threatScoreWarnThreshold', e.target.value)}
            hint="Scores ≥ warn are logged/enriched; ≥ block are denied"
          />
        </>
      )}
    </FormSection>
  )
}
