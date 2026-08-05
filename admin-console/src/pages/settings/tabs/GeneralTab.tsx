import { Checkbox, FormGrid, FormSection, Input, Select } from '../../../components/ui/Form'
import type { FormTabProps } from '../types'

export function GeneralTab({ form, update, tr }: FormTabProps) {
  return (
    <FormSection title={tr.settings.tabGeneral}>
      <FormGrid>
        <Input
          label="HTTP proxy port"
          type="number"
          value={form.httpPort}
          onChange={(e) => update('httpPort', e.target.value)}
        />
        <Input
          label="Metrics / control API port"
          type="number"
          value={form.metricsPort}
          onChange={(e) => update('metricsPort', e.target.value)}
        />
      </FormGrid>
      <FormGrid>
        <Select
          label="RUST_LOG"
          value={form.logLevel}
          onChange={(e) => update('logLevel', e.target.value)}
          options={[
            { value: 'warn', label: 'warn' },
            { value: 'info,bsdm_proxy=info', label: 'info,bsdm_proxy=info' },
            { value: 'info,bsdm_proxy=debug', label: 'info,bsdm_proxy=debug' },
            { value: 'debug', label: 'debug' },
          ]}
        />
        <Input
          label="Worker count"
          type="number"
          value={form.workerCount}
          onChange={(e) => update('workerCount', e.target.value)}
          hint="0 = number of CPU cores"
        />
      </FormGrid>
      <Checkbox
        label="MITM_ENABLED (HTTPS interception)"
        checked={form.mitmEnabled}
        onChange={(v) => update('mitmEnabled', v)}
        hint="Requires /certs/ca.key and ca.crt"
      />
      <Checkbox
        label="PERF_FAST_CACHE_HIT"
        checked={form.perfFastCacheHit}
        onChange={(v) => update('perfFastCacheHit', v)}
        hint="Skip per-hit bookkeeping on the hot path"
      />
      <Checkbox
        label="STREAMING_MISS_ENABLED"
        checked={form.streamingMissEnabled}
        onChange={(v) => update('streamingMissEnabled', v)}
      />
    </FormSection>
  )
}
