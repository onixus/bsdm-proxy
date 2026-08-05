import { Checkbox, FormGrid, FormSection, Input, Select } from '../../../components/ui/Form'
import { fetchClusterSessionState } from '../../../api/cluster'
import { useSourcedQuery } from '../../../hooks/useSourced'
import type { FormTabProps } from '../types'

export function SecurityTab({ form, update, tr }: FormTabProps) {
  const { data: sessionState } = useSourcedQuery(['cluster-session-state'], fetchClusterSessionState)

  return (
    <div className="space-y-6">
      <FormSection title="Global Session State (Redis Cluster)">
        <div className="space-y-2 rounded-lg border border-border-default bg-surface-hover/50 p-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-secondary">Session Store Mode:</span>
            <span
              className={`rounded px-2 py-0.5 font-mono text-xs font-semibold ${
                sessionState?.data?.redis_connected
                  ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                  : 'border border-amber-500/20 bg-amber-500/10 text-amber-400'
              }`}
            >
              {sessionState?.data?.status ?? 'standalone_memory'}
            </span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-secondary">Active Global Sessions:</span>
            <span className="font-mono font-semibold text-text-primary">
              {sessionState?.data?.session_count ?? 0}
            </span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-secondary">Distributed Rate Limiting:</span>
            <span className="font-mono text-xs text-text-secondary">
              {sessionState?.data?.distributed_rate_limit_enabled
                ? 'Active (Redis)'
                : 'Inactive (Local Buckets)'}
            </span>
          </div>
        </div>
      </FormSection>
      <FormSection title={tr.settings.tabSecurity}>
        <Checkbox
          label="RATE_LIMIT_ENABLED"
          checked={form.rateLimitEnabled}
          onChange={(v) => update('rateLimitEnabled', v)}
        />
        {form.rateLimitEnabled && (
          <Input
            label="RATE_LIMIT_MAX_KEYS"
            type="number"
            value={form.rateLimitMaxKeys}
            onChange={(e) => update('rateLimitMaxKeys', e.target.value)}
          />
        )}
      </FormSection>
      <FormSection title="eBPF / XDP (Experimental — Frozen)">
        <p className="mb-3 text-xs text-text-secondary">
          Not part of Hybrid pilot day-1. Leave disabled unless you accept Experimental (Frozen)
          scope in docs/project-status.md.
        </p>
        <Checkbox
          label="EBPF_XDP_ENABLED"
          checked={form.ebpfXdpEnabled}
          onChange={(v) => update('ebpfXdpEnabled', v)}
          hint="Requires CAP_BPF and a supported NIC driver"
        />
        {form.ebpfXdpEnabled && (
          <FormGrid>
            <Input
              label="EBPF_XDP_IFACE"
              value={form.ebpfXdpIface}
              onChange={(e) => update('ebpfXdpIface', e.target.value)}
            />
            <Select
              label="EBPF_XDP_MODE"
              value={form.ebpfXdpMode}
              onChange={(e) => update('ebpfXdpMode', e.target.value)}
              options={[
                { value: 'driver', label: 'driver (native)' },
                { value: 'skb', label: 'skb (generic)' },
                { value: 'hw', label: 'hw (offload)' },
              ]}
            />
          </FormGrid>
        )}
      </FormSection>
      <FormSection title="Wasm request hooks (Experimental — Frozen)">
        <p className="mb-3 text-xs text-text-secondary">
          PoC only. Not a pilot security boundary. Prefer ACL / DNS / selective MITM for policy.
        </p>
        <Checkbox
          label="WASM_ENABLED"
          checked={form.wasmEnabled}
          onChange={(v) => update('wasmEnabled', v)}
        />
        {form.wasmEnabled && (
          <>
            <Input
              label="WASM_MODULE_PATH"
              value={form.wasmModulePath}
              onChange={(e) => update('wasmModulePath', e.target.value)}
            />
            <FormGrid>
              <Input
                label="WASM_FUEL"
                type="number"
                value={form.wasmFuel}
                onChange={(e) => update('wasmFuel', e.target.value)}
              />
              <div className="pt-6">
                <Checkbox
                  label="WASM_FAIL_OPEN"
                  checked={form.wasmFailOpen}
                  onChange={(v) => update('wasmFailOpen', v)}
                  hint="Allow traffic if the module traps"
                />
              </div>
            </FormGrid>
          </>
        )}
      </FormSection>
      <FormSection title="gRPC control plane">
        <Checkbox
          label="CONTROL_GRPC_ENABLED"
          checked={form.controlGrpcEnabled}
          onChange={(v) => update('controlGrpcEnabled', v)}
        />
        {form.controlGrpcEnabled && (
          <Input
            label="CONTROL_GRPC_BIND"
            value={form.controlGrpcBind}
            onChange={(e) => update('controlGrpcBind', e.target.value)}
          />
        )}
        <Input
          label="CONTROL_API_TOKEN"
          type="password"
          value={form.controlApiToken}
          onChange={(e) => update('controlApiToken', e.target.value)}
          hint="Protects /api/stats, /api/cache/purge, hierarchy and TLS endpoints. Session-only."
        />
      </FormSection>
      <FormSection title="ICAP Content Adaptation (AV scanning)">
        <p className="mb-2 text-xs text-text-secondary">Experimental (Frozen).</p>
        <Checkbox
          label="ICAP_ENABLED"
          checked={form.icapEnabled}
          onChange={(v) => update('icapEnabled', v)}
        />
        {form.icapEnabled && (
          <>
            <Input
              label="ICAP_URL"
              value={form.icapUrl}
              onChange={(e) => update('icapUrl', e.target.value)}
              hint="e.g. icap://127.0.0.1:1344/srv_clamav"
            />
            <FormGrid>
              <div className="space-y-2">
                <Checkbox
                  label="ICAP_REQMOD (Request modification)"
                  checked={form.icapReqmod}
                  onChange={(v) => update('icapReqmod', v)}
                />
                <Checkbox
                  label="ICAP_RESPMOD (Response modification)"
                  checked={form.icapRespmod}
                  onChange={(v) => update('icapRespmod', v)}
                />
                <Checkbox
                  label="ICAP_FAIL_OPEN (Allow on error)"
                  checked={form.icapFailOpen}
                  onChange={(v) => update('icapFailOpen', v)}
                />
              </div>
            </FormGrid>
          </>
        )}
      </FormSection>
    </div>
  )
}
