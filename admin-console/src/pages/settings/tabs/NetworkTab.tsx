import { Checkbox, FormSection, Input } from '../../../components/ui/Form'
import type { FormTabProps } from '../types'

export function NetworkTab({ form, update, tr }: FormTabProps) {
  return (
    <div className="space-y-6">
      <FormSection title={tr.settings.tabNetwork}>
        <Input
          label="HIERARCHY_PEERS_PATH"
          value={form.hierarchyPeersPath}
          onChange={(e) => update('hierarchyPeersPath', e.target.value)}
          hint="JSON file with parent/sibling peers; empty disables the hierarchy"
        />
        <Checkbox
          label="ICP_SERVER_ENABLED"
          checked={form.icpServerEnabled}
          onChange={(v) => update('icpServerEnabled', v)}
        />
        {form.icpServerEnabled && (
          <Input label="ICP_BIND" value={form.icpBind} onChange={(e) => update('icpBind', e.target.value)} />
        )}
        <Checkbox
          label="HTCP_SERVER_ENABLED"
          checked={form.htcpServerEnabled}
          onChange={(v) => update('htcpServerEnabled', v)}
        />
        {form.htcpServerEnabled && (
          <Input label="HTCP_BIND" value={form.htcpBind} onChange={(e) => update('htcpBind', e.target.value)} />
        )}
        <Checkbox
          label="PEER_DISCOVERY_ENABLED (multicast)"
          checked={form.peerDiscoveryEnabled}
          onChange={(v) => update('peerDiscoveryEnabled', v)}
        />
        {form.peerDiscoveryEnabled && (
          <Input
            label="PEER_DISCOVERY_MULTICAST"
            value={form.peerDiscoveryMulticast}
            onChange={(e) => update('peerDiscoveryMulticast', e.target.value)}
          />
        )}
      </FormSection>
      <FormSection title="Upstream TLS / HTTP">
        <Input
          label="UPSTREAM_CA_CERT"
          value={form.upstreamCaCert}
          onChange={(e) => update('upstreamCaCert', e.target.value)}
          hint="Path to an extra CA bundle for upstream verification (corporate MITM chains)"
        />
        <Checkbox
          label="UPSTREAM_HTTP2_ENABLED"
          checked={form.upstreamHttp2Enabled}
          onChange={(v) => update('upstreamHttp2Enabled', v)}
        />
        <Checkbox
          label="HTTP_PRESERVE_HEADER_CASE"
          checked={form.preserveHeaderCase}
          onChange={(v) => update('preserveHeaderCase', v)}
        />
      </FormSection>
      <FormSection title="Encrypted DNS Gateways (Sinkhole)">
        <Checkbox
          label="DOH_ENABLED (DNS-over-HTTPS)"
          checked={form.dohEnabled}
          onChange={(v) => update('dohEnabled', v)}
        />
        {form.dohEnabled && (
          <Input label="DOH_BIND" value={form.dohBind} onChange={(e) => update('dohBind', e.target.value)} />
        )}
        <Checkbox
          label="DOT_ENABLED (DNS-over-TLS)"
          checked={form.dotEnabled}
          onChange={(v) => update('dotEnabled', v)}
        />
        {form.dotEnabled && (
          <Input label="DOT_BIND" value={form.dotBind} onChange={(e) => update('dotBind', e.target.value)} />
        )}
      </FormSection>
    </div>
  )
}
