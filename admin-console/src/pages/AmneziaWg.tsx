import { useState } from 'react'
import { ShieldCheck, ShieldAlert, Plus, Download, Key, RefreshCw, Cpu, Smartphone } from 'lucide-react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { fetchAwgStatus, updateAwgConfig, addAwgPeer, type AwgServerConfig, type AwgPeerConfig } from '../api/amneziawg'
import { Panel } from '../components/dashboard/MetricWidget'
import { Button } from '../components/ui/Button'
import { FormGrid, FormSection, Input, Checkbox } from '../components/ui/Form'
import { CodePreview, Modal } from '../components/ui/Modal'
import { useToast } from '../components/ui/Toast'

export function AmneziaWgPage() {
  const { data: sourcedData, isLoading, refetch } = useQuery({ queryKey: ['amneziawgStatus'], queryFn: fetchAwgStatus })
  const mutation = useMutation({ mutationFn: updateAwgConfig, onSuccess: () => refetch() })
  const addPeerMutation = useMutation({ mutationFn: addAwgPeer, onSuccess: () => refetch() })
  
  const { toast } = useToast()
  
  const [formState, setFormState] = useState<AwgServerConfig | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [showConfigModal, setShowConfigModal] = useState<AwgPeerConfig | null>(null)
  const [newPeerName, setNewPeerName] = useState('')

  const serverConfig = sourcedData?.data || null
  const activeConfig = formState || serverConfig

  if (isLoading || !activeConfig) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400">
        <RefreshCw className="w-6 h-6 animate-spin mr-2" />
        Loading AmneziaWG Endpoint Status...
      </div>
    )
  }

  const handleSaveObfuscation = async () => {
    try {
      await mutation.mutateAsync(activeConfig)
      toast('success', 'AmneziaWG obfuscation parameters updated successfully!')
      refetch()
    } catch {
      toast('error', 'Failed to save AmneziaWG configuration')
    }
  }

  const handleAddPeer = async () => {
    if (!newPeerName.trim()) return
    const id = `peer-${Date.now().toString().slice(-4)}`
    const ipLastOctet = (activeConfig.peers.length + 2).toString()
    const newPeer: AwgPeerConfig = {
      id,
      name: newPeerName,
      public_key: `awg_pub_${Math.random().toString(36).substring(2, 12)}...`,
      private_key: `awg_priv_${Math.random().toString(36).substring(2, 12)}...`,
      assigned_ip: `10.8.0.${ipLastOctet}`,
      allowed_ips: `10.8.0.${ipLastOctet}/32`,
      created_at: new Date().toISOString().split('T')[0],
    }

    try {
      await addPeerMutation.mutateAsync(newPeer)
      toast('success', `Added peer ${newPeer.name}`)
      setShowAddModal(false)
      setNewPeerName('')
      setShowConfigModal(newPeer)
      refetch()
    } catch {
      toast('error', 'Failed to add AmneziaWG peer')
    }
  }

  const generateConfText = (peer: AwgPeerConfig) => {
    return `[Interface]
PrivateKey = ${peer.private_key || 'CLIENT_PRIVATE_KEY'}
Address = ${peer.assigned_ip}/32
DNS = 1.1.1.1, 8.8.8.8
Jc = ${activeConfig.obfuscation.jc}
Jmin = ${activeConfig.obfuscation.jmin}
Jmax = ${activeConfig.obfuscation.jmax}
S1 = ${activeConfig.obfuscation.s1}
S2 = ${activeConfig.obfuscation.s2}
H1 = ${activeConfig.obfuscation.h1}
H2 = ${activeConfig.obfuscation.h2}
H3 = ${activeConfig.obfuscation.h3}
H4 = ${activeConfig.obfuscation.h4}

[Peer]
PublicKey = ${activeConfig.public_key}
Endpoint = proxy.corp.internal:${activeConfig.listen_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25`
  }

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Metrics */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100">AmneziaWG Endpoint & BSDM Connect</h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              DPI-Resistant Obfuscation
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Obfuscated WireGuard tunnel endpoint providing anti-censorship access for remote BSDM Connect clients.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="secondary" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button variant="primary" onClick={() => setShowAddModal(true)}>
            <Plus className="w-4 h-4 mr-2" />
            Add Client Peer
          </Button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Panel title="Service Status">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {activeConfig.enabled ? (
                <ShieldCheck className="w-6 h-6 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-6 h-6 text-amber-400" />
              )}
              <span className="text-lg font-semibold text-slate-100">
                {activeConfig.enabled ? 'Active (Listening)' : 'Disabled'}
              </span>
            </div>
            <span className="text-xs text-slate-400 font-mono">UDP :{activeConfig.listen_port}</span>
          </div>
        </Panel>

        <Panel title="Active Peers">
          <div className="flex items-center gap-3">
            <Smartphone className="w-6 h-6 text-indigo-400" />
            <span className="text-2xl font-bold text-slate-100">{activeConfig.peers.length}</span>
            <span className="text-xs text-slate-400">clients connected</span>
          </div>
        </Panel>

        <Panel title="Obfuscation Profile">
          <div className="flex items-center gap-3">
            <Cpu className="w-6 h-6 text-cyan-400" />
            <div>
              <div className="text-sm font-semibold text-slate-200">Header H1: {activeConfig.obfuscation.h1}</div>
              <div className="text-xs text-slate-400">Jc: {activeConfig.obfuscation.jc} junk pkts</div>
            </div>
          </div>
        </Panel>

        <Panel title="Subnet Allocation">
          <div className="flex items-center gap-3">
            <Key className="w-6 h-6 text-purple-400" />
            <div>
              <div className="text-sm font-mono text-slate-200">{activeConfig.address}</div>
              <div className="text-xs text-slate-400">Virtual Interface (awg0)</div>
            </div>
          </div>
        </Panel>
      </div>

      {/* Obfuscation Settings Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Obfuscation Parameters (DPI Bypass)</h2>
            <p className="text-xs text-slate-400">
              Customize junk packet counts and custom magic headers to evade Deep Packet Inspection fingerprinting.
            </p>
          </div>
          <Button variant="primary" onClick={handleSaveObfuscation}>
            Save Parameters
          </Button>
        </div>

        <FormSection title="Core Settings">
          <FormGrid>
            <Checkbox
              label="Enable AmneziaWG Endpoint"
              checked={activeConfig.enabled}
              onChange={(checked) =>
                setFormState({ ...activeConfig, enabled: checked })
              }
            />
            <Input
              label="Listen Port (UDP)"
              value={activeConfig.listen_port.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  listen_port: parseInt(e.target.value) || 51820,
                })
              }
            />
            <Input
              label="VPN Subnet"
              value={activeConfig.address}
              onChange={(e) =>
                setFormState({ ...activeConfig, address: e.target.value })
              }
            />
          </FormGrid>
        </FormSection>

        <FormSection title="Junk Packets & Padding (Jc / S1 / S2)">
          <FormGrid>
            <Input
              label="Junk Packet Count (Jc)"
              value={activeConfig.obfuscation.jc.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    jc: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
            <Input
              label="Min Junk Size (Jmin)"
              value={activeConfig.obfuscation.jmin.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    jmin: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
            <Input
              label="Max Junk Size (Jmax)"
              value={activeConfig.obfuscation.jmax.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    jmax: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
            <Input
              label="Init Padding Size (S1)"
              value={activeConfig.obfuscation.s1.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    s1: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
            <Input
              label="Response Padding Size (S2)"
              value={activeConfig.obfuscation.s2.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    s2: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
          </FormGrid>
        </FormSection>

        <FormSection title="Custom Packet Headers (H1 – H4 Magic Bytes)">
          <FormGrid>
            <Input
              label="Handshake Init (H1)"
              value={activeConfig.obfuscation.h1.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    h1: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
            <Input
              label="Handshake Resp (H2)"
              value={activeConfig.obfuscation.h2.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    h2: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
            <Input
              label="Cookie Reply (H3)"
              value={activeConfig.obfuscation.h3.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    h3: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
            <Input
              label="Transport Data (H4)"
              value={activeConfig.obfuscation.h4.toString()}
              onChange={(e) =>
                setFormState({
                  ...activeConfig,
                  obfuscation: {
                    ...activeConfig.obfuscation,
                    h4: parseInt(e.target.value) || 0,
                  },
                })
              }
            />
          </FormGrid>
        </FormSection>
      </div>

      {/* Peers Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-semibold text-slate-100">Provisioned Client Peers</h3>
          <span className="text-xs text-slate-400">{activeConfig.peers.length} configured</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950 text-slate-400 uppercase text-xs">
              <tr>
                <th className="px-4 py-3">Client Name</th>
                <th className="px-4 py-3">Assigned IP</th>
                <th className="px-4 py-3">Public Key</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {activeConfig.peers.map((peer: AwgPeerConfig) => (
                <tr key={peer.id} className="hover:bg-slate-800/50">
                  <td className="px-4 py-3 font-medium text-slate-100 flex items-center gap-2">
                    <Smartphone className="w-4 h-4 text-slate-400" />
                    {peer.name}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-emerald-400">{peer.assigned_ip}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">{peer.public_key}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">{peer.created_at}</td>
                  <td className="px-4 py-3 text-right space-x-2">
                    <Button
                      variant="secondary"
                      onClick={() => setShowConfigModal(peer)}
                    >
                      <Download className="w-3.5 h-3.5 mr-1" />
                      Get Config
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Peer Modal */}
      <Modal
        open={showAddModal}
        title="Add New AmneziaWG Client Peer"
        onClose={() => setShowAddModal(false)}
      >
        <div className="space-y-4">
          <Input
            label="Client Name / Device Description"
            placeholder="e.g. CEO Mobile Device"
            value={newPeerName}
            onChange={(e) => setNewPeerName(e.target.value)}
          />
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setShowAddModal(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleAddPeer}>
              Generate Client Credentials
            </Button>
          </div>
        </div>
      </Modal>

      {/* View Config Modal */}
      <Modal
        open={Boolean(showConfigModal)}
        title={`AmneziaWG Config: ${showConfigModal?.name || ''}`}
        onClose={() => setShowConfigModal(null)}
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-400">
            Download or copy this configuration into the official AmneziaWG application (iOS, Android, Windows, macOS).
          </p>
          {showConfigModal && (
            <CodePreview content={generateConfText(showConfigModal)} />
          )}
          <div className="flex justify-end pt-2">
            <Button variant="primary" onClick={() => setShowConfigModal(null)}>
              Close
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
