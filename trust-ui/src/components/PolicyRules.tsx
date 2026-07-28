import { useState } from 'react';
import { Sliders } from 'lucide-react';

interface PolicyRule {
  id: string;
  name: string;
  category: string;
  description: string;
  enabled: boolean;
  strictness: 'High' | 'Medium' | 'Low';
}

export const PolicyRules: React.FC = () => {
  const [rules, setRules] = useState<PolicyRule[]>([
    {
      id: 'rule-mtls',
      name: 'Upstream mTLS & Peer CA Verification',
      category: 'TLS & MITM',
      description: 'Enforce strict TLS validation against internal CA bundle (ca.crt)',
      enabled: true,
      strictness: 'High',
    },
    {
      id: 'rule-casb-dlp',
      name: 'CASB Aho-Corasick DLP Inspection',
      category: 'Data Protection',
      description: 'Scan POST/PUT HTTP request bodies for secret keys & sensitive data patterns',
      enabled: true,
      strictness: 'High',
    },
    {
      id: 'rule-ml-worker',
      name: 'ML-Worker Real-Time Vector Scoring',
      category: 'AI Anomaly Detection',
      description: 'Flag anomalous network session behavior via Kafka feature-store stream',
      enabled: true,
      strictness: 'Medium',
    },
    {
      id: 'rule-rpz-sinkhole',
      name: 'DNS RPZ-lite UDP Sinkhole',
      category: 'DNS Security',
      description: 'Redirect blacklisted domain queries to internal 127.0.0.1 sinkhole target',
      enabled: true,
      strictness: 'High',
    },
  ]);

  const toggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  return (
    <div className="glass-panel glass-panel-hover rounded-2xl p-6 relative">
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white">Zero-Trust Policy Enforcement Rules</h2>
          </div>
          <p className="text-xs text-slate-400">Configure active BSDM proxy security controls</p>
        </div>
        <span className="text-xs text-emerald-400 font-semibold px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
          {rules.filter((r) => r.enabled).length}/{rules.length} ACTIVE
        </span>
      </div>

      <div className="space-y-3">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className={`p-4 rounded-xl border transition-all flex items-start justify-between gap-4 ${
              rule.enabled
                ? 'bg-slate-900/80 border-slate-800'
                : 'bg-slate-950/40 border-slate-900 opacity-60'
            }`}
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-slate-200">{rule.name}</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-medium">
                  {rule.category}
                </span>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                    rule.strictness === 'High'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                  }`}
                >
                  {rule.strictness} Strictness
                </span>
              </div>
              <p className="text-xs text-slate-400">{rule.description}</p>
            </div>

            <button
              onClick={() => toggleRule(rule.id)}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                rule.enabled ? 'bg-cyan-500' : 'bg-slate-800'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  rule.enabled ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};
