import { Lock, FileSearch, ShieldOff, CheckCircle2, Cpu } from 'lucide-react';

interface MetricItem {
  title: string;
  value: string;
  subtext: string;
  icon: React.ElementType;
  trend: string;
  statusColor: string;
}

export const PostureMetrics: React.FC = () => {
  const metrics: MetricItem[] = [
    {
      title: 'mTLS Handshake Validation',
      value: '99.98%',
      subtext: 'Upstream & Peer CA Certs Verified',
      icon: Lock,
      trend: '+0.02%',
      statusColor: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10',
    },
    {
      title: 'Inline CASB DLP Inspections',
      value: '14,892',
      subtext: 'Aho-Corasick Regex Blocks Executed',
      icon: FileSearch,
      trend: '12 blocked',
      statusColor: 'text-cyan-400 border-cyan-500/20 bg-cyan-500/10',
    },
    {
      title: 'ML-Worker Threat Score',
      value: '0.041',
      subtext: 'Feature Store Anomaly Vector Index',
      icon: Cpu,
      trend: 'Low Risk',
      statusColor: 'text-blue-400 border-blue-500/20 bg-blue-500/10',
    },
    {
      title: 'RPZ Sinkhole Neutralized',
      value: '348',
      subtext: 'UDP Malicious Domain Intercepts',
      icon: ShieldOff,
      trend: 'Active Filter',
      statusColor: 'text-purple-400 border-purple-500/20 bg-purple-500/10',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {metrics.map((item, idx) => {
        const Icon = item.icon;
        return (
          <div
            key={idx}
            className="glass-panel glass-panel-hover rounded-2xl p-5 relative overflow-hidden flex flex-col justify-between"
          >
            <div className="flex items-center justify-between mb-3">
              <span className={`p-2.5 rounded-xl border ${item.statusColor}`}>
                <Icon className="w-5 h-5" />
              </span>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-md bg-slate-800 text-slate-400 border border-slate-700">
                {item.trend}
              </span>
            </div>

            <div>
              <p className="text-xs font-medium text-slate-400 mb-1">{item.title}</p>
              <h3 className="text-2xl font-extrabold text-white tracking-tight font-mono">{item.value}</h3>
              <p className="text-[11px] text-slate-500 mt-1 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                {item.subtext}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
};
