import { Laptop, Smartphone, Server, Key, UserCheck } from 'lucide-react';

interface DeviceInfo {
  id: string;
  name: string;
  type: 'laptop' | 'mobile' | 'server';
  owner: string;
  certIssuer: string;
  trustScore: number;
  lastActive: string;
  status: 'COMPLIANT' | 'FLAGGED' | 'REVOKED';
}

const mockDevices: DeviceInfo[] = [
  {
    id: 'dev-01',
    name: 'MacBook-Pro-SecOps',
    type: 'laptop',
    owner: 'admin@bsdm.internal',
    certIssuer: 'BSDM Local MITM Root CA',
    trustScore: 98,
    lastActive: 'Just now',
    status: 'COMPLIANT',
  },
  {
    id: 'dev-02',
    name: 'Workstation-Dev-04',
    type: 'laptop',
    owner: 'developer-04@bsdm.internal',
    certIssuer: 'BSDM Local MITM Root CA',
    trustScore: 85,
    lastActive: '3 min ago',
    status: 'COMPLIANT',
  },
  {
    id: 'dev-03',
    name: 'Prod-Cache-Indexer-01',
    type: 'server',
    owner: 'system-service',
    certIssuer: 'Internal mTLS Peer CA',
    trustScore: 100,
    lastActive: '12 sec ago',
    status: 'COMPLIANT',
  },
  {
    id: 'dev-04',
    name: 'Mobile-BYOD-Android',
    type: 'mobile',
    owner: 'guest-user@bsdm.internal',
    certIssuer: 'Self-Signed / Untrusted',
    trustScore: 32,
    lastActive: '15 min ago',
    status: 'FLAGGED',
  },
];

export const DeviceIdentity: React.FC = () => {
  const getDeviceIcon = (type: DeviceInfo['type']) => {
    switch (type) {
      case 'laptop':
        return <Laptop className="w-4 h-4 text-cyan-400" />;
      case 'mobile':
        return <Smartphone className="w-4 h-4 text-purple-400" />;
      case 'server':
        return <Server className="w-4 h-4 text-emerald-400" />;
    }
  };

  return (
    <div className="glass-panel glass-panel-hover rounded-2xl p-6 relative">
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="flex items-center gap-2">
            <UserCheck className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white">Identity & Device Trust Registry</h2>
          </div>
          <p className="text-xs text-slate-400">Authenticated client certificates & device posture</p>
        </div>
        <span className="text-xs font-mono text-cyan-400 font-semibold px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
          4 REGISTERED ENDPOINTS
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {mockDevices.map((dev) => (
          <div
            key={dev.id}
            className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-all flex items-start justify-between gap-3"
          >
            <div className="flex items-start gap-3">
              <div className="p-2.5 rounded-lg bg-slate-800/90 border border-slate-700 mt-0.5">
                {getDeviceIcon(dev.type)}
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h4 className="text-xs font-bold text-white">{dev.name}</h4>
                  <span
                    className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                      dev.status === 'COMPLIANT'
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                    }`}
                  >
                    {dev.status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-mono">{dev.owner}</p>
                <div className="flex items-center gap-1 text-[10px] text-slate-500">
                  <Key className="w-3 h-3 text-slate-500" />
                  <span>{dev.certIssuer}</span>
                </div>
              </div>
            </div>

            <div className="text-right">
              <span className="text-xs font-bold text-slate-400 font-mono">Score</span>
              <p
                className={`text-lg font-extrabold font-mono ${
                  dev.trustScore >= 80 ? 'text-emerald-400' : 'text-rose-400'
                }`}
              >
                {dev.trustScore}
              </p>
              <span className="text-[10px] text-slate-500">{dev.lastActive}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
