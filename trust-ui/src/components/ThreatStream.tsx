import { useState } from 'react';
import { Activity, Search } from 'lucide-react';

export interface ThreatLog {
  id: string;
  timestamp: string;
  clientIp: string;
  upstream: string;
  trustScore: number;
  action: 'ALLOWED' | 'BLOCKED' | 'MITM_INSPECTED' | 'SINKHOLED';
  reason: string;
}

const mockLogs: ThreatLog[] = [
  {
    id: 'log-101',
    timestamp: '14:49:12.890',
    clientIp: '10.240.1.45',
    upstream: 'https://api.github.com/user',
    trustScore: 95,
    action: 'ALLOWED',
    reason: 'mTLS validated, CA trusted',
  },
  {
    id: 'log-102',
    timestamp: '14:49:10.421',
    clientIp: '192.168.1.112',
    upstream: 'https://malicious-telemetry.xyz/collect',
    trustScore: 12,
    action: 'SINKHOLED',
    reason: 'RPZ DNS Sinkhole triggered',
  },
  {
    id: 'log-103',
    timestamp: '14:49:05.105',
    clientIp: '10.240.1.98',
    upstream: 'https://internal-s3.corp/bucket/keys.pem',
    trustScore: 45,
    action: 'BLOCKED',
    reason: 'CASB DLP rule: Aho-Corasick PEM Pattern',
  },
  {
    id: 'log-104',
    timestamp: '14:48:58.732',
    clientIp: '10.240.2.14',
    upstream: 'https://httpbin.org/uuid',
    trustScore: 88,
    action: 'MITM_INSPECTED',
    reason: 'MITM TLS decrypted & validated',
  },
  {
    id: 'log-105',
    timestamp: '14:48:42.199',
    clientIp: '172.16.4.80',
    upstream: 'http://c2-control.badsite.org',
    trustScore: 0,
    action: 'BLOCKED',
    reason: 'ML-Worker feature vector score > 0.85',
  },
];

export const ThreatStream: React.FC = () => {
  const [filterAction, setFilterAction] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredLogs = mockLogs.filter((log) => {
    const matchesAction = filterAction === 'ALL' || log.action === filterAction;
    const matchesQuery =
      log.clientIp.includes(searchQuery) ||
      log.upstream.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.reason.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesAction && matchesQuery;
  });

  const getBadgeStyle = (action: ThreatLog['action']) => {
    switch (action) {
      case 'ALLOWED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'MITM_INSPECTED':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      case 'BLOCKED':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'SINKHOLED':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
    }
  };

  return (
    <div className="glass-panel glass-panel-hover rounded-2xl p-6 relative flex flex-col justify-between">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white">Live Telemetry & Threat Stream</h2>
          </div>
          <p className="text-xs text-slate-400">Real-time BSDM proxy traffic & decision logging</p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, host, or rule..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 w-44"
            />
          </div>

          <div className="flex items-center rounded-lg bg-slate-900/90 border border-slate-800 p-1 text-xs">
            {['ALL', 'ALLOWED', 'BLOCKED', 'SINKHOLED'].map((act) => (
              <button
                key={act}
                onClick={() => setFilterAction(act)}
                className={`px-2.5 py-1 rounded-md transition-colors font-medium text-[11px] ${
                  filterAction === act
                    ? 'bg-cyan-500 text-slate-950 font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {act}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Log Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800/80 bg-slate-950/60">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Time</th>
              <th className="py-3 px-4">Client IP</th>
              <th className="py-3 px-4">Target Upstream</th>
              <th className="py-3 px-4">Trust Score</th>
              <th className="py-3 px-4">Action</th>
              <th className="py-3 px-4">Enforcement Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50 font-mono">
            {filteredLogs.map((log) => (
              <tr key={log.id} className="hover:bg-slate-900/40 transition-colors">
                <td className="py-3 px-4 text-slate-500 font-sans text-[11px]">{log.timestamp}</td>
                <td className="py-3 px-4 text-cyan-400 font-semibold">{log.clientIp}</td>
                <td className="py-3 px-4 text-slate-200 truncate max-w-[200px]" title={log.upstream}>
                  {log.upstream}
                </td>
                <td className="py-3 px-4">
                  <span
                    className={`font-bold ${
                      log.trustScore >= 80
                        ? 'text-emerald-400'
                        : log.trustScore >= 50
                        ? 'text-amber-400'
                        : 'text-rose-400'
                    }`}
                  >
                    {log.trustScore}/100
                  </span>
                </td>
                <td className="py-3 px-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getBadgeStyle(log.action)}`}>
                    {log.action}
                  </span>
                </td>
                <td className="py-3 px-4 text-slate-400 font-sans text-xs">{log.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
