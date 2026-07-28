import React, { useState, useEffect } from 'react';
import { Search, Activity } from 'lucide-react';
import { LiveTelemetryEvent, TelemetryStreamClient } from '../api/events';

const initialLogs: LiveTelemetryEvent[] = [
  {
    id: 'ev-101',
    timestamp: new Date().toLocaleTimeString(),
    clientIp: '10.240.1.45',
    upstream: 'https://api.github.com/user',
    trustScore: 95,
    action: 'ALLOWED',
    reason: 'mTLS validated, CA trusted',
  },
  {
    id: 'ev-102',
    timestamp: new Date(Date.now() - 3000).toLocaleTimeString(),
    clientIp: '192.168.1.112',
    upstream: 'https://malicious-telemetry.xyz/collect',
    trustScore: 12,
    action: 'SINKHOLED',
    reason: 'RPZ DNS Sinkhole triggered',
  },
  {
    id: 'ev-103',
    timestamp: new Date(Date.now() - 7000).toLocaleTimeString(),
    clientIp: '10.240.1.98',
    upstream: 'https://internal-s3.corp/bucket/keys.pem',
    trustScore: 45,
    action: 'BLOCKED',
    reason: 'CASB DLP rule: Aho-Corasick PEM Pattern',
  },
  {
    id: 'ev-104',
    timestamp: new Date(Date.now() - 12000).toLocaleTimeString(),
    clientIp: '10.240.2.14',
    upstream: 'https://httpbin.org/uuid',
    trustScore: 88,
    action: 'MITM_INSPECTED',
    reason: 'MITM TLS decrypted & validated',
  },
  {
    id: 'ev-105',
    timestamp: new Date(Date.now() - 18000).toLocaleTimeString(),
    clientIp: '172.16.4.80',
    upstream: 'http://c2-control.badsite.org',
    trustScore: 0,
    action: 'BLOCKED',
    reason: 'ML-Worker feature vector score > 0.85',
  },
];

export const ThreatStream: React.FC = () => {
  const [logs, setLogs] = useState<LiveTelemetryEvent[]>(initialLogs);
  const [filterAction, setFilterAction] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    const client = new TelemetryStreamClient();
    client.connect((newEvent) => {
      setLogs((prev) => [newEvent, ...prev.slice(0, 49)]);
    });

    // Simulated background live stream ticker for demo environment
    const interval = setInterval(() => {
      const actions: LiveTelemetryEvent['action'][] = ['ALLOWED', 'BLOCKED', 'MITM_INSPECTED', 'SINKHOLED'];
      const ips = ['10.240.1.55', '192.168.2.101', '172.16.8.22', '10.240.3.19'];
      const hosts = ['https://auth.internal.corp', 'https://telemetry.badactor.net', 'https://s3.amazonaws.com', 'http://udp-dns.rpz'];

      const randomAction = actions[Math.floor(Math.random() * actions.length)];
      const randomIp = ips[Math.floor(Math.random() * ips.length)];
      const randomHost = hosts[Math.floor(Math.random() * hosts.length)];

      const generatedEvent: LiveTelemetryEvent = {
        id: `ev-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        clientIp: randomIp,
        upstream: randomHost,
        trustScore: randomAction === 'ALLOWED' ? 96 : randomAction === 'BLOCKED' ? 24 : 70,
        action: randomAction,
        reason: randomAction === 'ALLOWED' ? 'Session trusted' : 'Rule violation detected',
      };

      setLogs((prev) => [generatedEvent, ...prev.slice(0, 49)]);
    }, 4000);

    return () => {
      client.disconnect();
      clearInterval(interval);
    };
  }, []);

  const filteredLogs = logs.filter((log) => {
    const matchesAction = filterAction === 'ALL' || log.action === filterAction;
    const matchesQuery =
      log.clientIp.includes(searchQuery) ||
      log.upstream.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.reason.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesAction && matchesQuery;
  });

  const getActionBadge = (action: LiveTelemetryEvent['action']) => {
    switch (action) {
      case 'ALLOWED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">ALLOWED</span>;
      case 'MITM_INSPECTED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">MITM</span>;
      case 'BLOCKED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">BLOCKED</span>;
      case 'SINKHOLED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30">SINKHOLED</span>;
    }
  };

  return (
    <div className="cyber-card p-6 h-full flex flex-col justify-between">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-cyan-400 animate-pulse" />
          <h3 className="text-base font-bold text-white">Live Telemetry Threat Stream</h3>
        </div>

        {/* Filter and Search Bar */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP / Host"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 w-36"
            />
          </div>

          <div className="flex items-center rounded-xl bg-slate-900 border border-slate-800 p-1 text-[11px]">
            {['ALL', 'ALLOWED', 'BLOCKED', 'SINKHOLED'].map((act) => (
              <button
                key={act}
                onClick={() => setFilterAction(act)}
                className={`px-2 py-0.5 rounded-lg transition-colors font-medium ${
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

      {/* Table header */}
      <div className="grid grid-cols-12 gap-2 text-[11px] font-semibold text-slate-400 border-b border-slate-800/80 pb-2 px-2">
        <div className="col-span-3">Time / IP</div>
        <div className="col-span-5">Upstream Target</div>
        <div className="col-span-2">Action</div>
        <div className="col-span-2 text-right">Trust</div>
      </div>

      {/* Rows */}
      <div className="divide-y divide-slate-800/50 my-1 max-h-[340px] overflow-y-auto pr-1">
        {filteredLogs.map((item) => (
          <div key={item.id} className="grid grid-cols-12 gap-2 items-center py-2.5 px-2 hover:bg-slate-900/40 rounded-lg transition-colors text-xs font-mono">
            <div className="col-span-3">
              <p className="font-semibold text-cyan-400">{item.clientIp}</p>
              <p className="text-[10px] text-slate-500 font-sans">{item.timestamp}</p>
            </div>
            <div className="col-span-5 text-slate-200 truncate text-[11px]" title={item.upstream}>
              {item.upstream}
            </div>
            <div className="col-span-2">{getActionBadge(item.action)}</div>
            <div className="col-span-2 text-right font-bold">
              <span className={item.trustScore >= 80 ? 'text-emerald-400' : 'text-rose-400'}>
                {item.trustScore}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
