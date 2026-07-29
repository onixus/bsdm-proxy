import { Activity, Clock3, Database, ShieldCheck } from 'lucide-react';
import type { ProxyMetrics, ProxyStats } from '../api/client';

interface TrustHeroSectionProps {
  connected: boolean;
  stats?: ProxyStats;
  metrics?: ProxyMetrics;
}

function formatUptime(seconds?: number): string {
  if (seconds === undefined) return '—';
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  return [days ? `${days}d` : '', hours ? `${hours}h` : '', `${minutes}m`].filter(Boolean).join(' ');
}

export const TrustHeroSection: React.FC<TrustHeroSectionProps> = ({
  connected,
  stats,
  metrics,
}) => {
  const facts = [
    {
      label: 'Node status',
      value: connected ? 'Connected' : 'Unavailable',
      icon: ShieldCheck,
      color: connected ? 'text-emerald-400' : 'text-rose-400',
    },
    {
      label: 'Uptime',
      value: formatUptime(stats?.uptime_secs),
      icon: Clock3,
      color: 'text-cyan-400',
    },
    {
      label: 'Observed requests',
      value: metrics?.totalRequests.toLocaleString() ?? '—',
      icon: Activity,
      color: 'text-cyan-400',
    },
    {
      label: 'Cache entries',
      value: stats?.cache.entries.toLocaleString() ?? '—',
      icon: Database,
      color: 'text-purple-400',
    },
  ];

  return (
    <div className="cyber-card p-8 relative overflow-hidden">
      <div className="relative">
        <p className="text-xs uppercase font-semibold text-cyan-400 tracking-[0.2em]">
          Live node telemetry
        </p>
        <h2 className="text-2xl font-bold text-white mt-2">Observed security posture</h2>
        <p className="text-sm text-slate-400 mt-2 max-w-3xl">
          Values below come directly from the proxy health, stats, and Prometheus endpoints.
          No synthetic trust score is calculated.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-7">
          {facts.map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="rounded-2xl bg-slate-950/50 border border-slate-800 p-5">
              <Icon className={`w-5 h-5 ${color}`} />
              <p className="text-xs text-slate-400 mt-4">{label}</p>
              <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
