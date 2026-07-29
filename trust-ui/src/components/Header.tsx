import { Activity, RefreshCw, Shield } from 'lucide-react';

interface HeaderProps {
  onRefresh: () => void;
  isRefreshing: boolean;
  connected: boolean;
  service?: string;
  requestsInFlight?: number;
}

export const Header: React.FC<HeaderProps> = ({
  onRefresh,
  isRefreshing,
  connected,
  service,
  requestsInFlight,
}) => (
  <header className="w-full px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4 border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-xl sticky top-0 z-50">
    <div className="flex items-center gap-3">
      <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
        <Shield className="w-7 h-7 stroke-[2.2]" />
      </div>
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-lg font-bold text-white tracking-wide">BSDM PROXY</h1>
          <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            TRUST-UI
          </span>
        </div>
        <p className="text-[11px] text-slate-400">Live Zero-Trust telemetry</p>
      </div>
    </div>

    <div className="flex flex-wrap items-center gap-2 text-xs">
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800">
        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400' : 'bg-rose-400'}`} />
        <span className={connected ? 'text-emerald-400' : 'text-rose-400'}>
          {connected ? service ?? 'Connected' : 'Backend unavailable'}
        </span>
      </div>
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-slate-300">
        <Activity className="w-3.5 h-3.5 text-purple-400" />
        <span className="text-slate-400">In flight:</span>
        <span className="font-mono">{requestsInFlight ?? '—'}</span>
      </div>
      <button
        onClick={onRefresh}
        disabled={isRefreshing}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-semibold disabled:opacity-50"
      >
        <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
        <span>Sync</span>
      </button>
    </div>
  </header>
);
