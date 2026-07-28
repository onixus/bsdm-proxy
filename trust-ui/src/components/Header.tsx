import React from 'react';
import { Shield, CheckCircle2, ShieldCheck, Activity, AlertCircle, RefreshCw } from 'lucide-react';

interface HeaderProps {
  onRefresh: () => void;
  isRefreshing: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onRefresh, isRefreshing }) => {
  return (
    <header className="w-full px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4 border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-xl sticky top-0 z-50">
      {/* Top Left Logo & Brand */}
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
          <Shield className="w-7 h-7 stroke-[2.2]" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold text-white tracking-wide">BSDM PROXY</h1>
            <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              TRUST-UI
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Zero-Trust Security & MITM Control Plane</p>
        </div>
      </div>

      {/* Top Status Pill Bar (Matching exact mockup pill header) */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-slate-300">
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-400">Node:</span>
          <span className="font-mono font-medium text-slate-200">#030712</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="text-emerald-400 font-semibold text-[11px]">Connected</span>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-slate-300">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-slate-400">CASB:</span>
          <span className="text-emerald-400 font-semibold">DLP Active</span>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-slate-300">
          <Activity className="w-3.5 h-3.5 text-purple-400" />
          <span className="text-slate-400">Threat Inspection:</span>
          <span className="text-purple-400 font-semibold">Real-Time</span>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-slate-300">
          <AlertCircle className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-slate-400">Status:</span>
          <span className="text-emerald-400 font-bold">Low Risk</span>
        </div>

        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-semibold transition-all ml-1 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>Sync</span>
        </button>
      </div>
    </header>
  );
};
