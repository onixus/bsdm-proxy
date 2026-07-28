import React from 'react';

interface PostureMetricsProps {
  metrics?: {
    casbDlpBlocks?: number;
    rpzSinkholeBlocks?: number;
  };
}

export const PostureMetrics: React.FC<PostureMetricsProps> = ({ metrics }) => {
  const casbBlocks = metrics?.casbDlpBlocks ?? 348;
  const rpzBlocks = metrics?.rpzSinkholeBlocks ?? 3913;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
      {/* Card 1: mTLS Validation */}
      <div className="cyber-card cyber-card-hover p-6 flex flex-col justify-between h-48">
        <div>
          <h3 className="text-sm font-medium text-slate-300">mTLS Validation</h3>
          <p className="text-3xl font-extrabold text-cyan-400 mt-4 tracking-tight drop-shadow-[0_0_15px_rgba(6,182,212,0.3)]">
            Active
          </p>
        </div>
        <div>
          <span className="text-[11px] font-medium text-slate-400">Status</span>
          <div className="w-full bg-slate-900 h-2 rounded-full mt-1.5 overflow-hidden border border-slate-800">
            <div className="bg-cyan-400 h-full rounded-full w-[85%] bar-glow-cyan"></div>
          </div>
          <span className="text-[10px] text-cyan-400 font-semibold mt-1 inline-block">Active</span>
        </div>
      </div>

      {/* Card 2: CASB DLP Inspections */}
      <div className="cyber-card cyber-card-hover p-6 flex flex-col justify-between h-48">
        <div>
          <h3 className="text-sm font-medium text-slate-300">CASB DLP Inspections</h3>
          <p className="text-3xl font-extrabold text-emerald-400 mt-4 tracking-tight drop-shadow-[0_0_15px_rgba(16,185,129,0.3)]">
            Secure ({casbBlocks})
          </p>
        </div>
        <div>
          <span className="text-[11px] font-medium text-slate-400">Rating</span>
          <div className="w-full bg-slate-900 h-2 rounded-full mt-1.5 overflow-hidden border border-slate-800">
            <div className="bg-emerald-400 h-full rounded-full w-[92%] bar-glow-emerald"></div>
          </div>
          <span className="text-[10px] text-emerald-400 font-semibold mt-1 inline-block">Secure</span>
        </div>
      </div>

      {/* Card 3: ML-Worker Threat Score */}
      <div className="cyber-card cyber-card-hover p-6 flex flex-col justify-between h-48">
        <div>
          <h3 className="text-sm font-medium text-slate-300">ML-Worker Threat Score</h3>
          <p className="text-3xl font-extrabold text-emerald-400 mt-4 tracking-tight">
            Low Risk
          </p>
        </div>
        <div>
          <span className="text-[11px] font-medium text-slate-400">Rating</span>
          <div className="w-full bg-slate-900 h-2 rounded-full mt-1.5 overflow-hidden flex gap-1 p-0.5 border border-slate-800">
            <div className="bg-emerald-400 h-full rounded-sm w-[35%]"></div>
            <div className="bg-slate-800 h-full rounded-sm w-[35%]"></div>
            <div className="bg-slate-800 h-full rounded-sm w-[30%]"></div>
          </div>
          <div className="flex justify-between text-[10px] text-slate-400 mt-1">
            <span>Risk</span>
            <span>High</span>
          </div>
        </div>
      </div>

      {/* Card 4: RPZ Sinkhole */}
      <div className="cyber-card cyber-card-hover p-6 flex flex-col justify-between h-48">
        <div>
          <h3 className="text-sm font-medium text-slate-300">RPZ Sinkhole</h3>
          <p className="text-3xl font-extrabold text-rose-400 mt-4 tracking-tight drop-shadow-[0_0_15px_rgba(244,63,94,0.3)]">
            {rpzBlocks}
          </p>
        </div>
        <div className="space-y-1 text-xs border-t border-slate-800/80 pt-2">
          <div className="flex justify-between text-slate-400">
            <span>RPZ Sinkhole</span>
            <span className="font-mono text-slate-200 font-bold">20</span>
          </div>
          <div className="flex justify-between text-slate-400">
            <span>Total Sinkhole</span>
            <span className="font-mono text-slate-200 font-bold">33</span>
          </div>
        </div>
      </div>
    </div>
  );
};
