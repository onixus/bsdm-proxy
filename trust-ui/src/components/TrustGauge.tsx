import { ShieldCheck, Zap, AlertTriangle } from 'lucide-react';

interface TrustGaugeProps {
  score: number;
  threatLevel: 'Low' | 'Medium' | 'High';
  verifiedSessions: number;
  flaggedSessions: number;
}

export const TrustGauge: React.FC<TrustGaugeProps> = ({
  score,
  threatLevel,
  verifiedSessions,
  flaggedSessions,
}) => {
  // Calculate SVG stroke offset for gauge meter
  const radius = 68;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getScoreColor = (val: number) => {
    if (val >= 80) return { text: 'text-emerald-400', stroke: '#10b981', bg: 'from-emerald-500/10' };
    if (val >= 50) return { text: 'text-amber-400', stroke: '#f59e0b', bg: 'from-amber-500/10' };
    return { text: 'text-rose-400', stroke: '#f43f5e', bg: 'from-rose-500/10' };
  };

  const colors = getScoreColor(score);

  return (
    <div className="glass-panel glass-panel-hover rounded-2xl p-6 relative overflow-hidden flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Overall Trust Score</h2>
          <p className="text-xs text-slate-500">Real-time composite security index</p>
        </div>
        <span
          className={`px-3 py-1 text-xs font-bold rounded-full border ${
            threatLevel === 'Low'
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              : threatLevel === 'Medium'
              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
              : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
          }`}
        >
          {threatLevel.toUpperCase()} RISK
        </span>
      </div>

      <div className="flex flex-col md:flex-row items-center justify-around my-2 gap-6">
        {/* Radial Circular Gauge */}
        <div className="relative w-44 h-44 flex items-center justify-center">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
            <circle
              cx="80"
              cy="80"
              r={radius}
              stroke="currentColor"
              strokeWidth="12"
              className="text-slate-800/80"
              fill="transparent"
            />
            <circle
              cx="80"
              cy="80"
              r={radius}
              stroke={colors.stroke}
              strokeWidth="12"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className={`text-4xl font-extrabold tracking-tight ${colors.text}`}>{score}</span>
            <span className="text-[10px] uppercase font-bold text-slate-400 mt-0.5">out of 100</span>
          </div>
        </div>

        {/* Quick Stats Grid */}
        <div className="flex-1 space-y-3 w-full">
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span className="text-xs text-slate-300 font-medium">Verified Sessions</span>
            </div>
            <span className="font-mono text-sm font-bold text-emerald-400">{verifiedSessions}</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span className="text-xs text-slate-300 font-medium">Flagged Anomalies</span>
            </div>
            <span className="font-mono text-sm font-bold text-amber-400">{flaggedSessions}</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span className="text-xs text-slate-300 font-medium">ML Score Sync</span>
            </div>
            <span className="font-mono text-xs text-cyan-400 font-semibold">0.02ms latency</span>
          </div>
        </div>
      </div>
    </div>
  );
};
