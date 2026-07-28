import React, { useState } from 'react';

interface TrustHeroSectionProps {
  score: number;
}

interface PolicyToggle {
  id: string;
  label: string;
  enabled: boolean;
}

export const TrustHeroSection: React.FC<TrustHeroSectionProps> = ({ score }) => {
  const [toggles, setToggles] = useState<PolicyToggle[]>([
    { id: '1', label: 'mTLS Validation', enabled: true },
    { id: '2', label: 'Security Policy', enabled: true },
    { id: '3', label: 'Security Policy', enabled: true },
    { id: '4', label: 'Protection Policy', enabled: false },
    { id: '5', label: 'Security Policy', enabled: true },
    { id: '6', label: 'Security Policy', enabled: true },
    { id: '7', label: 'Security Policy', enabled: false },
    { id: '8', label: 'Security Policy', enabled: false },
  ]);

  const handleToggle = (id: string) => {
    setToggles((prev) =>
      prev.map((t) => (t.id === id ? { ...t, enabled: !t.enabled } : t))
    );
  };

  // SVG Gauge calculations matching mockup dial
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * (circumference * 0.75); // 270 degree arc

  return (
    <div className="cyber-card p-8 relative overflow-hidden">
      {/* Background glow ambient gradient */}
      <div className="absolute -top-24 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-24 -right-24 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        {/* Left Side: Circular Gauge Meter (Matching mockup gauge) */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center relative">
          <div className="relative w-64 h-64 flex items-center justify-center">
            {/* Outer Tick Ring */}
            <svg className="w-full h-full transform -rotate-135" viewBox="0 0 200 200">
              {/* Outer tick marks */}
              <circle
                cx="100"
                cy="100"
                r="92"
                stroke="rgba(255, 255, 255, 0.15)"
                strokeWidth="4"
                strokeDasharray="2 6"
                fill="transparent"
              />
              {/* Track */}
              <circle
                cx="100"
                cy="100"
                r={radius}
                stroke="rgba(15, 23, 42, 0.9)"
                strokeWidth="14"
                fill="transparent"
              />
              {/* Active Cyan Progress Arc */}
              <circle
                cx="100"
                cy="100"
                r={radius}
                stroke="#06b6d4"
                strokeWidth="14"
                strokeDasharray={circumference * 0.75 + ' ' + circumference * 0.25}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-1000 ease-out drop-shadow-[0_0_12px_#06b6d4]"
              />
              {/* Secondary Emerald Accent Arc */}
              <circle
                cx="100"
                cy="100"
                r={radius - 12}
                stroke="#10b981"
                strokeWidth="3"
                strokeDasharray="1 5"
                fill="transparent"
                className="opacity-75"
              />
            </svg>

            {/* Inner Center Score Display */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">Trust Score</span>
              <div className="flex items-baseline gap-1 mt-1">
                <span className="text-5xl font-extrabold text-white tracking-tight drop-shadow-[0_0_20px_rgba(6,182,212,0.4)]">
                  {score}
                </span>
                <span className="text-lg font-bold text-cyan-400">/100</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Side: Policy Toggle Grid (Matching mockup double column toggles) */}
        <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4">
          {toggles.map((item) => (
            <div
              key={item.id}
              onClick={() => handleToggle(item.id)}
              className="toggle-pill px-5 py-3.5 rounded-2xl flex items-center justify-between cursor-pointer select-none"
            >
              <span className="text-sm font-medium text-slate-200">{item.label}</span>
              <div
                className={`w-12 h-6 rounded-full relative transition-colors duration-200 p-0.5 border ${
                  item.enabled
                    ? 'bg-cyan-500/20 border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.3)]'
                    : 'bg-rose-500/10 border-rose-500/30'
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-full transition-transform duration-200 ${
                    item.enabled
                      ? 'translate-x-6 bg-cyan-400 shadow-[0_0_8px_#06b6d4]'
                      : 'translate-x-0 bg-rose-400 shadow-[0_0_8px_#f43f5e]'
                  }`}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
