import React, { useState } from 'react';
import { Header } from './components/Header';
import { TrustGauge } from './components/TrustGauge';
import { PostureMetrics } from './components/PostureMetrics';
import { ThreatStream } from './components/ThreatStream';
import { PolicyRules } from './components/PolicyRules';
import { DeviceIdentity } from './components/DeviceIdentity';
import { ShieldCheck } from 'lucide-react';

export const App: React.FC = () => {
  const [trustScore, setTrustScore] = useState<number>(92);
  const [threatLevel, setThreatLevel] = useState<'Low' | 'Medium' | 'High'>('Low');
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [activeEnforcement, setActiveEnforcement] = useState<boolean>(true);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      // Simulate live trust score calculation
      const newScore = Math.floor(Math.random() * 15) + 85;
      setTrustScore(newScore);
      setThreatLevel(newScore >= 80 ? 'Low' : 'Medium');
      setIsRefreshing(false);
    }, 800);
  };

  const handleToggleEnforcement = () => {
    setActiveEnforcement((prev) => !prev);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans relative">
      {/* Background ambient lighting */}
      <div className="fixed top-0 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none -z-10" />

      {/* Navigation Header */}
      <Header
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
        activeEnforcement={activeEnforcement}
        onToggleEnforcement={handleToggleEnforcement}
      />

      {/* Main Content Dashboard */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8">
        {/* Top Hero Section: Trust Score & Posture Stats */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          <div className="lg:col-span-6">
            <TrustGauge
              score={trustScore}
              threatLevel={threatLevel}
              verifiedSessions={14892}
              flaggedSessions={12}
            />
          </div>
          <div className="lg:col-span-6 flex flex-col justify-between">
            <PolicyRules />
          </div>
        </section>

        {/* Middle Section: Metrics Cards */}
        <section>
          <PostureMetrics />
        </section>

        {/* Bottom Section: Threat Stream & Endpoint Identity */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7">
            <ThreatStream />
          </div>
          <div className="lg:col-span-5">
            <DeviceIdentity />
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 px-6 text-center text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between max-w-7xl w-full mx-auto">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-500" />
          <span>BSDM Proxy Trust-UI — Single Rust/Cargo Forward Proxy Ecosystem</span>
        </div>
        <div className="flex items-center gap-4 mt-2 sm:mt-0 font-mono text-[11px]">
          <span>MITM_ENABLED=true</span>
          <span>•</span>
          <span>mTLS Peer Auth</span>
          <span>•</span>
          <span>ClickHouse Analytics</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
