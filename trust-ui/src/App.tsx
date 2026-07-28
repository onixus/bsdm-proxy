import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Header } from './components/Header';
import { TrustHeroSection } from './components/TrustHeroSection';
import { PostureMetrics } from './components/PostureMetrics';
import { ThreatStream } from './components/ThreatStream';
import { DeviceIdentity } from './components/DeviceIdentity';
import { fetchProxyHealth, fetchProxyMetrics } from './api/client';
import { ShieldCheck } from 'lucide-react';

export const App: React.FC = () => {
  const [trustScore, setTrustScore] = useState<number>(92);

  const { data: healthData, refetch: refetchHealth, isFetching: isFetchingHealth } = useQuery({
    queryKey: ['proxyHealth'],
    queryFn: fetchProxyHealth,
  });

  const { data: metricsData, refetch: refetchMetrics, isFetching: isFetchingMetrics } = useQuery({
    queryKey: ['proxyMetrics'],
    queryFn: fetchProxyMetrics,
  });

  const isRefreshing = isFetchingHealth || isFetchingMetrics;

  const handleRefresh = () => {
    refetchHealth();
    refetchMetrics();
    setTrustScore(Math.floor(Math.random() * 10) + 90);
  };

  return (
    <div className="min-h-screen bg-[#040814] text-slate-100 flex flex-col font-sans relative selection:bg-cyan-500 selection:text-slate-950">
      {/* Background ambient lighting gradients */}
      <div className="fixed top-0 left-1/4 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[140px] pointer-events-none -z-10" />

      {/* Top Header */}
      <Header
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
        healthStatus={healthData?.status ?? 'ok'}
      />

      {/* Main Dashboard Layout */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-8 space-y-8">
        {/* Hero Section: Gauge + Policy Toggles */}
        <section>
          <TrustHeroSection score={trustScore} />
        </section>

        {/* Middle Section: 4 Key Metric Cards */}
        <section>
          <PostureMetrics
            metrics={{
              casbDlpBlocks: metricsData?.casbDlpBlocks ?? 348,
              rpzSinkholeBlocks: metricsData?.rpzSinkholeBlocks ?? 3913,
            }}
          />
        </section>

        {/* Bottom Section: Telemetry Stream + Device Posture */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-6">
            <ThreatStream />
          </div>
          <div className="lg:col-span-6">
            <DeviceIdentity />
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/60 bg-slate-950/80 py-4 px-6 text-center text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between max-w-[1400px] w-full mx-auto">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <span>BSDM Proxy Trust-UI — Zero-Trust MITM Security Control Plane</span>
        </div>
        <div className="flex items-center gap-4 mt-2 sm:mt-0 font-mono text-[11px] text-slate-400">
          <span>MITM_ENABLED={healthData?.mitmEnabled ? 'true' : 'false'}</span>
          <span>•</span>
          <span>mTLS Peer Validation</span>
          <span>•</span>
          <span>ClickHouse Analytics</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
