import { useQuery } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { fetchProxyHealth, fetchProxyMetrics, fetchProxyStats } from './api/client';
import { DeviceIdentity } from './components/DeviceIdentity';
import { Header } from './components/Header';
import { PostureMetrics } from './components/PostureMetrics';
import { ThreatStream } from './components/ThreatStream';
import { TrustHeroSection } from './components/TrustHeroSection';

export const App: React.FC = () => {
  const health = useQuery({
    queryKey: ['proxyHealth'],
    queryFn: fetchProxyHealth,
    refetchInterval: 15_000,
  });
  const stats = useQuery({
    queryKey: ['proxyStats'],
    queryFn: fetchProxyStats,
    refetchInterval: 5_000,
  });
  const metrics = useQuery({
    queryKey: ['proxyMetrics'],
    queryFn: fetchProxyMetrics,
    refetchInterval: 5_000,
  });

  const connected = health.data?.status === 'ok' && !health.error;
  const isRefreshing = health.isFetching || stats.isFetching || metrics.isFetching;
  const refresh = () => {
    void health.refetch();
    void stats.refetch();
    void metrics.refetch();
  };

  return (
    <div className="min-h-screen bg-[#040814] text-slate-100 flex flex-col font-sans relative selection:bg-cyan-500 selection:text-slate-950">
      <div className="fixed top-0 left-1/4 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[140px] pointer-events-none -z-10" />

      <Header
        onRefresh={refresh}
        isRefreshing={isRefreshing}
        connected={connected}
        service={stats.data?.service}
        requestsInFlight={stats.data?.requests_in_flight}
      />

      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-8 space-y-8">
        {(health.error || stats.error) && (
          <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
            Backend telemetry is incomplete:{' '}
            {(health.error as Error | null)?.message ?? (stats.error as Error | null)?.message}
          </section>
        )}

        <section>
          <TrustHeroSection connected={connected} stats={stats.data} metrics={metrics.data} />
        </section>

        <section>
          <PostureMetrics metrics={metrics.data} error={metrics.error} />
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-7">
            <ThreatStream />
          </div>
          <div className="lg:col-span-5">
            <DeviceIdentity />
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-800/60 bg-slate-950/80 py-4 px-6 text-center text-xs text-slate-500 flex items-center justify-between max-w-[1400px] w-full mx-auto">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <span>BSDM Proxy Trust-UI</span>
        </div>
        <span>Live API data only</span>
      </footer>
    </div>
  );
};

export default App;
