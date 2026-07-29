import type { ProxyMetrics } from '../api/client';

interface PostureMetricsProps {
  metrics?: ProxyMetrics;
  error?: Error | null;
}

export const PostureMetrics: React.FC<PostureMetricsProps> = ({ metrics, error }) => {
  const cards = [
    { label: 'Successful TLS handshakes', value: metrics?.tlsHandshakesOk },
    { label: 'MITM policy decisions', value: metrics?.mitmDecisions },
    { label: 'ACL deny decisions', value: metrics?.aclDenied },
    { label: 'Categorized blocks', value: metrics?.categorizationBlocked },
  ];

  return (
    <div>
      {error && (
        <div className="mb-4 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          Metrics unavailable: {error.message}
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {cards.map((card) => (
          <div
            key={card.label}
            className="cyber-card cyber-card-hover p-6 flex flex-col justify-between h-40"
          >
            <h3 className="text-sm font-medium text-slate-300">{card.label}</h3>
            <p className="text-3xl font-extrabold text-cyan-400 tracking-tight">
              {card.value === undefined ? '—' : card.value.toLocaleString()}
            </p>
            <span className="text-[11px] text-slate-500">Prometheus counter</span>
          </div>
        ))}
      </div>
    </div>
  );
};
