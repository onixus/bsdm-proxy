export interface ProxyHealthStatus {
  status: string;
}

export interface ProxyStats {
  service: string;
  uptime_secs: number;
  requests_in_flight: number;
  cache: {
    hits: number;
    misses: number;
    bypasses: number;
    hit_ratio: number;
    entries: number;
    capacity: number;
    shards: number;
    tags: number;
  };
}

export interface ProxyMetrics {
  totalRequests: number;
  aclDenied: number;
  mitmDecisions: number;
  categorizationBlocked: number;
  tlsHandshakesOk: number;
}

async function requireOk(response: Response, service: string): Promise<Response> {
  if (!response.ok) {
    throw new Error(`${service} returned HTTP ${response.status}`);
  }
  return response;
}

export const fetchProxyHealth = async (): Promise<ProxyHealthStatus> => {
  const response = await requireOk(await fetch('/health'), 'Proxy health API');
  const payload: unknown = await response.json();
  if (
    typeof payload !== 'object' ||
    payload === null ||
    typeof (payload as Record<string, unknown>).status !== 'string'
  ) {
    throw new Error('Proxy health API returned an invalid payload');
  }
  return payload as ProxyHealthStatus;
};

export const fetchProxyStats = async (): Promise<ProxyStats> => {
  const response = await requireOk(await fetch('/api/stats'), 'Proxy stats API');
  return (await response.json()) as ProxyStats;
};

function metricSum(text: string, name: string, labels?: Record<string, string>): number {
  let total = 0;
  let matched = false;

  for (const line of text.split('\n')) {
    if (!line.startsWith(name)) continue;
    const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+(\S+)/);
    if (!match || match[1] !== name) continue;

    const labelText = match[2] ?? '';
    const hasLabels = Object.entries(labels ?? {}).every(
      ([key, value]) =>
        new RegExp(`(?:^|,)${key}="${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"(?:,|$)`).test(
          labelText,
        ),
    );
    if (!hasLabels) continue;

    const value = Number(match[3]);
    if (Number.isFinite(value)) {
      total += value;
      matched = true;
    }
  }

  return matched ? total : 0;
}

export const fetchProxyMetrics = async (): Promise<ProxyMetrics> => {
  const response = await requireOk(await fetch('/metrics'), 'Proxy metrics API');
  const text = await response.text();

  return {
    totalRequests: metricSum(text, 'bsdm_proxy_requests_total'),
    aclDenied: metricSum(text, 'bsdm_proxy_acl_decisions_total', { action: 'deny' }),
    mitmDecisions: metricSum(text, 'bsdm_proxy_policy_decision_source_total', { source: 'mitm' }),
    categorizationBlocked: metricSum(text, 'bsdm_proxy_categorization_blocked_total'),
    tlsHandshakesOk: metricSum(text, 'bsdm_proxy_tls_handshakes_total', { status: 'success' }),
  };
};
