export interface TrafficEvent {
  ts: number;
  username?: string;
  client_ip: string;
  url: string;
  method: string;
  status: number;
  cache_status: string;
  domain: string;
  event_id: string;
  session_id: string;
  decision_source?: string;
}

export const fetchRecentEvents = async (): Promise<TrafficEvent[]> => {
  const query = new URLSearchParams({ days: '1', limit: '50' });
  const response = await fetch(`/api/search?${query}`);
  if (!response.ok) {
    throw new Error(`Search API returned HTTP ${response.status}`);
  }
  return (await response.json()) as TrafficEvent[];
};
