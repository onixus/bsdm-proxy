import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Search } from 'lucide-react';
import { fetchRecentEvents, type TrafficEvent } from '../api/events';

function eventAction(event: TrafficEvent): 'ALLOWED' | 'BLOCKED' | 'INSPECTED' {
  if (
    event.status === 403 ||
    event.cache_status === 'BLOCKED' ||
    event.cache_status === 'DENIED' ||
    event.acl_action === 'deny'
  )
    return 'BLOCKED';
  if (event.decision_source === 'mitm') return 'INSPECTED';
  return 'ALLOWED';
}

function actionBadge(action: ReturnType<typeof eventAction>) {
  const styles = {
    ALLOWED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    BLOCKED: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    INSPECTED: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${styles[action]}`}>
      {action}
    </span>
  );
}

export const ThreatStream: React.FC = () => {
  const [filterAction, setFilterAction] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const {
    data: events = [],
    error,
    isLoading,
  } = useQuery({
    queryKey: ['recentTrafficEvents'],
    queryFn: fetchRecentEvents,
    refetchInterval: 5_000,
    retry: false,
  });

  const filteredEvents = events.filter((event) => {
    const action = eventAction(event);
    const matchesAction = filterAction === 'ALL' || action === filterAction;
    const needle = searchQuery.toLowerCase();
    const matchesQuery =
      event.client_ip.includes(searchQuery) ||
      event.domain.toLowerCase().includes(needle) ||
      event.url.toLowerCase().includes(needle);
    return matchesAction && matchesQuery;
  });

  return (
    <div className="cyber-card p-6 h-full flex flex-col">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-cyan-400" />
          <h3 className="text-base font-bold text-white">Recent traffic decisions</h3>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP / host"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              className="pl-8 pr-3 py-1 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 w-36"
            />
          </div>
          <div className="flex items-center rounded-xl bg-slate-900 border border-slate-800 p-1 text-[11px]">
            {['ALL', 'ALLOWED', 'BLOCKED', 'INSPECTED'].map((action) => (
              <button
                key={action}
                onClick={() => setFilterAction(action)}
                className={`px-2 py-0.5 rounded-lg font-medium ${
                  filterAction === action
                    ? 'bg-cyan-500 text-slate-950 font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {action}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300">
          Traffic API unavailable: {(error as Error).message}
        </div>
      )}
      {isLoading && <div className="py-12 text-center text-sm text-slate-500">Loading events…</div>}
      {!isLoading && !error && filteredEvents.length === 0 && (
        <div className="py-12 text-center text-sm text-slate-500">
          No matching events returned by the Search API.
        </div>
      )}

      {filteredEvents.length > 0 && (
        <>
          <div className="grid grid-cols-12 gap-2 text-[11px] font-semibold text-slate-400 border-b border-slate-800/80 pb-2 px-2">
            <div className="col-span-3">Time / IP</div>
            <div className="col-span-5">Target</div>
            <div className="col-span-2">Action</div>
            <div className="col-span-2 text-right">HTTP</div>
          </div>
          <div className="divide-y divide-slate-800/50 my-1 max-h-[340px] overflow-y-auto pr-1">
            {filteredEvents.map((event) => (
              <div
                key={event.event_id}
                className="grid grid-cols-12 gap-2 items-center py-2.5 px-2 hover:bg-slate-900/40 rounded-lg text-xs font-mono"
              >
                <div className="col-span-3">
                  <p className="font-semibold text-cyan-400">{event.client_ip}</p>
                  <p className="text-[10px] text-slate-500 font-sans">
                    {new Date(event.ts * 1_000).toLocaleTimeString()}
                  </p>
                </div>
                <div className="col-span-5 truncate text-[11px]" title={event.url}>
                  <p className="text-slate-200 truncate">{event.domain || event.url}</p>
                  <p className="text-[10px] text-slate-500">
                    {event.method} · {event.cache_status}
                  </p>
                  {eventAction(event) === 'BLOCKED' && (event.acl_rule_id || event.acl_reason) && (
                    <p
                      className="text-[10px] text-rose-300 truncate"
                      title={[event.acl_rule_id, event.acl_reason].filter(Boolean).join(': ')}
                    >
                      {event.acl_rule_id || 'ACL'} · {event.acl_reason || 'Denied by policy'}
                    </p>
                  )}
                </div>
                <div className="col-span-2">{actionBadge(eventAction(event))}</div>
                <div className="col-span-2 text-right font-bold text-slate-200">{event.status}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
};
