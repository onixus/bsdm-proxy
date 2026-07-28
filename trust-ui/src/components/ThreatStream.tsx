import { AlertCircle, ChevronDown } from 'lucide-react';

export interface TelemetryEvent {
  id: string;
  name: string;
  subText: string;
  code: string;
  timeAgo: string;
}

const mockEvents: TelemetryEvent[] = [
  {
    id: 'ev-1',
    name: 'Security Event',
    subText: 'Security Events',
    code: '1198: 155 Patecntss',
    timeAgo: '3 months ago',
  },
  {
    id: 'ev-2',
    name: 'Security Event',
    subText: 'Security Events',
    code: '1196: 157 Threats',
    timeAgo: '3 months ago',
  },
  {
    id: 'ev-3',
    name: 'Security Event',
    subText: 'Security Events',
    code: '1199: 155 Patecets',
    timeAgo: '3 months ago',
  },
  {
    id: 'ev-4',
    name: 'Security Event',
    subText: 'Security Events',
    code: '1195: 153 Inspections',
    timeAgo: '3 months ago',
  },
  {
    id: 'ev-5',
    name: 'Security Event',
    subText: 'Security Events',
    code: '1198: 157 Threats',
    timeAgo: '2 months ago',
  },
];

export const ThreatStream: React.FC = () => {
  return (
    <div className="cyber-card p-6 h-full flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-bold text-white">Live Telemetry Threat Stream</h3>
        <button className="flex items-center gap-1.5 px-3 py-1 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 hover:text-white transition-colors">
          <span>All Sort</span>
          <ChevronDown className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Table header matching mockup */}
      <div className="grid grid-cols-12 gap-2 text-[11px] font-semibold text-slate-400 border-b border-slate-800/80 pb-2 px-2">
        <div className="col-span-5 flex items-center gap-1">
          <span>Event</span>
          <span className="text-[10px]">↑</span>
        </div>
        <div className="col-span-4">Event Details</div>
        <div className="col-span-3 text-right">Time</div>
      </div>

      {/* Rows */}
      <div className="divide-y divide-slate-800/50 my-1">
        {mockEvents.map((item) => (
          <div key={item.id} className="grid grid-cols-12 gap-2 items-center py-3 px-2 hover:bg-slate-900/40 rounded-lg transition-colors text-xs">
            <div className="col-span-5 flex items-center gap-2.5">
              <span className="p-1 rounded-full bg-rose-500/20 text-rose-400">
                <AlertCircle className="w-3.5 h-3.5 fill-rose-500/30" />
              </span>
              <div>
                <p className="font-semibold text-slate-200">{item.name}</p>
                <p className="text-[10px] text-slate-500">{item.subText}</p>
              </div>
            </div>
            <div className="col-span-4 font-mono text-slate-300 text-[11px]">{item.code}</div>
            <div className="col-span-3 text-right text-slate-400 text-[11px]">{item.timeAgo}</div>
          </div>
        ))}
      </div>
    </div>
  );
};
