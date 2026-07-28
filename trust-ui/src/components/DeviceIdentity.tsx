import React from 'react';
import { Monitor, Smartphone, CheckCircle2, Search, MoreVertical } from 'lucide-react';

interface DeviceItem {
  id: string;
  name: string;
  ip: string;
  type: 'desktop' | 'phone';
  status: 'Securoted' | 'Secured';
  connection: string;
}

const mockDevices: DeviceItem[] = [
  {
    id: 'd1',
    name: 'Desktop',
    ip: '192.10.1039833',
    type: 'desktop',
    status: 'Securoted',
    connection: 'Connected',
  },
  {
    id: 'd2',
    name: 'Desktop',
    ip: '192.10.3598807',
    type: 'phone',
    status: 'Secured',
    connection: 'Connected',
  },
  {
    id: 'd3',
    name: 'Hubruser Pro',
    ip: '192.108.7.60125009',
    type: 'desktop',
    status: 'Secured',
    connection: 'Connected',
  },
  {
    id: 'd4',
    name: 'Desktop',
    ip: '192.10.1039831',
    type: 'desktop',
    status: 'Secured',
    connection: 'Connected',
  },
  {
    id: 'd5',
    name: 'Desktop',
    ip: '192.10.97.20970',
    type: 'desktop',
    status: 'Secured',
    connection: 'Connected',
  },
];

export const DeviceIdentity: React.FC = () => {
  return (
    <div className="cyber-card p-6 h-full flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-bold text-white">Identity Device Posture List</h3>
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search"
            className="pl-8 pr-3 py-1 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 w-32"
          />
        </div>
      </div>

      {/* Table header */}
      <div className="grid grid-cols-12 gap-2 text-[11px] font-semibold text-slate-400 border-b border-slate-800/80 pb-2 px-2">
        <div className="col-span-5 flex items-center gap-1">
          <span>Device</span>
          <span className="text-[10px]">↕</span>
        </div>
        <div className="col-span-3">Status</div>
        <div className="col-span-4 text-right">Postiunty</div>
      </div>

      {/* Device Rows */}
      <div className="divide-y divide-slate-800/50 my-1">
        {mockDevices.map((dev) => (
          <div key={dev.id} className="grid grid-cols-12 gap-2 items-center py-3 px-2 hover:bg-slate-900/40 rounded-lg transition-colors text-xs">
            <div className="col-span-5 flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400">
                {dev.type === 'desktop' ? (
                  <Monitor className="w-4 h-4 text-cyan-400" />
                ) : (
                  <Smartphone className="w-4 h-4 text-purple-400" />
                )}
              </div>
              <div>
                <p className="font-semibold text-slate-200">{dev.name}</p>
                <p className="text-[10px] text-slate-500 font-mono">{dev.ip}</p>
              </div>
            </div>

            <div className="col-span-3 flex items-center gap-1 text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 fill-emerald-500/20" />
              <span className="text-emerald-400 font-medium">{dev.status}</span>
            </div>

            <div className="col-span-4 flex items-center justify-end gap-2 text-[11px]">
              <span className="text-slate-300 font-medium">{dev.connection}</span>
              <button className="text-slate-500 hover:text-white transition-colors">
                <MoreVertical className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
