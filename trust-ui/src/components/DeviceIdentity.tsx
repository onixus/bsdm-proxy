import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { fetchRegisteredDevices, revokeDeviceCertificate, RegisteredDevice } from '../api/devices';
import { Monitor, Smartphone, CheckCircle2, AlertTriangle, Search, ShieldX } from 'lucide-react';

export const DeviceIdentity: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const queryClient = useQueryClient();

  const { data: devices = [], error, isLoading } = useQuery({
    queryKey: ['registeredDevices'],
    queryFn: fetchRegisteredDevices,
    retry: false,
  });

  const revokeMutation = useMutation({
    mutationFn: revokeDeviceCertificate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['registeredDevices'] });
    },
  });

  const filteredDevices = devices.filter((dev) =>
    dev.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    dev.ip.includes(searchQuery) ||
    (dev.certSubject && dev.certSubject.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="cyber-card p-6 h-full flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-bold text-white">Identity Device Posture List</h3>
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search device / IP"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 pr-3 py-1 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 w-36"
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
        <div className="col-span-4 text-right">Action / Cert</div>
      </div>

      {/* Device Rows */}
      <div className="divide-y divide-slate-800/50 my-1 max-h-[340px] overflow-y-auto pr-1">
        {isLoading && (
          <div className="py-12 text-center text-sm text-slate-500">Loading devices…</div>
        )}
        {error && (
          <div className="my-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-300">
            {(error as Error).message}
          </div>
        )}
        {!isLoading && !error && filteredDevices.length === 0 && (
          <div className="py-12 text-center text-sm text-slate-500">
            No registered devices returned by the API.
          </div>
        )}
        {filteredDevices.map((dev: RegisteredDevice) => (
          <div key={dev.id} className="grid grid-cols-12 gap-2 items-center py-2.5 px-2 hover:bg-slate-900/40 rounded-lg transition-colors text-xs">
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
                <p className="text-[10px] text-slate-600">
                  Seen {new Date(dev.lastSeen * 1_000).toLocaleString()}
                </p>
              </div>
            </div>

            <div className="col-span-3 flex items-center gap-1 text-[11px]">
              {dev.status === 'Secured' ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 fill-emerald-500/20" />
                  <span className="text-emerald-400 font-medium">{dev.status}</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 fill-amber-500/20" />
                  <span className="text-amber-400 font-medium">{dev.status}</span>
                </>
              )}
            </div>

            <div className="col-span-4 flex items-center justify-end gap-2 text-[11px]">
              {dev.trustScore !== undefined && (
                <span className="text-slate-300 font-mono text-[10px] font-bold">
                  {dev.trustScore}/100
                </span>
              )}
              <button
                onClick={() => revokeMutation.mutate(dev.id)}
                disabled={dev.status === 'Revoked' || revokeMutation.isPending}
                title="Revoke device trust"
                className="p-1 text-slate-500 hover:text-rose-400 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ShieldX className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
      {revokeMutation.error && (
        <p className="mt-3 text-xs text-rose-400">{revokeMutation.error.message}</p>
      )}
    </div>
  );
};
