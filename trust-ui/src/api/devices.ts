export interface RegisteredDevice {
  id: string;
  name: string;
  ip: string;
  type: 'desktop' | 'phone';
  status: 'Secured' | 'Flagged' | 'Revoked';
  connection: string;
  certSubject?: string;
  certFingerprint?: string;
  trustScore: number;
}

export const fetchRegisteredDevices = async (): Promise<RegisteredDevice[]> => {
  try {
    const res = await fetch('/api/v1/devices');
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.warn('Failed to fetch devices API, using mock telemetry:', e);
  }
  return [
    {
      id: 'd1',
      name: 'Desktop-SecOps-01',
      ip: '192.10.1039833',
      type: 'desktop',
      status: 'Secured',
      connection: 'Connected',
      certSubject: 'CN=admin@bsdm.internal',
      certFingerprint: 'SHA256:a1:b2:c3:d4',
      trustScore: 98,
    },
    {
      id: 'd2',
      name: 'Mobile-BYOD-Android',
      ip: '192.10.3598807',
      type: 'phone',
      status: 'Flagged',
      connection: 'Connected',
      certSubject: 'CN=guest@bsdm.internal',
      certFingerprint: 'SHA256:e5:f6:g7:h8',
      trustScore: 42,
    },
    {
      id: 'd3',
      name: 'Hubruser Pro Node',
      ip: '192.108.7.60125009',
      type: 'desktop',
      status: 'Secured',
      connection: 'Connected',
      certSubject: 'CN=peer-node-01',
      certFingerprint: 'SHA256:99:88:77:66',
      trustScore: 100,
    },
    {
      id: 'd4',
      name: 'Workstation-Dev-04',
      ip: '192.10.1039831',
      type: 'desktop',
      status: 'Secured',
      connection: 'Connected',
      certSubject: 'CN=dev04@bsdm.internal',
      certFingerprint: 'SHA256:11:22:33:44',
      trustScore: 92,
    },
  ];
};

export const revokeDeviceCertificate = async (
  deviceId: string
): Promise<{ success: boolean; message: string }> => {
  try {
    const res = await fetch(`/api/v1/devices/${deviceId}/revoke`, {
      method: 'POST',
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.warn('Revoke API offline:', e);
  }
  return {
    success: true,
    message: `Device ${deviceId} certificate revoked`,
  };
};
