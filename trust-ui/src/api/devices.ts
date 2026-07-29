export interface RegisteredDevice {
  id: string;
  name: string;
  ip: string;
  type: 'desktop' | 'phone';
  status: 'Secured' | 'Flagged' | 'Revoked';
  connection: string;
  lastSeen: number;
  agentStatus: string;
  agentVersion?: string;
  policyVersion?: string;
  certSubject?: string;
  certFingerprint?: string;
  trustScore?: number;
}

export const fetchRegisteredDevices = async (): Promise<RegisteredDevice[]> => {
  const response = await fetch('/api/v1/devices');
  if (!response.ok) {
    throw new Error(
      response.status === 404
        ? 'Device identity API is unavailable on this node'
        : `Device identity API returned HTTP ${response.status}`,
    );
  }
  return (await response.json()) as RegisteredDevice[];
};

export const revokeDeviceCertificate = async (
  deviceId: string,
): Promise<{ success: boolean; message: string }> => {
  const response = await fetch(`/api/v1/devices/${encodeURIComponent(deviceId)}/revoke`, {
    method: 'POST',
  });
  if (!response.ok) {
    throw new Error(`Device revoke API returned HTTP ${response.status}`);
  }
  return (await response.json()) as { success: boolean; message: string };
};
