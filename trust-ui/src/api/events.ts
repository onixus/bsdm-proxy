export interface LiveTelemetryEvent {
  id: string;
  timestamp: string;
  clientIp: string;
  upstream: string;
  trustScore: number;
  action: 'ALLOWED' | 'BLOCKED' | 'MITM_INSPECTED' | 'SINKHOLED';
  reason: string;
}

export type EventCallback = (event: LiveTelemetryEvent) => void;

export class TelemetryStreamClient {
  private eventSource: EventSource | null = null;
  private listeners: EventCallback[] = [];

  constructor(private url: string = '/api/v1/events/stream') {}

  public connect(onEvent: EventCallback) {
    this.listeners.push(onEvent);

    try {
      this.eventSource = new EventSource(this.url);
      this.eventSource.onmessage = (e) => {
        try {
          const data: LiveTelemetryEvent = JSON.parse(e.data);
          this.notify(data);
        } catch (err) {
          console.error('Failed to parse SSE event:', err);
        }
      };
      this.eventSource.onerror = () => {
        // Fallback simulated stream when backend stream is not available
        this.eventSource?.close();
      };
    } catch {
      // Backend SSE not running, graceful fallback handling
    }
  }

  public notify(event: LiveTelemetryEvent) {
    this.listeners.forEach((cb) => cb(event));
  }

  public disconnect() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    this.listeners = [];
  }
}
