export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ThreatClass =
  | "ddos"
  | "botnet_beaconing"
  | "dns_tunnelling"
  | "port_scanning"
  | "unknown_anomaly";

export interface Evidence {
  feature: string;
  value: string | number | boolean;
  reason: string;
}

export interface Alert {
  alert_id: string;
  timestamp: string;
  flow_id: string;
  threat_class: ThreatClass;
  severity: Severity;
  confidence: number;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  window_seconds: number;
  evidence: Evidence[];
  detector: string;
  model_version: string;
  explanation?: string | null;
}

export interface Metrics {
  processed_events: number;
  alerts_generated: number;
  events_per_second: number;
  average_alert_latency_ms: number;
  scenario: string | null;
  status: "idle" | "running" | "completed" | "stopped" | "error";
  started_at: number | null;
  finished_at: number | null;
  threat_counts: Record<string, number>;
  error_count: number;
  last_error?: string;
}

export type SocketMessage =
  | { type: "alert"; alert: Alert }
  | { type: "metrics"; metrics: Metrics };
