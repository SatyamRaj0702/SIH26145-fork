import type { Alert, Metrics } from "./types";

const json = async <T>(response: Response): Promise<T> => {
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail ?? `Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
};

export const getScenarios = async (): Promise<string[]> => {
  const response = await fetch("/api/scenarios");
  const payload = await json<{ scenarios: string[] }>(response);
  return payload.scenarios;
};

export const getMetrics = async (): Promise<Metrics> => {
  const response = await fetch("/api/metrics");
  return json<Metrics>(response);
};

export const getAlerts = async (): Promise<Alert[]> => {
  const response = await fetch("/api/alerts?limit=100");
  const payload = await json<{ alerts: Alert[] }>(response);
  return payload.alerts;
};

export const startReplay = async (scenario: string, speed: number): Promise<void> => {
  const response = await fetch("/api/replay/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario, speed }),
  });
  await json(response);
};

export const stopReplay = async (): Promise<void> => {
  const response = await fetch("/api/replay/stop", { method: "POST" });
  await json(response);
};

export const socketUrl = (): string => {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/ws/alerts`;
};
