import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  Chip,
  Divider,
  Drawer,
  DrawerBody,
  DrawerContent,
  DrawerHeader,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Progress,
  Select,
  SelectItem,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/react";
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  CircleStop,
  Database,
  Gauge,
  Radar,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Wifi,
  WifiOff,
} from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { getAlerts, getMetrics, getScenarios, socketUrl, startReplay, stopReplay } from "./api";
import { appwriteConfigured, listStoredAlerts, subscribeAlerts } from "./appwrite";
import type { Alert, Metrics, Severity, SocketMessage } from "./types";

const initialMetrics: Metrics = {
  processed_events: 0,
  alerts_generated: 0,
  events_per_second: 0,
  average_alert_latency_ms: 0,
  scenario: null,
  status: "idle",
  running: false,
  started_at: null,
  finished_at: null,
  threat_counts: {},
  error_count: 0,
};

const severityColor: Record<Severity, "danger" | "warning" | "primary" | "default"> = {
  critical: "danger",
  high: "danger",
  medium: "warning",
  low: "primary",
  info: "default",
};

const humanThreat = (value: string) =>
  value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

const formatTime = (value: string) =>
  new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(
    new Date(value),
  );

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<Metrics>(initialMetrics);
  const [scenarios, setScenarios] = useState<string[]>([]);
  const [selectedScenario, setSelectedScenario] = useState("");
  const [speed, setSpeed] = useState("12");
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [connected, setConnected] = useState(false);
  const [appwriteReady, setAppwriteReady] = useState(appwriteConfigured);
  const [appwriteError, setAppwriteError] = useState("");
  const [loading, setLoading] = useState(true);
  const [actionError, setActionError] = useState("");
  const [timeline, setTimeline] = useState<{ time: string; alerts: number }[]>([]);

  const prependAlert = useCallback((alert: Alert) => {
    setAlerts((current) => [alert, ...current.filter((item) => item.alert_id !== alert.alert_id)].slice(0, 100));
    setTimeline((current) => [...current.slice(-11), { time: formatTime(alert.timestamp), alerts: 1 }]);
  }, []);

  const loadInitialData = useCallback(async () => {
    try {
      const [scenarioData, metricData, alertData] = await Promise.all([getScenarios(), getMetrics(), getAlerts()]);
      setScenarios(scenarioData);
      setSelectedScenario((current) => current || scenarioData[0] || "");
      setMetrics(metricData);
      setAlerts(alertData);
      setTimeline(alertData.slice(0, 12).reverse().map((alert) => ({ time: formatTime(alert.timestamp), alerts: 1 })));
      if (appwriteConfigured) {
        try {
          const stored = await listStoredAlerts(100);
          if (stored.length > 0) {
            setAlerts(stored);
            setTimeline(stored.slice(0, 12).reverse().map((alert) => ({ time: formatTime(alert.timestamp), alerts: 1 })));
          }
        } catch (error) {
          setAppwriteError(error instanceof Error ? error.message : "Unable to list Appwrite alerts");
        }
      }
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to load the local detection service");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadInitialData();
    const socket = new WebSocket(socketUrl());
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (message) => {
      const payload = JSON.parse(message.data) as SocketMessage;
      if (payload.type === "metrics") {
        setMetrics(payload.metrics);
      } else if (payload.type === "explained") {
        setAlerts((current) =>
          current.map((alert) =>
            alert.alert_id === payload.alert_id ? { ...alert, explanation: payload.explanation } : alert,
          ),
        );
      } else {
        prependAlert(payload.alert);
        setMetrics((current) => ({ ...current, alerts_generated: current.alerts_generated + 1 }));
      }
    };
    const appwriteRealtime = subscribeAlerts(
      (alert) => prependAlert(alert),
      (message) => setAppwriteError(message),
    );
    if (appwriteConfigured) {
      setAppwriteReady(Boolean(appwriteRealtime));
    }
    return () => {
      socket.close();
      appwriteRealtime?.unsubscribe();
    };
  }, [loadInitialData, prependAlert]);

  const counts = useMemo(() => alerts.reduce<Record<string, number>>((result, alert) => {
    result[alert.severity] = (result[alert.severity] ?? 0) + 1;
    return result;
  }, {}), [alerts]);

  const handleStart = async () => {
    if (!selectedScenario) return;
    setActionError("");
    try {
      await startReplay(selectedScenario, Number(speed));
      setAlerts([]);
      setTimeline([]);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to start replay");
    }
  };

  const handleStop = async () => {
    try {
      await stopReplay();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to stop replay");
    }
  };

  const statusLabel = metrics.status === "running" ? "Replay active" : metrics.status;

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark"><Radar size={20} /></div>
          <div>
            <p className="eyebrow">SIH26145 / NTRO</p>
            <h1>Passive Detection Console</h1>
          </div>
        </div>
        <div className="topbar-status">
          <Chip color={metrics.status === "error" ? "danger" : metrics.status === "running" ? "warning" : "success"} variant="flat" startContent={<Activity size={14} />}>
            {statusLabel}
          </Chip>
          <span className={connected ? "connection connected" : "connection"}>
            {connected ? <Wifi size={15} /> : <WifiOff size={15} />}
            {connected ? "Realtime connected" : "Reconnecting"}
          </span>
          {appwriteConfigured && (
            <Chip size="sm" color={appwriteReady ? "success" : "danger"} variant="flat" startContent={<Database size={13} />}>
              Appwrite {appwriteReady ? "connected" : "offline"}
            </Chip>
          )}
          <Chip size="sm" color={metrics.ollama_status?.available ? "success" : "default"} variant="flat" startContent={<Sparkles size={13} />}>
            Ollama {metrics.ollama_status?.available ? metrics.ollama_status.model : "off"}
          </Chip>
        </div>
      </header>

      <section className="command-strip">
        <div className="command-copy">
          <span className="section-kicker">READ-ONLY REPLAY</span>
          <strong>Simulated monitoring enclave</strong>
          <span>Metadata-only analysis. No probes, payload decryption, or response path.</span>
        </div>
        <div className="command-controls">
          {loading ? <Spinner size="sm" /> : (
            <Select aria-label="Traffic scenario" className="scenario-select" selectedKeys={selectedScenario ? [selectedScenario] : []} onSelectionChange={(keys) => setSelectedScenario(String([...keys][0] ?? ""))}>
              {scenarios.map((scenario) => <SelectItem key={scenario}>{humanThreat(scenario)}</SelectItem>)}
            </Select>
          )}
          <Dropdown>
            <DropdownTrigger><Button variant="flat" endContent={<ChevronDown size={15} />} startContent={<Gauge size={15} />}>{speed}x</Button></DropdownTrigger>
            <DropdownMenu aria-label="Replay speed" onAction={(key) => setSpeed(String(key))}>
              {["1", "4", "8", "12", "20"].map((value) => <DropdownItem key={value}>{value}x</DropdownItem>)}
            </DropdownMenu>
          </Dropdown>
          <Button color="primary" startContent={<Activity size={16} />} onPress={() => void handleStart()} isDisabled={!selectedScenario || metrics.status === "running"}>Start replay</Button>
          <Button variant="flat" color="danger" startContent={<CircleStop size={16} />} onPress={() => void handleStop()} isDisabled={metrics.status !== "running"}>Stop</Button>
          <Button isIconOnly variant="light" aria-label="Refresh dashboard" onPress={() => void loadInitialData()}><RefreshCw size={17} /></Button>
        </div>
      </section>

      {actionError && <div className="error-banner"><AlertTriangle size={16} />{actionError}</div>}
      {appwriteConfigured && appwriteError && <div className="error-banner"><AlertTriangle size={16} />Appwrite: {appwriteError}</div>}

      <section className="metric-grid">
        <MetricCard label="Events processed" value={metrics.processed_events.toLocaleString()} hint={`${metrics.events_per_second.toLocaleString()} events/sec`} icon={<Activity size={18} />} />
        <MetricCard label="Alerts generated" value={metrics.alerts_generated.toString()} hint="Structured detections" icon={<AlertTriangle size={18} />} tone="danger" />
        <MetricCard label="Critical / high" value={`${counts.critical ?? 0} / ${counts.high ?? 0}`} hint="Current replay" icon={<ShieldCheck size={18} />} tone="warning" />
        <MetricCard label="Detection latency" value={`${metrics.average_alert_latency_ms.toFixed(0)} ms`} hint="Target: under 2 seconds" icon={<Gauge size={18} />} />
      </section>

      <section className="content-grid">
        <Card className="panel chart-panel"><CardBody>
          <div className="panel-heading"><div><span className="section-kicker">ACTIVITY</span><h2>Detection timeline</h2></div><Chip size="sm" variant="flat" color="success">Live</Chip></div>
          <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><LineChart data={timeline}><CartesianGrid stroke="#273242" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="time" stroke="#718096" tickLine={false} axisLine={false} /><YAxis allowDecimals={false} stroke="#718096" tickLine={false} axisLine={false} /><Tooltip contentStyle={{ background: "#121a25", border: "1px solid #2b394b", borderRadius: 6 }} /><Line type="monotone" dataKey="alerts" stroke="#f87171" strokeWidth={2} dot={{ r: 3, fill: "#f87171" }} /></LineChart></ResponsiveContainer></div>
        </CardBody></Card>
        <Card className="panel summary-panel"><CardBody>
          <div className="panel-heading"><div><span className="section-kicker">DISTRIBUTION</span><h2>Threat classes</h2></div></div>
          <div className="distribution-list">{Object.entries(metrics.threat_counts).length === 0 ? <div className="empty-state">No detections in the current replay.</div> : Object.entries(metrics.threat_counts).map(([threat, count]) => <div className="distribution-row" key={threat}><span>{humanThreat(threat)}</span><strong>{count}</strong></div>)}</div>
          <Divider className="divider" />
          <div className="enclave-note"><ShieldCheck size={17} /><span>Local rules are authoritative{metrics.model_status?.available ? `; ${metrics.model_status.version} model scoring is active` : "; no ML model loaded (rules-only)"}.{metrics.appwrite_status?.enabled ? ` ${metrics.appwrite_status.persisted_count} alerts persisted to Appwrite.` : " Appwrite persistence is off."}{metrics.ollama_status?.available ? " Local Ollama explanations are active." : " LLM explanations are off."} External AI APIs are not required.</span></div>
        </CardBody></Card>
      </section>

      <section className="panel alerts-panel">
        <div className="panel-heading"><div><span className="section-kicker">ALERT STREAM</span><h2>Recent detections</h2></div><span className="muted-label">{alerts.length} visible</span></div>
        <Table aria-label="Recent detections" removeWrapper classNames={{ th: "table-head", td: "table-cell" }} selectionMode="single" onRowAction={(key) => setSelectedAlert(alerts.find((alert) => alert.alert_id === String(key)) ?? null)}>
          <TableHeader><TableColumn>SEVERITY</TableColumn><TableColumn>THREAT</TableColumn><TableColumn>SOURCE</TableColumn><TableColumn>DESTINATION</TableColumn><TableColumn>CONFIDENCE</TableColumn><TableColumn>TIME</TableColumn></TableHeader>
          <TableBody emptyContent={<div className="empty-state">Start a replay to populate the alert stream.</div>} items={alerts}>{(alert) => <TableRow key={alert.alert_id}><TableCell><Chip size="sm" color={severityColor[alert.severity]} variant="flat">{alert.severity.toUpperCase()}</Chip></TableCell><TableCell><span className="threat-name">{humanThreat(alert.threat_class)}</span><span className="detector-name">{alert.detector}</span></TableCell><TableCell><code>{alert.source_ip}</code></TableCell><TableCell><code>{alert.destination_ip}:{alert.flow_id.split(":").pop()}</code></TableCell><TableCell><div className="confidence-cell"><Progress aria-label="Confidence" size="sm" color={severityColor[alert.severity]} value={alert.confidence * 100} /><span>{Math.round(alert.confidence * 100)}%</span></div></TableCell><TableCell><span className="timestamp">{formatTime(alert.timestamp)}</span></TableCell></TableRow>}</TableBody>
        </Table>
      </section>

      <Drawer isOpen={selectedAlert !== null} onOpenChange={(open) => !open && setSelectedAlert(null)} size="lg"><DrawerContent>{(onClose) => selectedAlert && <><DrawerHeader className="drawer-header"><div><span className="section-kicker">ALERT DETAILS</span><h2>{humanThreat(selectedAlert.threat_class)}</h2></div><Button isIconOnly variant="light" aria-label="Close alert details" onPress={onClose}>×</Button></DrawerHeader><DrawerBody><div className="detail-hero"><Chip color={severityColor[selectedAlert.severity]}>{selectedAlert.severity.toUpperCase()}</Chip><strong>{Math.round(selectedAlert.confidence * 100)}% confidence</strong><span>{selectedAlert.detector}</span></div><div className="detail-grid"><Detail label="Source" value={selectedAlert.source_ip} /><Detail label="Destination" value={selectedAlert.destination_ip} /><Detail label="Protocol" value={selectedAlert.protocol} /><Detail label="Flow ID" value={selectedAlert.flow_id} /></div><div className="evidence-heading"><span className="section-kicker">SUPPORTING EVIDENCE</span><h3>Why this was flagged</h3></div><div className="evidence-list">{selectedAlert.evidence.map((item) => <div className="evidence-item" key={item.feature}><div><strong>{item.feature.replaceAll("_", " ")}</strong><span>{item.reason}</span></div><code>{String(item.value)}</code></div>)}</div>          <div className="explanation-box"><span className="section-kicker">ANALYST EXPLANATION</span>{selectedAlert.explanation ? <p>{selectedAlert.explanation}</p> : metrics.ollama_status?.available ? <p className="explanation-pending"><Spinner size="sm" /> Generating explanation with the local model…</p> : <p>Deterministic evidence is available. Start Ollama and restart the API to enable local LLM explanations.</p>}</div></DrawerBody></>}</DrawerContent></Drawer>
    </main>
  );
}

function MetricCard({ label, value, hint, icon, tone = "default" }: { label: string; value: string; hint: string; icon: React.ReactNode; tone?: "default" | "danger" | "warning" }) {
  return <Card className={`metric-card ${tone}`}><CardBody><div className="metric-icon">{icon}</div><span className="metric-label">{label}</span><strong className="metric-value">{value}</strong><span className="metric-hint">{hint}</span></CardBody></Card>;
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><span className="detail-label">{label}</span><code>{value}</code></div>;
}

export default App;
