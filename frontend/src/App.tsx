import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
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
  Lock,
  LogOut,
  Radar,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  SquareDashedMousePointer,
  Wifi,
  WifiOff,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { getAlerts, getMetrics, getScenarios, socketUrl, startReplay, stopReplay } from "./api";
import { appwriteConfigured, listStoredAlerts, subscribeAlerts } from "./appwrite";
import type { Alert, Metrics, Severity, SocketMessage } from "./types";

const DEMO_KEY = "sih26145-demo-entered";

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

const severityOrder: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low", "info"];

const severityPalette: Record<Severity, string> = {
  critical: "#fb7185",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#60a5fa",
  info: "#94a3b8",
};

const severityLabel: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const threatPalette: Record<string, string> = {
  ddos: "#22d3ee",
  botnet_beaconing: "#a78bfa",
  dns_tunnelling: "#34d399",
  dga: "#f59e0b",
  encrypted_session_anomaly: "#60a5fa",
  port_scanning: "#f97316",
  data_exfiltration: "#fb7185",
  udp_amplification: "#14b8a6",
  slowloris: "#c084fc",
};

const defaultSampleAlert: Alert = {
  alert_id: "demo-2026-09-08-001",
  timestamp: new Date().toISOString(),
  flow_id: "flow:demo:1",
  threat_class: "port_scanning",
  severity: "high",
  confidence: 0.97,
  source_ip: "10.0.0.25",
  destination_ip: "10.0.0.8",
  protocol: "tcp",
  window_seconds: 30,
  evidence: [
    { feature: "distinct_destination_ports", value: 18, reason: "fan-out exceeds the learned baseline" },
    { feature: "unique_destination_hosts", value: 7, reason: "target spread is unusually wide" },
    { feature: "syn_to_ack_ratio", value: 5.4, reason: "probing pattern matches recon activity" },
  ],
  detector: "rule+rf",
  model_version: "demo",
  explanation: null,
};

const humanThreat = (value: string) => value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

const formatTime = (value: string) =>
  new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));

const formatClock = (value: Date) =>
  new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(value);

function getStoredDemoState() {
  if (typeof window === "undefined") return false;
  return window.localStorage.getItem(DEMO_KEY) === "1";
}

function setStoredDemoState(value: boolean) {
  window.localStorage.setItem(DEMO_KEY, value ? "1" : "0");
}

function useCountUp(target: number) {
  const [value, setValue] = useState(target);

  useEffect(() => {
    let frame = 0;
    const start = performance.now();
    const initial = value;
    const duration = 650;

    const animate = (now: number) => {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(initial + (target - initial) * eased));
      if (progress < 1) {
        frame = window.requestAnimationFrame(animate);
      }
    };

    frame = window.requestAnimationFrame(animate);
    return () => window.cancelAnimationFrame(frame);
  }, [target]);

  return value;
}

function toPercent(value: number) {
  return Math.max(0, Math.min(100, Math.round(value * 100)));
}

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
  const [activeTab, setActiveTab] = useState<"overview" | "alerts" | "analytics" | "about">("overview");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [clock, setClock] = useState(() => formatClock(new Date()));
  const [demoEntered, setDemoEntered] = useState(() => getStoredDemoState());
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");

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
          current.map((alert) => (alert.alert_id === payload.alert_id ? { ...alert, explanation: payload.explanation } : alert)),
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

  useEffect(() => {
    const interval = window.setInterval(() => setClock(formatClock(new Date())), 1000);
    return () => window.clearInterval(interval);
  }, []);

  const counts = useMemo(
    () =>
      alerts.reduce<Record<string, number>>((result, alert) => {
        result[alert.severity] = (result[alert.severity] ?? 0) + 1;
        return result;
      }, {}),
    [alerts],
  );

  const filteredAlerts = useMemo(
    () =>
      alerts.filter((alert) => {
        const query = search.trim().toLowerCase();
        const matchesSearch =
          query.length === 0 ||
          [
            alert.threat_class,
            alert.severity,
            alert.source_ip,
            alert.destination_ip,
            alert.protocol,
            alert.detector,
            alert.flow_id,
            ...alert.evidence.flatMap((item) => [item.feature, item.reason, String(item.value)]),
          ]
            .join(" ")
            .toLowerCase()
            .includes(query);
        const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
        return matchesSearch && matchesSeverity;
      }),
    [alerts, search, severityFilter],
  );

  const distributionData = useMemo(
    () =>
      Object.entries(metrics.threat_counts).map(([threat, count]) => ({
        name: humanThreat(threat),
        raw: threat,
        count,
        color: threatPalette[threat] ?? "#22d3ee",
      })),
    [metrics.threat_counts],
  );

  const analyticsSeverityData = useMemo(
    () =>
      severityOrder
        .filter((severity): severity is Severity => severity !== "all")
        .map((severity) => ({
          severity: severityLabel[severity],
          value: counts[severity] ?? 0,
          color: severityPalette[severity],
        })),
    [counts],
  );

  const analyticsTrendData = useMemo(() => {
    const ordered = [...alerts].reverse();
    return ordered.slice(-18).map((alert, index) => ({
      point: index + 1,
      alerts: 1,
      confidence: toPercent(alert.confidence),
      label: formatTime(alert.timestamp),
    }));
  }, [alerts]);

  const analyticsThreatData = useMemo(() => {
    const entries = Object.entries(counts)
      .filter(([severity]) => severity !== "all")
      .sort((left, right) => (right[1] ?? 0) - (left[1] ?? 0));
    return entries.map(([severity, value]) => ({
      name: severityLabel[severity as Severity],
      value,
      color: severityPalette[severity as Severity],
    }));
  }, [counts]);

  const totalAlerts = useCountUp(metrics.alerts_generated);
  const totalEvents = useCountUp(metrics.processed_events);
  const eventRate = useCountUp(metrics.events_per_second);
  const latency = useCountUp(Math.round(metrics.average_alert_latency_ms));

  const login = () => {
    setLoginError("");
    setStoredDemoState(true);
    setDemoEntered(true);
  };

  const handleLoginSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!loginEmail.trim() && !loginPassword.trim()) {
      setLoginError("Enter any demo credentials or use Enter Demo.");
      return;
    }
    login();
  };

  const handleLogout = () => {
    window.localStorage.removeItem(DEMO_KEY);
    setDemoEntered(false);
    setLoginEmail("");
    setLoginPassword("");
    setLoginError("");
  };

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

  if (!demoEntered) {
    return (
      <LoginScreen
        onDemo={login}
        onSubmit={handleLoginSubmit}
        email={loginEmail}
        password={loginPassword}
        setEmail={setLoginEmail}
        setPassword={setLoginPassword}
        error={loginError}
      />
    );
  }

  return (
    <main className="app-shell">
      <header className="topbar glass-panel">
        <div className="brand-lockup">
          <div className="brand-mark">
            <Radar size={18} />
          </div>
          <div>
            <p className="eyebrow">SIH26145 / NTRO</p>
            <h1>Passive Detection Console</h1>
          </div>
        </div>
        <div className="topbar-status">
          <span className={connected ? "connection connected" : "connection"}>
            {connected ? <Wifi size={14} /> : <WifiOff size={14} />}
            {connected ? "Realtime connected" : "Realtime disconnected"}
          </span>
          <span className="clock-chip">{clock}</span>
          <Chip size="sm" className="status-pill status-replay" variant="flat" startContent={<Activity size={13} />}>
            {statusLabel}
          </Chip>
          {appwriteConfigured && (
            <Chip size="sm" className={`status-pill ${appwriteReady ? "status-good" : "status-bad"}`} variant="flat" startContent={<Database size={13} />}>
              Appwrite {appwriteReady ? "connected" : "offline"}
            </Chip>
          )}
          <Chip size="sm" className={`status-pill ${metrics.model_status?.available ? "status-good" : "status-muted"}`} variant="flat" startContent={<Sparkles size={13} />}>
            {metrics.model_status?.available ? `ML ${metrics.model_status.version}` : "Rules only"}
          </Chip>
          <Button className="logout-button" size="sm" variant="flat" startContent={<LogOut size={14} />} onPress={handleLogout}>
            Logout
          </Button>
        </div>
      </header>

      <section className="hero-shell">
        <div className="hero-copy">
          <span className="section-kicker">READ-ONLY SOC CONSOLE</span>
          <h2>Premium passive monitoring for synthetic replay and live alert triage.</h2>
          <p>
            Metadata-only analysis. No probes, no decryption, no network-side action. The local replay engine,
            WebSocket alerts, Appwrite persistence, and optional Ollama explanation layer remain unchanged.
          </p>
          <div className="hero-badges">
            <Chip className="status-pill status-good" variant="flat" startContent={<ShieldCheck size={13} />}>
              Passive monitoring
            </Chip>
            <Chip className="status-pill status-muted" variant="flat" startContent={<Lock size={13} />}>
              No decryption
            </Chip>
            <Chip className="status-pill status-muted" variant="flat" startContent={<SquareDashedMousePointer size={13} />}>
              No probes
            </Chip>
          </div>
        </div>
        <div className="hero-telemetry glass-panel">
          <div>
            <span className="section-kicker">ACTIVE SESSION</span>
            <strong>{metrics.scenario ? humanThreat(metrics.scenario) : "No scenario running"}</strong>
          </div>
          <div className="telemetry-grid">
            <div>
              <span>Events</span>
              <strong>{totalEvents.toLocaleString()}</strong>
            </div>
            <div>
              <span>Alerts</span>
              <strong>{totalAlerts.toLocaleString()}</strong>
            </div>
            <div>
              <span>Throughput</span>
              <strong>{eventRate.toLocaleString()} /s</strong>
            </div>
            <div>
              <span>Latency</span>
              <strong>{latency} ms</strong>
            </div>
          </div>
        </div>
      </section>

      <nav className="tabbar glass-panel" aria-label="Dashboard sections">
        {[
          ["overview", "Overview"],
          ["alerts", "Alerts"],
          ["analytics", "Analytics"],
          ["about", "About"],
        ].map(([key, label]) => (
          <button key={key} className={activeTab === key ? "tab active" : "tab"} type="button" onClick={() => setActiveTab(key as typeof activeTab)}>
            {label}
          </button>
        ))}
      </nav>

      <section className="command-strip glass-panel">
        <div className="command-copy">
          <span className="section-kicker">REPLAY CONTROL</span>
          <strong>Simulated monitoring enclave</strong>
          <span>Metadata-only analysis. No probes, payload decryption, or response path.</span>
        </div>
        <div className="command-controls">
          {loading ? (
            <Spinner size="sm" />
          ) : (
            <Select
              aria-label="Traffic scenario"
              className="scenario-select"
              selectedKeys={selectedScenario ? [selectedScenario] : []}
              onSelectionChange={(keys) => setSelectedScenario(String([...keys][0] ?? ""))}
            >
              {scenarios.map((scenario) => (
                <SelectItem key={scenario}>{humanThreat(scenario)}</SelectItem>
              ))}
            </Select>
          )}
          <Dropdown>
            <DropdownTrigger>
              <Button className="speed-button" variant="flat" endContent={<ChevronDown size={15} />} startContent={<Gauge size={15} />}>
                {speed}x
              </Button>
            </DropdownTrigger>
            <DropdownMenu aria-label="Replay speed" onAction={(key) => setSpeed(String(key))}>
              {["1", "4", "8", "12", "20"].map((value) => (
                <DropdownItem key={value}>{value}x</DropdownItem>
              ))}
            </DropdownMenu>
          </Dropdown>
          <Button className="start-button" startContent={<Zap size={16} />} onPress={() => void handleStart()} isDisabled={!selectedScenario || metrics.status === "running"}>
            Start replay
          </Button>
          <Button className="stop-button" variant="flat" color="danger" startContent={<CircleStop size={16} />} onPress={() => void handleStop()} isDisabled={metrics.status !== "running"}>
            Stop
          </Button>
          <Button isIconOnly variant="light" aria-label="Refresh dashboard" onPress={() => void loadInitialData()}>
            <RefreshCw size={17} />
          </Button>
        </div>
        <div className={metrics.running ? "live-indicator live" : "live-indicator"}>
          <span />
          {metrics.running ? "LIVE replay running" : "Idle"}
        </div>
      </section>

      {actionError && <div className="error-banner"><AlertTriangle size={16} />{actionError}</div>}
      {appwriteConfigured && appwriteError && <div className="error-banner"><AlertTriangle size={16} />Appwrite: {appwriteError}</div>}

      {activeTab === "overview" && (
        <>
          <section className="metric-grid">
            <MetricCard label="Events/sec" value={eventRate.toLocaleString()} hint={`${totalEvents.toLocaleString()} processed`} icon={<Activity size={18} />} />
            <MetricCard label="Detections" value={totalAlerts.toLocaleString()} hint="Structured alerts streamed" icon={<AlertTriangle size={18} />} tone="danger" />
            <MetricCard label="Critical / high" value={`${counts.critical ?? 0} / ${counts.high ?? 0}`} hint="Current replay mix" icon={<ShieldCheck size={18} />} tone="warning" />
            <MetricCard label="Latency" value={`${latency} ms`} hint="Target under 2 seconds" icon={<Gauge size={18} />} />
          </section>

          <section className="content-grid">
            <Card className="panel chart-panel glass-panel">
              <CardBody>
                <div className="panel-heading">
                  <div>
                    <span className="section-kicker">TIMELINE</span>
                    <h2>Detection activity</h2>
                  </div>
                  <Chip size="sm" className={metrics.running ? "status-pill status-good pulse" : "status-pill status-muted"} variant="flat">
                    {metrics.running ? "Live" : "Paused"}
                  </Chip>
                </div>
                <div className="chart-wrap chart-large">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={timeline}>
                      <defs>
                        <linearGradient id="timelineStroke" x1="0" y1="0" x2="1" y2="0">
                          <stop offset="0%" stopColor="#22d3ee" />
                          <stop offset="50%" stopColor="#a78bfa" />
                          <stop offset="100%" stopColor="#34d399" />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="rgba(148, 163, 184, 0.12)" strokeDasharray="4 4" vertical={false} />
                      <XAxis dataKey="time" stroke="#8fa3bc" tickLine={false} axisLine={false} />
                      <YAxis allowDecimals={false} stroke="#8fa3bc" tickLine={false} axisLine={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Line type="monotone" dataKey="alerts" stroke="url(#timelineStroke)" strokeWidth={3} dot={{ r: 4, fill: "#7dd3fc" }} activeDot={{ r: 6, fill: "#fff" }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardBody>
            </Card>
            <Card className="panel summary-panel glass-panel">
              <CardBody>
                <div className="panel-heading">
                  <div>
                    <span className="section-kicker">THREAT MIX</span>
                    <h2>Distribution</h2>
                  </div>
                </div>
                <div className="chart-wrap chart-medium">
                  <ResponsiveContainer width="100%" height="100%">
                    {distributionData.length > 0 ? (
                      <PieChart>
                        <Pie data={distributionData} dataKey="count" nameKey="name" innerRadius={52} outerRadius={90} paddingAngle={4}>
                          {distributionData.map((entry) => (
                            <Cell key={entry.raw} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip content={<ChartTooltip />} />
                        <Legend verticalAlign="bottom" iconType="circle" formatter={(value) => <span className="legend-label">{value}</span>} />
                      </PieChart>
                    ) : (
                      <EmptyChartState title="No alerts yet" subtitle="Start a replay to populate the distribution ring." />
                    )}
                  </ResponsiveContainer>
                </div>
                <div className="threat-legend">
                  {distributionData.length > 0 ? (
                    distributionData.map((item) => (
                      <div className="distribution-row" key={item.raw}>
                        <span className="legend-dot" style={{ background: item.color }} />
                        <span>{item.name}</span>
                        <strong>{item.count}</strong>
                      </div>
                    ))
                  ) : (
                    <div className="empty-state">No detections in the current replay.</div>
                  )}
                </div>
                <Divider className="divider" />
                <div className="enclave-note">
                  <ShieldCheck size={17} />
                  <span>
                    Local rules are authoritative{metrics.model_status?.available ? `; ${metrics.model_status.version} model scoring is active` : "; no ML model loaded (rules-only)"}.{metrics.appwrite_status?.enabled ? ` ${metrics.appwrite_status.persisted_count} alerts persisted to Appwrite.` : " Appwrite persistence is off."}{metrics.ollama_status?.available ? " Local Ollama explanations are active." : " LLM explanations are off."} External AI APIs are not required.
                  </span>
                </div>
              </CardBody>
            </Card>
          </section>
        </>
      )}

      {activeTab === "alerts" && (
        <section className="panel alerts-panel glass-panel">
          <div className="panel-heading alerts-heading">
            <div>
              <span className="section-kicker">ALERT STREAM</span>
              <h2>Recent detections</h2>
            </div>
            <span className="muted-label">
              {filteredAlerts.length} visible / {alerts.length} total
            </span>
          </div>
          <div className="alerts-toolbar">
            <label className="search-field">
              <Search size={15} />
              <input
                aria-label="Search alerts"
                type="search"
                placeholder="Search threats, IPs, evidence, detector"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </label>
            <div className="severity-chips" role="group" aria-label="Severity filter">
              {severityOrder.map((severity) => (
                <button key={severity} className={severityFilter === severity ? "severity-chip active" : "severity-chip"} type="button" onClick={() => setSeverityFilter(severity)}>
                  {severity === "all" ? "All" : severityLabel[severity]}
                </button>
              ))}
            </div>
          </div>
          <Table
            aria-label="Recent detections"
            removeWrapper
            isHeaderSticky
            classNames={{ th: "table-head", td: "table-cell", tr: "table-row", wrapper: "table-wrapper" }}
            selectionMode="single"
            onRowAction={(key) => setSelectedAlert(alerts.find((alert) => alert.alert_id === String(key)) ?? null)}
          >
            <TableHeader>
              <TableColumn>SEVERITY</TableColumn>
              <TableColumn>THREAT</TableColumn>
              <TableColumn>SOURCE</TableColumn>
              <TableColumn>DESTINATION</TableColumn>
              <TableColumn>CONFIDENCE</TableColumn>
              <TableColumn>TIME</TableColumn>
            </TableHeader>
            <TableBody emptyContent={<div className="empty-state">No alerts yet — start a replay.</div>} items={filteredAlerts}>
              {(alert) => (
                <TableRow key={alert.alert_id}>
                  <TableCell>
                    <span className={`severity-badge severity-${alert.severity}`}>{severityLabel[alert.severity]}</span>
                  </TableCell>
                  <TableCell>
                    <span className="threat-name">{humanThreat(alert.threat_class)}</span>
                    <span className="detector-name">{alert.detector}</span>
                  </TableCell>
                  <TableCell>
                    <code>{alert.source_ip}</code>
                  </TableCell>
                  <TableCell>
                    <code>{alert.destination_ip}:{alert.flow_id.split(":").pop()}</code>
                  </TableCell>
                  <TableCell>
                    <div className="confidence-cell">
                      <Progress
                        aria-label="Confidence"
                        size="sm"
                        className="confidence-bar"
                        color={alert.severity === "critical" || alert.severity === "high" ? "danger" : alert.severity === "medium" ? "warning" : alert.severity === "low" ? "primary" : "default"}
                        value={alert.confidence * 100}
                      />
                      <span>{Math.round(alert.confidence * 100)}%</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <span className="timestamp">{formatTime(alert.timestamp)}</span>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </section>
      )}

      {activeTab === "analytics" && (
        <section className="analytics-grid">
          <Card className="panel glass-panel">
            <CardBody>
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">SEVERITY</span>
                  <h2>Alert balance</h2>
                </div>
              </div>
              <div className="chart-wrap chart-medium">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={analyticsSeverityData}>
                    <CartesianGrid stroke="rgba(148, 163, 184, 0.12)" strokeDasharray="4 4" vertical={false} />
                    <XAxis dataKey="severity" stroke="#8fa3bc" tickLine={false} axisLine={false} />
                    <YAxis allowDecimals={false} stroke="#8fa3bc" tickLine={false} axisLine={false} />
                    <Tooltip content={<ChartTooltip />} />
                    <Bar dataKey="value" radius={[12, 12, 0, 0]}>
                      {analyticsSeverityData.map((entry) => (
                        <Cell key={entry.severity} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardBody>
          </Card>
          <Card className="panel glass-panel">
            <CardBody>
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">TREND</span>
                  <h2>Alert cadence</h2>
                </div>
              </div>
              <div className="chart-wrap chart-medium">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={analyticsTrendData}>
                    <defs>
                      <linearGradient id="analyticsFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.45} />
                        <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(148, 163, 184, 0.12)" strokeDasharray="4 4" vertical={false} />
                    <XAxis dataKey="label" hide />
                    <YAxis allowDecimals={false} stroke="#8fa3bc" tickLine={false} axisLine={false} />
                    <Tooltip content={<ChartTooltip />} />
                    <Area type="monotone" dataKey="confidence" stroke="#22d3ee" fill="url(#analyticsFill)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardBody>
          </Card>
          <Card className="panel glass-panel">
            <CardBody>
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">THREATS</span>
                  <h2>Top classes</h2>
                </div>
              </div>
              <div className="chart-wrap chart-medium">
                <ResponsiveContainer width="100%" height="100%">
                  {analyticsThreatData.length > 0 ? (
                    <PieChart>
                      <Pie data={analyticsThreatData} dataKey="value" nameKey="name" innerRadius={56} outerRadius={90} paddingAngle={4}>
                        {analyticsThreatData.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip content={<ChartTooltip />} />
                      <Legend verticalAlign="bottom" iconType="circle" formatter={(value) => <span className="legend-label">{value}</span>} />
                    </PieChart>
                  ) : (
                    <EmptyChartState title="No data yet" subtitle="Run a replay to populate analytics." />
                  )}
                </ResponsiveContainer>
              </div>
            </CardBody>
          </Card>
        </section>
      )}

      {activeTab === "about" && (
        <section className="about-panel glass-panel">
          <div className="about-hero">
            <span className="section-kicker">CONCEPT</span>
            <h2>Passive AI cyber-threat detection</h2>
            <p>
              A read-only SOC dashboard for nine threat scenarios with deterministic alerts, local model scoring, and optional explanation output. The interface is intentionally projector-friendly and offline-safe.
            </p>
          </div>
          <div className="about-grid">
            <Card className="mini-card glass-panel">
              <CardBody>
                <span className="section-kicker">THREATS</span>
                <strong>9 replay scenarios</strong>
                <p>{scenarios.length > 0 ? scenarios.map(humanThreat).join(" · ") : "Loading scenario catalog…"}</p>
              </CardBody>
            </Card>
            <Card className="mini-card glass-panel">
              <CardBody>
                <span className="section-kicker">RULES</span>
                <strong>Local-first detection</strong>
                <p>Rule detectors remain authoritative; ML only supplements them.</p>
              </CardBody>
            </Card>
            <Card className="mini-card glass-panel">
              <CardBody>
                <span className="section-kicker">JSON</span>
                <strong>Alert sample</strong>
                <pre>{JSON.stringify(defaultSampleAlert, null, 2)}</pre>
              </CardBody>
            </Card>
          </div>
          <div className="footer-note">Read-only passive monitoring · No probes · No decryption</div>
        </section>
      )}

      <Drawer isOpen={selectedAlert !== null} onOpenChange={(open) => !open && setSelectedAlert(null)} size="lg">
        <DrawerContent>
          {(onClose) =>
            selectedAlert && (
              <>
                <DrawerHeader className="drawer-header">
                  <div>
                    <span className="section-kicker">ALERT DETAILS</span>
                    <h2>{humanThreat(selectedAlert.threat_class)}</h2>
                  </div>
                  <Button isIconOnly variant="light" aria-label="Close alert details" onPress={onClose}>
                    ×
                  </Button>
                </DrawerHeader>
                <DrawerBody>
                  <div className="detail-hero">
                    <span className={`severity-badge severity-${selectedAlert.severity}`}>{severityLabel[selectedAlert.severity]}</span>
                    <strong>{Math.round(selectedAlert.confidence * 100)}% confidence</strong>
                    <span>{selectedAlert.detector}</span>
                  </div>
                  <div className="detail-grid">
                    <Detail label="Severity" value={severityLabel[selectedAlert.severity]} />
                    <Detail label="Threat" value={humanThreat(selectedAlert.threat_class)} />
                    <Detail label="Source" value={selectedAlert.source_ip} />
                    <Detail label="Destination" value={selectedAlert.destination_ip} />
                    <Detail label="Confidence" value={`${Math.round(selectedAlert.confidence * 100)}%`} />
                    <Detail label="Time" value={formatTime(selectedAlert.timestamp)} />
                    <Detail label="Protocol" value={selectedAlert.protocol} />
                    <Detail label="Flow ID" value={selectedAlert.flow_id} />
                  </div>
                  <div className="evidence-heading">
                    <span className="section-kicker">SUPPORTING EVIDENCE</span>
                    <h3>Why this was flagged</h3>
                  </div>
                  <div className="evidence-list">
                    {selectedAlert.evidence.map((item) => (
                      <div className="evidence-item" key={item.feature}>
                        <div>
                          <strong>{item.feature.replaceAll("_", " ")}</strong>
                          <span>{item.reason}</span>
                        </div>
                        <code>{String(item.value)}</code>
                      </div>
                    ))}
                  </div>
                  <div className="explanation-box">
                    <span className="section-kicker">ANALYST EXPLANATION</span>
                    {selectedAlert.explanation ? (
                      <p>{selectedAlert.explanation}</p>
                    ) : metrics.ollama_status?.available ? (
                      <p className="explanation-pending">
                        <Spinner size="sm" /> Generating explanation with the local model…
                      </p>
                    ) : (
                      <p>Deterministic evidence is available. Start Ollama and restart the API to enable local LLM explanations.</p>
                    )}
                  </div>
                  <div className="json-box">
                    <span className="section-kicker">ALERT JSON</span>
                    <pre>{JSON.stringify(selectedAlert, null, 2)}</pre>
                  </div>
                </DrawerBody>
              </>
            )
          }
        </DrawerContent>
      </Drawer>
    </main>
  );
}

function MetricCard({ label, value, hint, icon, tone = "default" }: { label: string; value: string; hint: string; icon: ReactNode; tone?: "default" | "danger" | "warning" }) {
  return (
    <Card className={`metric-card ${tone} glass-panel`}>
      <CardBody>
        <div className="metric-icon">{icon}</div>
        <span className="metric-label">{label}</span>
        <strong className="metric-value">{value}</strong>
        <span className="metric-hint">{hint}</span>
      </CardBody>
    </Card>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="detail-label">{label}</span>
      <code>{value}</code>
    </div>
  );
}

function EmptyChartState({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="empty-chart">
      <strong>{title}</strong>
      <span>{subtitle}</span>
    </div>
  );
}

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="chart-tooltip">
      {label && <div className="chart-tooltip-label">{String(label)}</div>}
      {payload.map((entry: any, index: number) => (
        <div key={`${entry.name ?? index}`} className="chart-tooltip-row">
          <span className="chart-tooltip-swatch" style={{ background: entry.color ?? "#22d3ee" }} />
          <span>{entry.name ?? "Value"}</span>
          <strong>{String(entry.value ?? 0)}</strong>
        </div>
      ))}
    </div>
  );
}

function LoginScreen({
  onDemo,
  onSubmit,
  email,
  password,
  setEmail,
  setPassword,
  error,
}: {
  onDemo: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  email: string;
  password: string;
  setEmail: (value: string) => void;
  setPassword: (value: string) => void;
  error: string;
}) {
  return (
    <main className="login-shell">
      <div className="login-orb orb-a" />
      <div className="login-orb orb-b" />
      <Card className="login-card glass-panel">
        <CardBody>
          <div className="login-brand">
            <div className="brand-mark brand-mark-large">
              <Radar size={22} />
            </div>
            <div>
              <p className="eyebrow">SIH26145 / NTRO</p>
              <h1>Passive Detection Console</h1>
            </div>
          </div>
          <div className="login-copy">
            <span className="section-kicker">READ-ONLY SOC DEMO</span>
            <h2>Dark, glowing threat-monitoring interface for projector demos.</h2>
            <p>Enter any credentials or skip directly into the live dashboard. No backend auth is used.</p>
          </div>
          <form className="login-form" onSubmit={onSubmit}>
            <label>
              <span>Email</span>
              <input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="analyst@soc.local" />
            </label>
            <label>
              <span>Password</span>
              <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" placeholder="Any demo password" />
            </label>
            {error && <div className="login-error">{error}</div>}
            <div className="login-actions">
              <Button className="start-button" type="submit" startContent={<Zap size={16} />}>
                Sign in
              </Button>
              <Button variant="flat" type="button" onPress={onDemo}>
                Enter Demo
              </Button>
            </div>
          </form>
          <div className="login-footnote">Read-only passive monitoring · No probes · No decryption</div>
        </CardBody>
      </Card>
    </main>
  );
}

export default App;
