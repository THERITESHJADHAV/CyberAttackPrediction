"use client";

import { useState, useEffect, useRef, useCallback } from "react";

/* ─── Types ─── */
interface PredictionEntry {
  id: string;
  timestamp: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  packets: number;
  bytes: number;
  duration: number;
  connState: string;
  prediction: number;
  attackProbability: number;
  featuresUsed: string[];
  featureSelectionEnabled: boolean;
}

interface Stats {
  totalFlows: number;
  attacksDetected: number;
  safeFlows: number;
  avgThreatProbability: number;
}

interface ActivityItem {
  id: string;
  type: "safe" | "threat" | "warning" | "info";
  title: string;
  detail: string;
  time: string;
}

/* ─── Helpers ─── */
const formatTime = (d: Date | string) => {
  const date = typeof d === "string" ? new Date(d) : d;
  return date.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
};

const formatBytes = (b: number) =>
  b > 1_000_000 ? `${(b / 1_000_000).toFixed(1)} MB` : b > 1_000 ? `${(b / 1_000).toFixed(1)} KB` : `${b} B`;

/* ─── Dashboard Component ─── */
export default function Dashboard() {
  const [flows, setFlows] = useState<PredictionEntry[]>([]);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [stats, setStats] = useState<Stats>({ totalFlows: 0, attacksDetected: 0, safeFlows: 0, avgThreatProbability: 0 });
  const [threatLevel, setThreatLevel] = useState(0);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [isOnline, setIsOnline] = useState(false);
  const [mlStatus, setMlStatus] = useState<string>("checking...");
  const [agentConnected, setAgentConnected] = useState(false);
  const prevFlowCountRef = useRef(0);
  const lastTimestampRef = useRef<string | null>(null);

  /* Clock */
  useEffect(() => {
    const t = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  /* Convert prediction to activity item */
  const predictionToActivity = useCallback((pred: PredictionEntry): ActivityItem => {
    const status = pred.prediction === 1
      ? (pred.attackProbability > 0.8 ? "threat" : "warning")
      : "safe";

    const titles: Record<string, string[]> = {
      threat: ["⚠️ Attack Detected", "🚨 Intrusion Alert", "🔴 Malicious Traffic"],
      warning: ["🟡 Suspicious Activity", "⚠️ Anomaly Detected"],
      safe: ["✅ Normal Traffic", "🟢 Benign Flow"],
    };

    const titleList = titles[status] || titles.safe;
    const title = titleList[Math.floor(Math.random() * titleList.length)];

    return {
      id: pred.id,
      type: status === "threat" ? "threat" : status === "warning" ? "warning" : pred.attackProbability > 0.1 ? "info" : "safe",
      title,
      detail: `${pred.srcIp}:${pred.srcPort} → ${pred.dstIp}:${pred.dstPort} (${(pred.attackProbability * 100).toFixed(1)}%)`,
      time: pred.timestamp,
    };
  }, []);

  /* Poll predictions API */
  useEffect(() => {
    const poll = async () => {
      try {
        const params = lastTimestampRef.current ? `?since=${encodeURIComponent(lastTimestampRef.current)}` : "";
        const res = await fetch(`/api/predictions${params}`, { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();

        const newPredictions: PredictionEntry[] = data.predictions || [];
        const serverStats: Stats = data.stats || stats;

        // Update stats
        setStats(serverStats);

        // Check if agent is sending data
        if (serverStats.totalFlows > prevFlowCountRef.current) {
          setAgentConnected(true);
          prevFlowCountRef.current = serverStats.totalFlows;
        }

        // Add new flows
        if (newPredictions.length > 0) {
          lastTimestampRef.current = newPredictions[0].timestamp;

          setFlows((prev) => {
            const existingIds = new Set(prev.map((f) => f.id));
            const unique = newPredictions.filter((p) => !existingIds.has(p.id));
            return [...unique, ...prev].slice(0, 50);
          });

          setActivity((prev) => {
            const existingIds = new Set(prev.map((a) => a.id));
            const newActivities = newPredictions
              .filter((p) => !existingIds.has(p.id))
              .map(predictionToActivity);
            return [...newActivities, ...prev].slice(0, 30);
          });

          // Update threat level based on recent predictions
          setThreatLevel(() => {
            const recent = newPredictions.slice(0, 20);
            if (recent.length === 0) return 0;
            const avgProb = recent.reduce((s, p) => s + p.attackProbability, 0) / recent.length;
            return Math.round(avgProb * 100);
          });
        }
      } catch {
        /* silently retry next interval */
      }
    };

    poll();
    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, [stats, predictionToActivity]);

  /* Poll ML status */
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch("/api/ml-status", { cache: "no-store" });
        if (res.ok) {
          const data = await res.json();
          setIsOnline(data.status === "healthy");
          setMlStatus(data.incremental_models_ready ? "Models Ready" : "Models Loading...");
        } else {
          setIsOnline(false);
          setMlStatus("ML Backend Offline");
        }
      } catch {
        setIsOnline(false);
        setMlStatus("ML Backend Offline");
      }
    };

    check();
    const interval = setInterval(check, 10000);
    return () => clearInterval(interval);
  }, []);

  /* Compute threat level from all flows */
  useEffect(() => {
    if (flows.length === 0) return;
    const attacks = flows.filter((f) => f.prediction === 1).length;
    const ratio = attacks / flows.length;
    setThreatLevel(Math.round(ratio * 100));
  }, [flows]);

  /* Gauge SVG helpers */
  const gaugeRadius = 72;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius;
  const gaugeOffset = gaugeCircumference * (1 - threatLevel / 100);
  const gaugeSeverity = threatLevel > 60 ? "high" : threatLevel > 30 ? "medium" : "low";

  /* Flow verdict */
  const getVerdict = (p: PredictionEntry) => {
    if (p.prediction === 1 && p.attackProbability > 0.7) return "threat";
    if (p.prediction === 1 || p.attackProbability > 0.4) return "suspicious";
    return "safe";
  };

  return (
    <>
      <div className="bg-grid" />
      <div className="scan-line" />

      <div className="app-container">
        {/* ── Header ── */}
        <header className="header">
          <div className="header-brand">
            <div className="header-logo">🛡️</div>
            <div>
              <div className="header-title">CyberGuard AI</div>
              <div className="header-subtitle">ML-Powered Network Threat Detection — Local Mode</div>
            </div>
          </div>
          <div className="header-status">
            <span className={`status-badge ${isOnline ? "online" : "offline"}`}>
              <span className={`status-dot ${isOnline ? "online" : "offline"}`} />
              {isOnline ? mlStatus : "ML Offline"}
            </span>
            <span className={`status-badge ${agentConnected ? "online" : "offline"}`}>
              <span className={`status-dot ${agentConnected ? "online" : "offline"}`} />
              {agentConnected ? "Agent Connected" : "Waiting for Agent"}
            </span>
            <span className="header-time">{formatTime(currentTime)}</span>
          </div>
        </header>

        {/* ── Stats ── */}
        <section className="stats-grid">
          <div className="stat-card cyan">
            <div className="stat-header">
              <span className="stat-label">Total Flows</span>
              <span className="stat-icon">📊</span>
            </div>
            <div className="stat-value cyan">{stats.totalFlows.toLocaleString()}</div>
            <div className="stat-change up">
              {agentConnected ? "▲ Live capture" : "⏳ Waiting for packets"}
            </div>
          </div>
          <div className="stat-card red">
            <div className="stat-header">
              <span className="stat-label">Attacks Detected</span>
              <span className="stat-icon">🚨</span>
            </div>
            <div className="stat-value red">{stats.attacksDetected}</div>
            <div className="stat-change neutral">
              ML classification active
            </div>
          </div>
          <div className="stat-card green">
            <div className="stat-header">
              <span className="stat-label">Safe Flows</span>
              <span className="stat-icon">✅</span>
            </div>
            <div className="stat-value green">{stats.safeFlows}</div>
            <div className="stat-change up">
              ▲ {stats.totalFlows > 0 ? ((stats.safeFlows / stats.totalFlows) * 100).toFixed(1) : 0}% clean
            </div>
          </div>
          <div className="stat-card purple">
            <div className="stat-header">
              <span className="stat-label">Avg Threat Prob</span>
              <span className="stat-icon">🧠</span>
            </div>
            <div className="stat-value purple">{(stats.avgThreatProbability * 100).toFixed(1)}%</div>
            <div className="stat-change neutral">
              AutoEncoder + SGD
            </div>
          </div>
        </section>

        {/* ── Main Content ── */}
        <section className="content-grid">
          {/* Activity Feed */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">
                <span className="panel-title-icon">📡</span>
                Live Activity Feed
              </span>
              <span className="panel-badge live">● Live</span>
            </div>
            <div className="panel-body">
              {activity.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-state-icon">📡</div>
                  <div className="empty-state-text">Waiting for network flows...</div>
                  <div className="empty-state-sub">
                    {isOnline
                      ? "Start the network agent to begin capturing traffic."
                      : "Start the ML backend and network agent."}
                  </div>
                </div>
              ) : (
                <div className="activity-feed">
                  {activity.map((item) => (
                    <div className="activity-item fade-in" key={item.id}>
                      <div className={`activity-indicator ${item.type}`}>
                        {item.type === "threat" ? "⚠️" : item.type === "warning" ? "🔶" : item.type === "safe" ? "✅" : "ℹ️"}
                      </div>
                      <div className="activity-content">
                        <div className="activity-title">{item.title}</div>
                        <div className="activity-detail">{item.detail}</div>
                      </div>
                      <span className="activity-time">{formatTime(item.time)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Threat Gauge */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">
                <span className="panel-title-icon">🎯</span>
                Threat Level
              </span>
              <span className="panel-badge info">Real-time</span>
            </div>
            <div className="threat-gauge">
              <div className="gauge-ring">
                <svg viewBox="0 0 160 160">
                  <circle className="gauge-bg" cx="80" cy="80" r={gaugeRadius} />
                  <circle
                    className={`gauge-fill ${gaugeSeverity}`}
                    cx="80"
                    cy="80"
                    r={gaugeRadius}
                    strokeDasharray={gaugeCircumference}
                    strokeDashoffset={gaugeOffset}
                  />
                </svg>
                <div className="gauge-center">
                  <div className={`gauge-value ${gaugeSeverity}`}>{threatLevel}</div>
                  <div className="gauge-label">
                    {gaugeSeverity === "high" ? "Critical" : gaugeSeverity === "medium" ? "Elevated" : "Normal"}
                  </div>
                </div>
              </div>
              <div className="threat-details">
                <div className="threat-row">
                  <span className="threat-row-label">🟢 Benign Traffic</span>
                  <span className="threat-row-value safe">{stats.safeFlows}</span>
                </div>
                <div className="threat-row">
                  <span className="threat-row-label">🟡 Suspicious</span>
                  <span className="threat-row-value warning">
                    {flows.filter((f) => f.prediction === 1 && f.attackProbability <= 0.7).length}
                  </span>
                </div>
                <div className="threat-row">
                  <span className="threat-row-label">🔴 Attacks</span>
                  <span className="threat-row-value danger">{stats.attacksDetected}</span>
                </div>
                <div className="threat-row">
                  <span className="threat-row-label">📈 Detection Rate</span>
                  <span className="threat-row-value safe">
                    {stats.totalFlows > 0 ? ((stats.attacksDetected / stats.totalFlows) * 100).toFixed(1) : 0}%
                  </span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── Flow Table ── */}
        <section className="panel" style={{ marginBottom: 28 }}>
          <div className="panel-header">
            <span className="panel-title">
              <span className="panel-title-icon">🔍</span>
              Recent Network Flows
            </span>
            <span className="panel-badge info">{flows.length} flows</span>
          </div>
          <div className="flow-table-wrapper">
            <table className="flow-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Packets</th>
                  <th>Data</th>
                  <th>Duration</th>
                  <th>State</th>
                  <th>ML Probability</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {flows.length === 0 ? (
                  <tr>
                    <td colSpan={10} style={{ textAlign: "center", padding: "32px", color: "var(--text-muted)" }}>
                      No flows captured yet. Start the network agent to begin monitoring.
                    </td>
                  </tr>
                ) : (
                  flows.slice(0, 15).map((f) => {
                    const verdict = getVerdict(f);
                    return (
                      <tr key={f.id} className="fade-in">
                        <td>{formatTime(f.timestamp)}</td>
                        <td>{f.srcIp}:{f.srcPort}</td>
                        <td>{f.dstIp}:{f.dstPort}</td>
                        <td>{f.protocol}</td>
                        <td>{f.packets}</td>
                        <td>{formatBytes(f.bytes)}</td>
                        <td>{f.duration.toFixed(2)}s</td>
                        <td>
                          <span className={`conn-state ${f.connState.toLowerCase()}`}>{f.connState}</span>
                        </td>
                        <td style={{ color: f.attackProbability > 0.7 ? "var(--accent-red)" : f.attackProbability > 0.4 ? "var(--accent-amber)" : "var(--accent-green)" }}>
                          {(f.attackProbability * 100).toFixed(1)}%
                        </td>
                        <td>
                          <span className={`flow-status ${verdict}`}>
                            {verdict === "safe" ? "✅ Safe" : verdict === "threat" ? "🚨 Threat" : "⚠️ Suspicious"}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* ── Footer ── */}
        <footer className="footer">
          CyberGuard AI — ML Cyber Attack Prediction System &nbsp;|&nbsp; AutoEncoder + SGD Classifier &nbsp;|&nbsp;
          Local Mode — All predictions from real captured traffic
        </footer>
      </div>
    </>
  );
}
