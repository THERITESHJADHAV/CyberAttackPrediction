"use client";

import { useState, useEffect, useCallback } from "react";

/* ─── Types ─── */
interface FlowEntry {
  id: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  packets: number;
  bytes: number;
  duration: string;
  status: "safe" | "threat" | "suspicious";
  connState: "CON" | "FIN" | "INT";
  probability: number;
  timestamp: Date;
}

interface ActivityItem {
  id: string;
  type: "safe" | "threat" | "warning" | "info";
  title: string;
  detail: string;
  time: Date;
}

/* ─── Helpers ─── */
const randomIp = () =>
  `${10 + Math.floor(Math.random() * 240)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;

const randomPort = () => [22, 53, 80, 443, 3306, 5432, 8080, 8443, 9090][Math.floor(Math.random() * 9)];

const attackTypes = [
  "DDoS SYN Flood",
  "Port Scan Detected",
  "Brute Force SSH",
  "SQL Injection Attempt",
  "DNS Amplification",
  "HTTP Flood",
  "Slowloris Attack",
];

const formatTime = (d: Date) =>
  d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

const formatBytes = (b: number) => (b > 1_000_000 ? `${(b / 1_000_000).toFixed(1)} MB` : b > 1_000 ? `${(b / 1_000).toFixed(1)} KB` : `${b} B`);

const uid = () => Math.random().toString(36).slice(2, 10);

/* ─── Dashboard Component ─── */
export default function Dashboard() {
  const [flows, setFlows] = useState<FlowEntry[]>([]);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [stats, setStats] = useState({
    totalFlows: 0,
    attacksBlocked: 0,
    safeFlows: 0,
    avgThreatProb: 0,
  });
  const [threatLevel, setThreatLevel] = useState(12);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [isOnline, setIsOnline] = useState(true);

  /* Clock */
  useEffect(() => {
    const t = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  /* Simulate Data */
  const generateFlow = useCallback((): FlowEntry => {
    const prob = Math.random();
    const status: FlowEntry["status"] = prob > 0.85 ? "threat" : prob > 0.7 ? "suspicious" : "safe";
    const connStates: FlowEntry["connState"][] = ["CON", "FIN", "INT"];
    return {
      id: uid(),
      srcIp: randomIp(),
      dstIp: "192.168.0.101",
      srcPort: randomPort(),
      dstPort: randomPort(),
      protocol: Math.random() > 0.3 ? "TCP" : "UDP",
      packets: 2 + Math.floor(Math.random() * 200),
      bytes: 128 + Math.floor(Math.random() * 500000),
      duration: `${(0.01 + Math.random() * 10).toFixed(2)}s`,
      status,
      connState: connStates[Math.floor(Math.random() * 3)],
      probability: Number((status === "threat" ? 0.7 + Math.random() * 0.3 : status === "suspicious" ? 0.4 + Math.random() * 0.3 : Math.random() * 0.3).toFixed(3)),
      timestamp: new Date(),
    };
  }, []);

  const generateActivity = useCallback(
    (flow: FlowEntry): ActivityItem => {
      if (flow.status === "threat") {
        const attack = attackTypes[Math.floor(Math.random() * attackTypes.length)];
        return {
          id: uid(),
          type: "threat",
          title: attack,
          detail: `${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}`,
          time: new Date(),
        };
      }
      if (flow.status === "suspicious") {
        return {
          id: uid(),
          type: "warning",
          title: "Suspicious Activity Flagged",
          detail: `${flow.srcIp}:${flow.srcPort} (prob: ${flow.probability})`,
          time: new Date(),
        };
      }
      return {
        id: uid(),
        type: Math.random() > 0.6 ? "safe" : "info",
        title: Math.random() > 0.5 ? "Normal Traffic Flow" : "Flow Analyzed",
        detail: `${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}`,
        time: new Date(),
      };
    },
    []
  );

  useEffect(() => {
    /* initial batch */
    const initial = Array.from({ length: 8 }, () => generateFlow());
    setFlows(initial);
    setActivity(initial.map(generateActivity));
    setStats({
      totalFlows: initial.length,
      attacksBlocked: initial.filter((f) => f.status === "threat").length,
      safeFlows: initial.filter((f) => f.status === "safe").length,
      avgThreatProb: Number(
        (initial.reduce((s, f) => s + f.probability, 0) / initial.length).toFixed(3)
      ),
    });

    /* continuous stream */
    const interval = setInterval(() => {
      const newFlow = generateFlow();
      setFlows((prev) => [newFlow, ...prev].slice(0, 50));
      setActivity((prev) => [generateActivity(newFlow), ...prev].slice(0, 30));
      setStats((prev) => {
        const totalFlows = prev.totalFlows + 1;
        const attacksBlocked = prev.attacksBlocked + (newFlow.status === "threat" ? 1 : 0);
        const safeFlows = prev.safeFlows + (newFlow.status === "safe" ? 1 : 0);
        const avgThreatProb = Number(
          ((prev.avgThreatProb * prev.totalFlows + newFlow.probability) / totalFlows).toFixed(3)
        );
        return { totalFlows, attacksBlocked, safeFlows, avgThreatProb };
      });
      setThreatLevel((prev) => {
        const delta = newFlow.status === "threat" ? 5 : newFlow.status === "suspicious" ? 1 : -1;
        return Math.max(0, Math.min(100, prev + delta));
      });
    }, 2500);

    /* connectivity check */
    const online = setInterval(async () => {
      try {
        const r = await fetch("/api/healthcheck", { cache: "no-store" });
        setIsOnline(r.ok);
      } catch {
        setIsOnline(false);
      }
    }, 10000);

    return () => {
      clearInterval(interval);
      clearInterval(online);
    };
  }, [generateFlow, generateActivity]);

  /* Gauge SVG helpers */
  const gaugeRadius = 72;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius;
  const gaugeOffset = gaugeCircumference * (1 - threatLevel / 100);
  const gaugeSeverity = threatLevel > 60 ? "high" : threatLevel > 30 ? "medium" : "low";

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
              <div className="header-subtitle">ML-Powered Network Threat Detection</div>
            </div>
          </div>
          <div className="header-status">
            <span className={`status-badge ${isOnline ? "online" : "offline"}`}>
              <span className={`status-dot ${isOnline ? "online" : "offline"}`} />
              {isOnline ? "System Online" : "System Offline"}
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
              ▲ Live monitoring
            </div>
          </div>
          <div className="stat-card red">
            <div className="stat-header">
              <span className="stat-label">Attacks Detected</span>
              <span className="stat-icon">🚨</span>
            </div>
            <div className="stat-value red">{stats.attacksBlocked}</div>
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
            <div className="stat-value purple">{(stats.avgThreatProb * 100).toFixed(1)}%</div>
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
                  <div className="empty-state-sub">The agent will begin capturing traffic shortly.</div>
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
                    {stats.totalFlows - stats.safeFlows - stats.attacksBlocked}
                  </span>
                </div>
                <div className="threat-row">
                  <span className="threat-row-label">🔴 Attacks</span>
                  <span className="threat-row-value danger">{stats.attacksBlocked}</span>
                </div>
                <div className="threat-row">
                  <span className="threat-row-label">📈 Detection Rate</span>
                  <span className="threat-row-value safe">
                    {stats.totalFlows > 0 ? ((stats.attacksBlocked / stats.totalFlows) * 100).toFixed(1) : 0}%
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
                {flows.slice(0, 15).map((f) => (
                  <tr key={f.id} className="fade-in">
                    <td>{formatTime(f.timestamp)}</td>
                    <td>{f.srcIp}:{f.srcPort}</td>
                    <td>{f.dstIp}:{f.dstPort}</td>
                    <td>{f.protocol}</td>
                    <td>{f.packets}</td>
                    <td>{formatBytes(f.bytes)}</td>
                    <td>{f.duration}</td>
                    <td>
                      <span className={`conn-state ${f.connState.toLowerCase()}`}>{f.connState}</span>
                    </td>
                    <td style={{ color: f.probability > 0.7 ? "var(--accent-red)" : f.probability > 0.4 ? "var(--accent-amber)" : "var(--accent-green)" }}>
                      {(f.probability * 100).toFixed(1)}%
                    </td>
                    <td>
                      <span className={`flow-status ${f.status}`}>
                        {f.status === "safe" ? "✅ Safe" : f.status === "threat" ? "🚨 Threat" : "⚠️ Suspicious"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* ── Footer ── */}
        <footer className="footer">
          CyberGuard AI — ML Cyber Attack Prediction System &nbsp;|&nbsp; AutoEncoder + SGD Classifier &nbsp;|&nbsp;
          Powered by <a href="https://nextjs.org" target="_blank" rel="noopener noreferrer">Next.js</a> &amp; Scapy
        </footer>
      </div>
    </>
  );
}
