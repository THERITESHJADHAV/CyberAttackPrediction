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

interface AttackNotification {
  id: string;
  severity: "critical" | "high" | "medium";
  title: string;
  message: string;
  srcIp: string;
  dstIp: string;
  probability: number;
  timestamp: Date;
  dismissed: boolean;
}

interface GeoAttacker {
  ip: string;
  lat: number;
  lon: number;
  city: string;
  country: string;
  attackProbability: number;
  attackCount: number;
  lastSeen: string;
  isLocal: boolean;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
declare const L: any;

/* ─── Helpers ─── */
const formatTime = (d: Date | string) => {
  const date = typeof d === "string" ? new Date(d) : d;
  return date.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
};

const formatBytes = (b: number) =>
  b > 1_000_000 ? `${(b / 1_000_000).toFixed(1)} MB` : b > 1_000 ? `${(b / 1_000).toFixed(1)} KB` : `${b} B`;

/* ─── Sound Alert System using Web Audio API ─── */
class AlertSoundSystem {
  private audioContext: AudioContext | null = null;
  private isEnabled: boolean = true;
  private hasInteracted: boolean = false;

  enable() { this.isEnabled = true; }
  disable() { this.isEnabled = false; }
  get enabled() { return this.isEnabled; }

  initContext = () => {
    // If we've already interacted and the context is running, nothing to do
    if (this.hasInteracted && this.audioContext?.state === "running") return;

    try {
      if (!this.audioContext) {
        this.audioContext = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
      }
      if (this.audioContext.state === "suspended") {
        this.audioContext.resume();
      }
      this.hasInteracted = true;
    } catch {
      // ignore
    }
  };

  private getContext(): AudioContext | null {
    if (!this.audioContext) {
      this.initContext();
    }
    return this.audioContext;
  }

  playCriticalAlert() {
    if (!this.isEnabled) return;
    const ctx = this.getContext();
    if (!ctx) return;

    const now = ctx.currentTime;

    // Three-tone urgent alarm: rising pitch siren
    const frequencies = [880, 1100, 1320, 1100, 880, 1100, 1320];
    const noteDuration = 0.12;

    frequencies.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.type = "square";
      osc.frequency.setValueAtTime(freq, now + i * noteDuration);
      gain.gain.setValueAtTime(0.15, now + i * noteDuration);
      gain.gain.exponentialRampToValueAtTime(0.01, now + (i + 1) * noteDuration);

      osc.start(now + i * noteDuration);
      osc.stop(now + (i + 1) * noteDuration);
    });
  }

  playHighAlert() {
    if (!this.isEnabled) return;
    const ctx = this.getContext();
    if (!ctx) return;

    const now = ctx.currentTime;

    // Two-tone warning beep
    [660, 880, 660].forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.type = "triangle";
      osc.frequency.setValueAtTime(freq, now + i * 0.15);
      gain.gain.setValueAtTime(0.12, now + i * 0.15);
      gain.gain.exponentialRampToValueAtTime(0.01, now + (i + 1) * 0.15);

      osc.start(now + i * 0.15);
      osc.stop(now + (i + 1) * 0.15);
    });
  }

  playMediumAlert() {
    if (!this.isEnabled) return;
    const ctx = this.getContext();
    if (!ctx) return;

    const now = ctx.currentTime;

    // Single soft beep
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.type = "sine";
    osc.frequency.setValueAtTime(520, now);
    gain.gain.setValueAtTime(0.08, now);
    gain.gain.exponentialRampToValueAtTime(0.01, now + 0.3);

    osc.start(now);
    osc.stop(now + 0.3);
  }
}

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

  /* ─── Attack Notification State ─── */
  const [notifications, setNotifications] = useState<AttackNotification[]>([]);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [totalAttackAlerts, setTotalAttackAlerts] = useState(0);
  const [showNotifPanel, setShowNotifPanel] = useState(false);
  const [notifHistory, setNotifHistory] = useState<AttackNotification[]>([]);
  const soundSystemRef = useRef<AlertSoundSystem | null>(null);
  const processedAttackIdsRef = useRef<Set<string>>(new Set());

  /* ─── Geo Threat Map State ─── */
  const [geoAttackers, setGeoAttackers] = useState<GeoAttacker[]>([]);
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<any>(null);
  const markersLayerRef = useRef<any>(null);
  const linesLayerRef = useRef<any>(null);

  /* Initialize sound system and interaction listener */
  useEffect(() => {
    soundSystemRef.current = new AlertSoundSystem();

    // Browsers block audio unless the user has interacted with the page.
    const handleUserInteraction = () => {
      soundSystemRef.current?.initContext();
      window.removeEventListener("click", handleUserInteraction);
      window.removeEventListener("keydown", handleUserInteraction);
    };

    window.addEventListener("click", handleUserInteraction);
    window.addEventListener("keydown", handleUserInteraction);

    return () => {
      window.removeEventListener("click", handleUserInteraction);
      window.removeEventListener("keydown", handleUserInteraction);
      soundSystemRef.current = null;
    };
  }, []);

  /* Toggle sound */
  useEffect(() => {
    if (soundSystemRef.current) {
      if (soundEnabled) {
        soundSystemRef.current.enable();
      } else {
        soundSystemRef.current.disable();
      }
    }
  }, [soundEnabled]);

  /* Auto-dismiss notifications after 8 seconds */
  useEffect(() => {
    const timer = setInterval(() => {
      setNotifications((prev) =>
        prev.filter((n) => {
          const age = Date.now() - n.timestamp.getTime();
          return age < 8000 && !n.dismissed;
        })
      );
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  /* Create attack notification */
  const createAttackNotification = useCallback((pred: PredictionEntry) => {
    // Skip if already processed
    if (processedAttackIdsRef.current.has(pred.id)) return;
    processedAttackIdsRef.current.add(pred.id);

    // Keep processed IDs set manageable
    if (processedAttackIdsRef.current.size > 500) {
      const ids = Array.from(processedAttackIdsRef.current);
      processedAttackIdsRef.current = new Set(ids.slice(ids.length - 200));
    }

    const severity: AttackNotification["severity"] =
      pred.attackProbability > 0.8 ? "critical" :
      pred.attackProbability > 0.5 ? "high" : "medium";

    const severityTitles = {
      critical: "🚨 CRITICAL ATTACK DETECTED",
      high: "⚠️ HIGH THREAT DETECTED",
      medium: "🔶 SUSPICIOUS ACTIVITY",
    };

    const severityMessages = {
      critical: `Critical intrusion detected with ${(pred.attackProbability * 100).toFixed(1)}% confidence. Immediate action required!`,
      high: `High-risk traffic detected with ${(pred.attackProbability * 100).toFixed(1)}% attack probability.`,
      medium: `Anomalous network activity detected. Probability: ${(pred.attackProbability * 100).toFixed(1)}%`,
    };

    const notif: AttackNotification = {
      id: `notif_${pred.id}_${Date.now()}`,
      severity,
      title: severityTitles[severity],
      message: severityMessages[severity],
      srcIp: pred.srcIp,
      dstIp: pred.dstIp,
      probability: pred.attackProbability,
      timestamp: new Date(),
      dismissed: false,
    };

    // Add to active notifications (max 5 visible)
    setNotifications((prev) => [notif, ...prev].slice(0, 5));

    // Add to history
    setNotifHistory((prev) => [notif, ...prev].slice(0, 50));

    // Increment attack counter
    setTotalAttackAlerts((prev) => prev + 1);

    // Play sound alert
    if (soundSystemRef.current) {
      switch (severity) {
        case "critical":
          soundSystemRef.current.playCriticalAlert();
          break;
        case "high":
          soundSystemRef.current.playHighAlert();
          break;
        case "medium":
          soundSystemRef.current.playMediumAlert();
          break;
      }
    }
  }, []);

  /* Dismiss notification */
  const dismissNotification = useCallback((id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, dismissed: true } : n))
    );
  }, []);

  /* Clear all notifications */
  const clearAllNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

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

          // ─── ATTACK NOTIFICATION TRIGGER ───
          newPredictions.forEach((pred) => {
            if (pred.prediction === 1) {
              createAttackNotification(pred);
            }
          });
        }
      } catch {
        /* silently retry next interval */
      }
    };

    poll();
    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, [stats, predictionToActivity, createAttackNotification]);

  /* Poll ML status */
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch("/api/ml-status", { cache: "no-store" });
        if (res.ok) {
          const data = await res.json();
          setIsOnline(data.status === "healthy");
          setMlStatus(data.models_loaded ? "Models Ready" : "Models Loading...");
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

  /* ─── Poll Geo API ─── */
  useEffect(() => {
    const pollGeo = async () => {
      try {
        const res = await fetch("/api/geo", { cache: "no-store" });
        if (res.ok) {
          const data = await res.json();
          setGeoAttackers(data.attackers || []);
        }
      } catch {
        /* silently retry */
      }
    };

    pollGeo();
    const interval = setInterval(pollGeo, 5000);
    return () => clearInterval(interval);
  }, []);

  /* ─── Initialize & Update Leaflet Map ─── */
  useEffect(() => {
    if (typeof window === "undefined" || typeof L === "undefined") return;
    if (!mapContainerRef.current) return;

    // Initialize map only once
    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 8,
        zoomControl: true,
        attributionControl: true,
        scrollWheelZoom: true,
      });

      // CartoDB Dark Matter tiles
      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
          subdomains: "abcd",
          maxZoom: 19,
        }
      ).addTo(map);

      // Create layer groups for markers and lines
      markersLayerRef.current = L.layerGroup().addTo(map);
      linesLayerRef.current = L.layerGroup().addTo(map);

      mapInstanceRef.current = map;

      // Fix Leaflet resize issues
      setTimeout(() => map.invalidateSize(), 200);
    }

    // Update markers
    const markers = markersLayerRef.current;
    const lines = linesLayerRef.current;
    if (!markers || !lines) return;

    markers.clearLayers();
    lines.clearLayers();

    // Server marker (your location — centered in India as configured)
    const serverLat = 19.076;
    const serverLon = 72.8777;
    const serverIcon = L.divIcon({
      className: "",
      html: `<div style="width:20px;height:20px;border-radius:50%;background:radial-gradient(circle,#06b6d4 30%,rgba(6,182,212,0.3) 100%);border:3px solid rgba(6,182,212,0.6);box-shadow:0 0 20px rgba(6,182,212,0.5),0 0 40px rgba(6,182,212,0.2);animation:serverPulse 3s ease-in-out infinite;"></div>`,
      iconSize: [20, 20],
      iconAnchor: [10, 10],
    });
    const serverMarker = L.marker([serverLat, serverLon], { icon: serverIcon, zIndexOffset: 1000 });
    serverMarker.bindTooltip(
      `<div class="attack-tooltip"><div class="tooltip-ip">🛡️ Your Server</div><div class="tooltip-location">Mumbai, India</div></div>`,
      { className: "attack-tooltip", direction: "top", offset: [0, -14] }
    );
    markers.addLayer(serverMarker);

    // Add attacker markers
    geoAttackers.forEach((attacker) => {
      const severity =
        attacker.attackProbability > 0.8
          ? "critical"
          : attacker.attackProbability > 0.5
          ? "high"
          : "medium";

      const markerSize =
        severity === "critical" ? 20 : severity === "high" ? 16 : 12;

      const colors: Record<string, {bg: string; border: string; shadow: string}> = {
        critical: { bg: "radial-gradient(circle,#ef4444 35%,rgba(239,68,68,0.4) 100%)", border: "rgba(239,68,68,0.7)", shadow: "0 0 20px rgba(239,68,68,0.6),0 0 40px rgba(239,68,68,0.25)" },
        high: { bg: "radial-gradient(circle,#f97316 35%,rgba(249,115,22,0.4) 100%)", border: "rgba(249,115,22,0.7)", shadow: "0 0 16px rgba(249,115,22,0.5),0 0 30px rgba(249,115,22,0.2)" },
        medium: { bg: "radial-gradient(circle,#f59e0b 35%,rgba(245,158,11,0.4) 100%)", border: "rgba(245,158,11,0.6)", shadow: "0 0 12px rgba(245,158,11,0.4)" },
      };
      const c = colors[severity];

      const icon = L.divIcon({
        className: "",
        html: `<div style="width:${markerSize}px;height:${markerSize}px;border-radius:50%;background:${c.bg};border:2px solid ${c.border};box-shadow:${c.shadow};animation:markerPulse${severity === 'critical' ? 'Critical' : ''} ${severity === 'critical' ? '1.5' : '2'}s ease-in-out infinite;cursor:pointer;"></div>`,
        iconSize: [markerSize, markerSize],
        iconAnchor: [markerSize / 2, markerSize / 2],
      });

      const marker = L.marker([attacker.lat, attacker.lon], {
        icon,
        zIndexOffset: severity === "critical" ? 900 : severity === "high" ? 800 : 700,
      });

      // Tooltip
      const probPercent = (attacker.attackProbability * 100).toFixed(1);
      marker.bindTooltip(
        `<div class="attack-tooltip">` +
          `<div class="tooltip-ip">${attacker.ip}</div>` +
          `<div class="tooltip-location">📍 ${attacker.city}, ${attacker.country}</div>` +
          `<div class="tooltip-prob ${severity}">🎯 ${probPercent}% threat · ${attacker.attackCount} attacks</div>` +
        `</div>`,
        { className: "attack-tooltip", direction: "top", offset: [0, -(markerSize / 2 + 4)] }
      );

      // Popup with details
      marker.bindPopup(
        `<div>` +
          `<div class="popup-title">${severity === "critical" ? "🚨" : severity === "high" ? "⚠️" : "🔶"} Attacker Details</div>` +
          `<div class="popup-row"><span class="popup-label">IP Address</span><span class="popup-value">${attacker.ip}</span></div>` +
          `<div class="popup-row"><span class="popup-label">Location</span><span class="popup-value">${attacker.city}, ${attacker.country}</span></div>` +
          `<div class="popup-row"><span class="popup-label">Coordinates</span><span class="popup-value">${attacker.lat.toFixed(2)}, ${attacker.lon.toFixed(2)}</span></div>` +
          `<div class="popup-row"><span class="popup-label">Threat Level</span><span class="popup-value" style="color:${severity === "critical" ? "#ef4444" : severity === "high" ? "#f97316" : "#f59e0b"}">${probPercent}%</span></div>` +
          `<div class="popup-row"><span class="popup-label">Attack Count</span><span class="popup-value">${attacker.attackCount}</span></div>` +
          `<div class="popup-row"><span class="popup-label">Last Seen</span><span class="popup-value">${new Date(attacker.lastSeen).toLocaleTimeString()}</span></div>` +
          `<div class="popup-row"><span class="popup-label">Source</span><span class="popup-value">${attacker.isLocal ? "Local (Demo)" : "Real GeoIP"}</span></div>` +
        `</div>`,
        { maxWidth: 300 }
      );

      markers.addLayer(marker);

      // Connection line from attacker to server
      const lineColor =
        severity === "critical"
          ? "rgba(239, 68, 68, 0.4)"
          : severity === "high"
          ? "rgba(249, 115, 22, 0.3)"
          : "rgba(245, 158, 11, 0.25)";

      const line = L.polyline(
        [
          [attacker.lat, attacker.lon],
          [serverLat, serverLon],
        ],
        {
          color: lineColor,
          weight: severity === "critical" ? 2.5 : 2,
          dashArray: severity === "critical" ? "8,4" : "6,4",
          opacity: 0.9,
        }
      );
      lines.addLayer(line);
    });
  }, [geoAttackers]);

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

      {/* ── Attack Notification Toasts ── */}
      <div className="notification-container" id="notification-container">
        {notifications
          .filter((n) => !n.dismissed)
          .map((notif, index) => (
            <div
              key={notif.id}
              className={`attack-toast ${notif.severity} ${index === 0 ? "toast-enter" : ""}`}
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className="toast-severity-bar" />
              <div className="toast-content">
                <div className="toast-header">
                  <span className="toast-title">{notif.title}</span>
                  <button
                    className="toast-close"
                    onClick={() => dismissNotification(notif.id)}
                    aria-label="Dismiss notification"
                  >
                    ✕
                  </button>
                </div>
                <p className="toast-message">{notif.message}</p>
                <div className="toast-meta">
                  <span className="toast-meta-item">
                    📡 {notif.srcIp} → {notif.dstIp}
                  </span>
                  <span className="toast-meta-item">
                    🎯 {(notif.probability * 100).toFixed(1)}%
                  </span>
                  <span className="toast-meta-item">
                    🕐 {formatTime(notif.timestamp)}
                  </span>
                </div>
                <div className="toast-progress">
                  <div className={`toast-progress-bar ${notif.severity}`} />
                </div>
              </div>
            </div>
          ))}
      </div>

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
            {/* Sound Toggle */}
            <button
              className={`sound-toggle ${soundEnabled ? "on" : "off"}`}
              onClick={() => setSoundEnabled(!soundEnabled)}
              title={soundEnabled ? "Sound alerts ON — Click to mute" : "Sound alerts OFF — Click to unmute"}
              id="sound-toggle-btn"
            >
              {soundEnabled ? "🔊" : "🔇"}
            </button>

            {/* Attack Alert Badge */}
            <button
              className={`alert-badge-btn ${totalAttackAlerts > 0 ? "has-alerts" : ""}`}
              onClick={() => setShowNotifPanel(!showNotifPanel)}
              title="View attack notifications"
              id="alert-badge-btn"
            >
              🔔
              {totalAttackAlerts > 0 && (
                <span className="alert-count">{totalAttackAlerts > 99 ? "99+" : totalAttackAlerts}</span>
              )}
            </button>

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

        {/* ── Notification History Panel ── */}
        {showNotifPanel && (
          <div className="notif-panel-overlay" onClick={() => setShowNotifPanel(false)}>
            <div className="notif-panel" onClick={(e) => e.stopPropagation()}>
              <div className="notif-panel-header">
                <h3>🔔 Attack Alert History</h3>
                <div className="notif-panel-actions">
                  <button
                    className="notif-clear-btn"
                    onClick={() => {
                      setNotifHistory([]);
                      setTotalAttackAlerts(0);
                      clearAllNotifications();
                    }}
                  >
                    Clear All
                  </button>
                  <button
                    className="notif-close-btn"
                    onClick={() => setShowNotifPanel(false)}
                  >
                    ✕
                  </button>
                </div>
              </div>
              <div className="notif-panel-body">
                {notifHistory.length === 0 ? (
                  <div className="notif-empty">
                    <div className="notif-empty-icon">🛡️</div>
                    <p>No attack alerts yet</p>
                    <p className="notif-empty-sub">Alerts will appear here when threats are detected</p>
                  </div>
                ) : (
                  notifHistory.map((notif) => (
                    <div key={notif.id} className={`notif-history-item ${notif.severity}`}>
                      <div className={`notif-severity-dot ${notif.severity}`} />
                      <div className="notif-history-content">
                        <div className="notif-history-title">{notif.title}</div>
                        <div className="notif-history-msg">{notif.message}</div>
                        <div className="notif-history-meta">
                          {notif.srcIp} → {notif.dstIp} · {formatTime(notif.timestamp)}
                        </div>
                      </div>
                      <div className={`notif-prob ${notif.severity}`}>
                        {(notif.probability * 100).toFixed(0)}%
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

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
          <div className={`stat-card red ${stats.attacksDetected > 0 ? "attack-pulse" : ""}`}>
            <div className="stat-header">
              <span className="stat-label">Attacks Detected</span>
              <span className="stat-icon">🚨</span>
            </div>
            <div className="stat-value red">{stats.attacksDetected}</div>
            <div className="stat-change neutral">
              {stats.attacksDetected > 0 ? `🔴 ${totalAttackAlerts} alerts triggered` : "ML classification active"}
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
              Random Forest
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
        {/* NOTE: Global Threat Map is placed after the flow table below */}
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
                      <tr key={f.id} className={`fade-in ${verdict === "threat" ? "threat-row-highlight" : ""}`}>
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

        {/* ── Global Threat Map ── */}
        <section className="threat-map-section" id="threat-map-section">
          <div className="panel threat-map-container">
            <div className="panel-header">
              <span className="panel-title">
                <span className="panel-title-icon">🌍</span>
                Global Threat Map
              </span>
              <span className="panel-badge live">● LIVE</span>
            </div>
            <div className="threat-map" style={{ position: "relative" }}>
              <div ref={mapContainerRef} style={{ width: "100%", height: "100%" }} id="threat-map" />
              {geoAttackers.length === 0 && (
                <div className="map-empty">
                  <div className="map-empty-icon">🌐</div>
                  <div className="map-empty-text">No attack origins detected yet</div>
                  <div className="map-empty-sub">Attacker locations will appear when threats are identified</div>
                </div>
              )}
            </div>
            <div className="map-stats">
              <div className="map-stat">
                <span>🎯 Active Attackers:</span>
                <span className="map-stat-value">{geoAttackers.length}</span>
              </div>
              <div className="map-stat">
                <span>🚨 Critical:</span>
                <span className="map-stat-value" style={{ color: "var(--accent-red)" }}>
                  {geoAttackers.filter((a) => a.attackProbability > 0.8).length}
                </span>
              </div>
              <div className="map-stat">
                <span>⚠️ High:</span>
                <span className="map-stat-value" style={{ color: "#f97316" }}>
                  {geoAttackers.filter((a) => a.attackProbability > 0.5 && a.attackProbability <= 0.8).length}
                </span>
              </div>
              <div className="map-stat">
                <span>🌍 Countries:</span>
                <span className="map-stat-value">
                  {new Set(geoAttackers.map((a) => a.country)).size}
                </span>
              </div>
            </div>
            <div className="map-legend">
              <div className="legend-item">
                <span className="legend-dot critical" />
                <span>Critical (&gt;80%)</span>
              </div>
              <div className="legend-item">
                <span className="legend-dot high" />
                <span>High (&gt;50%)</span>
              </div>
              <div className="legend-item">
                <span className="legend-dot medium" />
                <span>Medium</span>
              </div>
              <div className="legend-item">
                <span className="legend-dot server" />
                <span>Your Server</span>
              </div>
            </div>
          </div>
        </section>

        {/* ── Footer ── */}
        <footer className="footer">
          CyberGuard AI — ML Cyber Attack Prediction System &nbsp;|&nbsp; Random Forest Classifier &nbsp;|&nbsp;
          Local Mode — All predictions from real captured traffic
        </footer>
      </div>
    </>
  );
}
