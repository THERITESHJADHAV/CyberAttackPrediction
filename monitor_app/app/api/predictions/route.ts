import { NextRequest, NextResponse } from "next/server";

/* ── In-memory prediction store ── */
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
  prediction: number;        // 0 = safe, 1 = attack
  attackProbability: number;  // 0.0 – 1.0
  featuresUsed: string[];
  featureSelectionEnabled: boolean;
}

const MAX_ENTRIES = 200;
let predictions: PredictionEntry[] = [];
let idCounter = 0;

/* ── POST: Agent pushes a new prediction ── */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    const entry: PredictionEntry = {
      id: `pred_${++idCounter}`,
      timestamp: body.timestamp || new Date().toISOString(),
      srcIp: body.src_ip || body.srcIp || "unknown",
      dstIp: body.dst_ip || body.dstIp || "unknown",
      srcPort: Number(body.src_port || body.srcPort || 0),
      dstPort: Number(body.dst_port || body.dstPort || 0),
      protocol: String(body.protocol || "TCP").toUpperCase(),
      packets: Number(body.total_packets || body.packets || 0),
      bytes: Number(body.total_bytes || body.bytes || 0),
      duration: Number(body.duration || 0),
      connState: body.connection_state || body.connState || "CON",
      prediction: Number(body.prediction ?? 0),
      attackProbability: Number(body.attack_probability ?? body.attackProbability ?? 0),
      featuresUsed: body.features_used || [],
      featureSelectionEnabled: body.feature_selection_enabled ?? false,
    };

    predictions.unshift(entry);
    if (predictions.length > MAX_ENTRIES) {
      predictions = predictions.slice(0, MAX_ENTRIES);
    }

    return NextResponse.json({ success: true, id: entry.id });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

/* ── GET: Dashboard polls for latest predictions ── */
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const since = url.searchParams.get("since"); // ISO timestamp
  const limit = Math.min(Number(url.searchParams.get("limit") || 100), MAX_ENTRIES);

  let results = predictions;

  if (since) {
    const sinceDate = new Date(since).getTime();
    results = results.filter((p) => new Date(p.timestamp).getTime() > sinceDate);
  }

  results = results.slice(0, limit);

  // Compute summary stats
  const total = predictions.length;
  const attacks = predictions.filter((p) => p.prediction === 1).length;
  const safe = predictions.filter((p) => p.prediction === 0).length;
  const avgProb =
    total > 0
      ? predictions.reduce((sum, p) => sum + p.attackProbability, 0) / total
      : 0;

  return NextResponse.json({
    predictions: results,
    stats: {
      totalFlows: total,
      attacksDetected: attacks,
      safeFlows: safe,
      avgThreatProbability: Number(avgProb.toFixed(4)),
    },
  });
}
