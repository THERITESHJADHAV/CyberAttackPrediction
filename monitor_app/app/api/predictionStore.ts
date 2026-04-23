/**
 * Shared in-memory prediction store.
 * Both the predictions API route and the geo route read from this store.
 */

export interface PredictionEntry {
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

export function addPrediction(entry: Omit<PredictionEntry, "id">): string {
  const id = `pred_${++idCounter}`;
  const full: PredictionEntry = { ...entry, id };
  predictions.unshift(full);
  if (predictions.length > MAX_ENTRIES) {
    predictions = predictions.slice(0, MAX_ENTRIES);
  }
  return id;
}

export function getPredictions(): PredictionEntry[] {
  return predictions;
}

export function getIdCounter(): number {
  return idCounter;
}
