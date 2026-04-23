import { NextResponse } from "next/server";
import { getPredictions } from "../predictionStore";

/* ── Types ── */
interface GeoEntry {
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

/* ── In-memory geo cache ── */
const geoCache = new Map<string, { lat: number; lon: number; city: string; country: string; isLocal: boolean }>();

/* ── Helper: detect private / local IPs ── */
function isPrivateIp(ip: string): boolean {
  if (ip === "unknown") return true;
  return (
    ip.startsWith("127.") ||
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.16.") || ip.startsWith("172.17.") || ip.startsWith("172.18.") ||
    ip.startsWith("172.19.") || ip.startsWith("172.20.") || ip.startsWith("172.21.") ||
    ip.startsWith("172.22.") || ip.startsWith("172.23.") || ip.startsWith("172.24.") ||
    ip.startsWith("172.25.") || ip.startsWith("172.26.") || ip.startsWith("172.27.") ||
    ip.startsWith("172.28.") || ip.startsWith("172.29.") || ip.startsWith("172.30.") ||
    ip.startsWith("172.31.") ||
    ip === "0.0.0.0" ||
    ip === "::1" ||
    ip === "localhost"
  );
}

/* ── Demo coordinates for local IPs ── */
const DEMO_LOCATIONS = [
  { lat: 55.7558, lon: 37.6176, city: "Moscow", country: "Russia" },
  { lat: 39.9042, lon: 116.4074, city: "Beijing", country: "China" },
  { lat: 28.6139, lon: 77.2090, city: "New Delhi", country: "India" },
  { lat: -23.5505, lon: -46.6333, city: "São Paulo", country: "Brazil" },
  { lat: 37.5665, lon: 126.9780, city: "Seoul", country: "South Korea" },
  { lat: 51.5074, lon: -0.1278, city: "London", country: "United Kingdom" },
  { lat: 48.8566, lon: 2.3522, city: "Paris", country: "France" },
  { lat: 35.6762, lon: 139.6503, city: "Tokyo", country: "Japan" },
  { lat: 40.7128, lon: -74.0060, city: "New York", country: "United States" },
  { lat: -33.8688, lon: 151.2093, city: "Sydney", country: "Australia" },
  { lat: 1.3521, lon: 103.8198, city: "Singapore", country: "Singapore" },
  { lat: 52.5200, lon: 13.4050, city: "Berlin", country: "Germany" },
  { lat: 41.0082, lon: 28.9784, city: "Istanbul", country: "Turkey" },
  { lat: -1.2921, lon: 36.8219, city: "Nairobi", country: "Kenya" },
  { lat: 19.4326, lon: -99.1332, city: "Mexico City", country: "Mexico" },
  { lat: 25.2048, lon: 55.2708, city: "Dubai", country: "UAE" },
  { lat: 59.3293, lon: 18.0686, city: "Stockholm", country: "Sweden" },
  { lat: -34.6037, lon: -58.3816, city: "Buenos Aires", country: "Argentina" },
  { lat: 33.8688, lon: 35.4955, city: "Beirut", country: "Lebanon" },
  { lat: 6.5244, lon: 3.3792, city: "Lagos", country: "Nigeria" },
];

let demoIndex = 0;

function getDemoLocation(ip: string) {
  // Deterministic assignment based on IP to ensure consistency
  const cached = geoCache.get(ip);
  if (cached) return cached;

  const loc = DEMO_LOCATIONS[demoIndex % DEMO_LOCATIONS.length];
  // Add slight randomization so multiple local IPs don't stack
  const jitter = () => (Math.random() - 0.5) * 4;
  const result = {
    lat: loc.lat + jitter(),
    lon: loc.lon + jitter(),
    city: loc.city,
    country: loc.country,
    isLocal: true,
  };
  geoCache.set(ip, result);
  demoIndex++;
  return result;
}

/* ── Fetch real geolocation from ip-api.com ── */
async function fetchGeoLocation(ip: string): Promise<{ lat: number; lon: number; city: string; country: string; isLocal: boolean }> {
  const cached = geoCache.get(ip);
  if (cached) return cached;

  if (isPrivateIp(ip)) {
    return getDemoLocation(ip);
  }

  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`, {
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.status === "success") {
        const result = {
          lat: data.lat,
          lon: data.lon,
          city: data.city || "Unknown",
          country: data.country || "Unknown",
          isLocal: false,
        };
        geoCache.set(ip, result);
        return result;
      }
    }
  } catch {
    // API failure — fall back to demo
  }

  return getDemoLocation(ip);
}

/* ── GET: Return geo-located attacker IPs ── */
export async function GET() {
  const predictions = getPredictions();

  // Group attack predictions by source IP
  const attackerMap = new Map<string, { totalProb: number; count: number; lastSeen: string }>();

  for (const pred of predictions) {
    if (pred.prediction === 1) {
      const existing = attackerMap.get(pred.srcIp);
      if (existing) {
        existing.totalProb += pred.attackProbability;
        existing.count += 1;
        if (pred.timestamp > existing.lastSeen) {
          existing.lastSeen = pred.timestamp;
        }
      } else {
        attackerMap.set(pred.srcIp, {
          totalProb: pred.attackProbability,
          count: 1,
          lastSeen: pred.timestamp,
        });
      }
    }
  }

  // Resolve geolocation for each attacker IP
  const geoEntries: GeoEntry[] = [];

  for (const [ip, data] of attackerMap.entries()) {
    const geo = await fetchGeoLocation(ip);
    geoEntries.push({
      ip,
      lat: geo.lat,
      lon: geo.lon,
      city: geo.city,
      country: geo.country,
      attackProbability: data.totalProb / data.count,
      attackCount: data.count,
      lastSeen: data.lastSeen,
      isLocal: geo.isLocal,
    });
  }

  return NextResponse.json({
    attackers: geoEntries,
    totalAttackers: geoEntries.length,
    cacheSize: geoCache.size,
  });
}
