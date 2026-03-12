import { NextResponse } from "next/server";

const ML_BACKEND_URL = process.env.ML_BACKEND_URL || "http://localhost:8080";

/* ── GET: Proxy ML backend health status ── */
export async function GET() {
  try {
    const res = await fetch(`${ML_BACKEND_URL}/health`, {
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      return NextResponse.json(
        { status: "unhealthy", error: `ML backend returned ${res.status}` },
        { status: 502 }
      );
    }

    const data = await res.json();
    return NextResponse.json({ status: "healthy", ...data });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Connection failed";
    return NextResponse.json(
      { status: "offline", error: message },
      { status: 503 }
    );
  }
}
