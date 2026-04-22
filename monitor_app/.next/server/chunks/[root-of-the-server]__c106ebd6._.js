module.exports = {

"[project]/.next-internal/server/app/api/predictions/route/actions.js [app-rsc] (server actions loader, ecmascript)": ((__turbopack_context__) => {

var { m: module, e: exports } = __turbopack_context__;
{
}}),
"[externals]/next/dist/compiled/next-server/app-route-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-route-turbo.runtime.dev.js, cjs)": ((__turbopack_context__) => {

var { m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-route-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-route-turbo.runtime.dev.js"));

module.exports = mod;
}}),
"[externals]/next/dist/compiled/@opentelemetry/api [external] (next/dist/compiled/@opentelemetry/api, cjs)": ((__turbopack_context__) => {

var { m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/compiled/@opentelemetry/api", () => require("next/dist/compiled/@opentelemetry/api"));

module.exports = mod;
}}),
"[externals]/next/dist/compiled/next-server/app-page-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-page-turbo.runtime.dev.js, cjs)": ((__turbopack_context__) => {

var { m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js"));

module.exports = mod;
}}),
"[externals]/next/dist/server/app-render/work-unit-async-storage.external.js [external] (next/dist/server/app-render/work-unit-async-storage.external.js, cjs)": ((__turbopack_context__) => {

var { m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/server/app-render/work-unit-async-storage.external.js", () => require("next/dist/server/app-render/work-unit-async-storage.external.js"));

module.exports = mod;
}}),
"[externals]/next/dist/server/app-render/work-async-storage.external.js [external] (next/dist/server/app-render/work-async-storage.external.js, cjs)": ((__turbopack_context__) => {

var { m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/server/app-render/work-async-storage.external.js", () => require("next/dist/server/app-render/work-async-storage.external.js"));

module.exports = mod;
}}),
"[externals]/next/dist/shared/lib/no-fallback-error.external.js [external] (next/dist/shared/lib/no-fallback-error.external.js, cjs)": ((__turbopack_context__) => {

var { m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/shared/lib/no-fallback-error.external.js", () => require("next/dist/shared/lib/no-fallback-error.external.js"));

module.exports = mod;
}}),
"[externals]/next/dist/server/app-render/after-task-async-storage.external.js [external] (next/dist/server/app-render/after-task-async-storage.external.js, cjs)": ((__turbopack_context__) => {

var { m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/server/app-render/after-task-async-storage.external.js", () => require("next/dist/server/app-render/after-task-async-storage.external.js"));

module.exports = mod;
}}),
"[project]/app/api/predictions/route.ts [app-route] (ecmascript)": ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s({
    "GET": ()=>GET,
    "POST": ()=>POST
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/server.js [app-route] (ecmascript)");
;
const MAX_ENTRIES = 200;
let predictions = [];
let idCounter = 0;
async function POST(req) {
    try {
        const body = await req.json();
        const entry = {
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
            featureSelectionEnabled: body.feature_selection_enabled ?? false
        };
        predictions.unshift(entry);
        if (predictions.length > MAX_ENTRIES) {
            predictions = predictions.slice(0, MAX_ENTRIES);
        }
        return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
            success: true,
            id: entry.id
        });
    } catch (err) {
        const message = err instanceof Error ? err.message : "Unknown error";
        return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
            error: message
        }, {
            status: 400
        });
    }
}
async function GET(req) {
    const url = new URL(req.url);
    const since = url.searchParams.get("since"); // ISO timestamp
    const limit = Math.min(Number(url.searchParams.get("limit") || 100), MAX_ENTRIES);
    let results = predictions;
    if (since) {
        const sinceDate = new Date(since).getTime();
        results = results.filter((p)=>new Date(p.timestamp).getTime() > sinceDate);
    }
    results = results.slice(0, limit);
    // Compute summary stats
    const total = predictions.length;
    const attacks = predictions.filter((p)=>p.prediction === 1).length;
    const safe = predictions.filter((p)=>p.prediction === 0).length;
    const avgProb = total > 0 ? predictions.reduce((sum, p)=>sum + p.attackProbability, 0) / total : 0;
    return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
        predictions: results,
        stats: {
            totalFlows: total,
            attacksDetected: attacks,
            safeFlows: safe,
            avgThreatProbability: Number(avgProb.toFixed(4))
        }
    });
}
}),

};

//# sourceMappingURL=%5Broot-of-the-server%5D__c106ebd6._.js.map