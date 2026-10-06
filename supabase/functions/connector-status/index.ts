import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const url = Deno.env.get("SUPABASE_URL")!;
const service = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const cors = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, apikey, content-type, x-client-info, x-connection-id",
  "access-control-allow-methods": "GET, POST, OPTIONS",
};

function json(status: number, value: Record<string, unknown>) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { ...cors, "content-type": "application/json", "cache-control": "no-store" },
  });
}

function secureEquals(a: string, b: string) {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let i = 0; i < left.length; i++) mismatch |= left[i] ^ right[i];
  return mismatch === 0;
}

async function sha256(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map((part) => part.toString(16).padStart(2, "0")).join("");
}

function number(value: unknown, max: number, integer = false): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= max && (!integer || Number.isInteger(value)) ? value : null;
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  const token = request.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1] ?? "";

  if (request.method === "GET") {
    if (!token) return json(401, { error: "Unauthorized" });
    const { data: user, error: authError } = await service.auth.getUser(token);
    if (authError || !user.user) return json(401, { error: "Unauthorized" });
    const started = performance.now();
    const { error } = await service.from("wazuh_connections").select("id", { head: true, count: "exact" });
    const databaseLatencyMs = Math.round(performance.now() - started);
    if (error) return json(503, { api: true, database: false });
    return json(200, { api: true, database: true, databaseLatencyMs });
  }

  if (request.method !== "POST") return json(405, { error: "Method not allowed" });
  if (Number(request.headers.get("content-length") ?? 0) > 4096) return json(413, { error: "Payload too large" });
  const connectionId = request.headers.get("x-connection-id") ?? "";
  if (!/^[0-9a-f-]{36}$/i.test(connectionId) || token.length < 40 || token.length > 512) return json(401, { error: "Unauthorized" });
  const { data: credential, error: credentialError } = await service.from("wazuh_ingest_credentials")
    .select("token_sha256").eq("connection_id", connectionId).maybeSingle();
  if (credentialError || !credential || !secureEquals(credential.token_sha256, await sha256(token))) return json(401, { error: "Unauthorized" });
  const { data: connection, error: connectionError } = await service.from("wazuh_connections")
    .select("is_active").eq("id", connectionId).maybeSingle();
  if (connectionError || !connection?.is_active) return json(404, { error: "Connection unavailable" });

  let payload: Record<string, unknown>;
  try { payload = await request.json() as Record<string, unknown>; }
  catch { return json(400, { error: "Invalid JSON" }); }
  const fields = ["vpn_active", "indexer_reachable", "connector_active"] as const;
  if (!payload || typeof payload !== "object" || fields.some((field) => typeof payload[field] !== "boolean")) return json(400, { error: "Invalid status" });
  const uptime = number(payload.uptime_seconds, 1_000_000_000, true);
  const load = number(payload.load_percent, 1000);
  const memory = number(payload.memory_percent, 100);
  const disk = number(payload.disk_percent, 100);
  const latency = payload.indexer_latency_ms === null ? null : number(payload.indexer_latency_ms, 60000, true);
  if (uptime === null || load === null || memory === null || disk === null || (payload.indexer_latency_ms !== null && latency === null)) return json(400, { error: "Invalid metrics" });
  const { error } = await service.from("connector_status_heartbeats").upsert({
    connection_id: connectionId,
    observed_at: new Date().toISOString(),
    vpn_active: payload.vpn_active,
    indexer_reachable: payload.indexer_reachable,
    connector_active: payload.connector_active,
    uptime_seconds: uptime,
    load_percent: load,
    memory_percent: memory,
    disk_percent: disk,
    indexer_latency_ms: latency,
  });
  return error ? json(503, { error: "Status unavailable" }) : json(200, { ok: true });
});
