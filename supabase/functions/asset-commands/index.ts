import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false, autoRefreshToken: false } });
const uuid = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value);
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
async function matches(left: string, right: string) {
  const digest = (value: string) => crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  const [a, b] = await Promise.all([digest(left), digest(right)]);
  let diff = 0;
  const x = new Uint8Array(a), y = new Uint8Array(b);
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
Deno.serve(async (request) => {
  if (request.method !== "POST") return json(405, { error: "Method not allowed" });
  const expected = Deno.env.get("WAZUH_WORKER_CONFIG_TOKEN");
  const token = request.headers.get("x-worker-token") ?? "";
  if (!expected || !token || token.length > 512 || !(await matches(token, expected))) return json(401, { error: "Unauthorized" });
  try {
    const raw = await request.text();
    if (raw.length > 4096) return json(413, { error: "Payload too large" });
    const body = JSON.parse(raw);
    if (!uuid(body.connectionId) || !uuid(body.tenantId)) return json(400, { error: "Invalid scope" });
    if (body.action === "claim") {
      if (typeof body.apiUrl !== "string" || body.apiUrl.length > 2048 || !body.apiUrl.startsWith("https://")) return json(400, { error: "Invalid endpoint" });
      const { data, error } = await admin.rpc("claim_asset_deletion", { p_connection: body.connectionId, p_tenant: body.tenantId, p_api_url: body.apiUrl });
      if (error) throw error;
      return json(200, { job: data });
    }
    if (body.action === "finish" && uuid(body.id) && uuid(body.claimToken) && ["succeeded", "failed", "uncertain"].includes(body.outcome)) {
      const { data, error } = await admin.rpc("finish_asset_deletion", { p_id: body.id, p_connection: body.connectionId, p_tenant: body.tenantId, p_claim: body.claimToken, p_outcome: body.outcome, p_code: typeof body.code === "string" ? body.code.slice(0, 50) : "source_failed" });
      if (error) throw error;
      return json(data ? 200 : 409, { accepted: data === true });
    }
    return json(400, { error: "Invalid command" });
  } catch {
    return json(500, { error: "Command service unavailable" });
  }
});
