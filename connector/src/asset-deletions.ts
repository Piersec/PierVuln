import { deleteExactAgent, type DeletionIdentity } from "./asset-deletion-protocol";

const required = (name: string) => { const value = process.env[name]; if (!value) throw new Error(`Missing ${name}`); return value; };
const apiUrl = required("ASSET_API_URL");
const cloudUrl = required("SUPABASE_URL").replace(/\/$/, "");
const connectionId = required("WAZUH_CONNECTION_ID"), tenantId = required("ASSET_TENANT_ID");
if (new URL(apiUrl).protocol !== "https:" || new URL(cloudUrl).protocol !== "https:") throw new Error("HTTPS required");

async function command(body: Record<string, unknown>) {
  const response = await fetch(`${cloudUrl}/functions/v1/asset-commands`, { method: "POST", redirect: "error", headers: { "content-type": "application/json", apikey: required("SUPABASE_PUBLISHABLE_KEY"), "x-worker-token": required("WAZUH_WORKER_CONFIG_TOKEN") }, body: JSON.stringify({ ...body, connectionId, tenantId }), signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`Command service HTTP ${response.status}`);
  return response.json();
}
async function main() {
  const { job } = await command({ action: "claim", apiUrl });
  if (!job) return;
  let outcome: { outcome: string; code: string } = { outcome: "failed", code: "preflight_failed" };
  try {
    const authUrl = new URL("security/user/authenticate", apiUrl.replace(/\/?$/, "/"));
    const auth = await fetch(authUrl, { method: "POST", redirect: "error", headers: { Authorization: `Basic ${Buffer.from(`${required("ASSET_API_USERNAME")}:${required("ASSET_API_PASSWORD")}`).toString("base64")}` }, signal: AbortSignal.timeout(30_000) });
    if (auth.status === 401 || auth.status === 403) outcome = { outcome: "failed", code: "source_denied" };
    else if (auth.ok) {
      const payload = await auth.json();
      if (typeof payload?.data?.token === "string" && payload.data.token) outcome = await deleteExactAgent(apiUrl, payload.data.token, job as DeletionIdentity);
    }
  } catch { /* No DELETE is issued if authentication fails. */ }
  // Only the acknowledgement is retried. The source DELETE is never retried.
  for (let attempt = 0; attempt < 3; attempt++) {
    try { await command({ action: "finish", id: job.id, claimToken: job.claimToken, ...outcome }); return; }
    catch { if (attempt === 2) throw new Error("Deletion result awaiting reconciliation; source operation will not be retried"); }
  }
}
main().catch(() => { console.error("[asset-deletion] Command failed; check the request status in the application."); process.exitCode = 1; });
