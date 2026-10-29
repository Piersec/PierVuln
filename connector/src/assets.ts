import { randomUUID } from "node:crypto";

const env = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
};
const supabaseUrl = env("SUPABASE_URL").replace(/\/$/, "");
const apiUrl = env("ASSET_API_URL").replace(/\/$/, "");
const username = env("ASSET_API_USERNAME");
const password = env("ASSET_API_PASSWORD");
const connectionId = env("WAZUH_CONNECTION_ID");
const ingestToken = env("WAZUH_INGEST_TOKEN");
const publishableKey = env("SUPABASE_PUBLISHABLE_KEY");
const pageSize = 500;

if (new URL(apiUrl).protocol !== "https:") throw new Error("Asset API must use HTTPS");

type ApiAgent = {
  id?: unknown; name?: unknown; ip?: unknown; status?: unknown; group?: unknown;
  os?: { name?: unknown; version?: unknown }; dateAdd?: unknown; lastKeepAlive?: unknown;
};

async function responseJson(response: Response, label: string): Promise<Record<string, unknown>> {
  if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}`);
  const value = await response.json() as Record<string, unknown>;
  if (!value || typeof value !== "object") throw new Error(`${label} returned invalid JSON`);
  return value;
}

async function postIngest(payload: Record<string, unknown>) {
  const response = await fetch(`${supabaseUrl}/functions/v1/wazuh-ingest`, {
    method: "POST",
    headers: { apikey: publishableKey, Authorization: `Bearer ${ingestToken}`,
      "x-connection-id": connectionId, "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(60_000),
  });
  return responseJson(response, "Asset ingestion");
}

function timestamp(value: unknown): string | null {
  return typeof value === "string" && !Number.isNaN(Date.parse(value)) ? new Date(value).toISOString() : null;
}

function toAsset(agent: ApiAgent) {
  const id = typeof agent.id === "string" ? agent.id.trim() : "";
  const name = typeof agent.name === "string" ? agent.name.trim() : "";
  if (!id || !name) throw new Error("Agent missing ID or name");
  const os = agent.os && typeof agent.os === "object"
    ? [agent.os.name, agent.os.version].filter((part): part is string => typeof part === "string" && !!part.trim()).join(" ")
    : "";
  return {
    agentId: id, agentName: name,
    ipAddress: typeof agent.ip === "string" ? agent.ip : null,
    status: typeof agent.status === "string" ? agent.status : "unknown",
    groups: Array.isArray(agent.group) ? agent.group.filter((part): part is string => typeof part === "string") : [],
    hostOs: os || null, registeredAt: timestamp(agent.dateAdd), lastKeepAliveAt: timestamp(agent.lastKeepAlive),
  };
}

async function main() {
  const runId = randomUUID();
  const basic = Buffer.from(`${username}:${password}`, "utf8").toString("base64");
  const auth = await responseJson(await fetch(`${apiUrl}/security/user/authenticate`, {
    method: "POST", headers: { Authorization: `Basic ${basic}` }, signal: AbortSignal.timeout(30_000),
  }), "Asset API authentication");
  const token = (auth.data as { token?: unknown } | undefined)?.token;
  if (typeof token !== "string" || !token) throw new Error("Asset API did not provide a token");
  await postIngest({ action: "assets_start", runId });
  try {
    let offset = 0;
    let total: number | null = null;
    while (total === null || offset < total) {
      const page = await responseJson(await fetch(`${apiUrl}/agents?limit=${pageSize}&offset=${offset}`, {
        headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(45_000),
      }), "Asset API agents");
      const data = page.data as { affected_items?: unknown; total_affected_items?: unknown } | undefined;
      if (!data || !Array.isArray(data.affected_items) || !Number.isSafeInteger(data.total_affected_items)) {
        throw new Error("Asset API page has invalid shape");
      }
      if (total === null) total = Number(data.total_affected_items);
      if (total !== data.total_affected_items || data.affected_items.length > pageSize
          || (data.affected_items.length === 0 && offset < total)) throw new Error("Asset API changed during pagination");
      if (data.affected_items.length) {
        await postIngest({ action: "assets_batch", runId, items: data.affected_items.map((item) => toAsset(item as ApiAgent)) });
      }
      offset += data.affected_items.length;
      console.info(`[assets] connectionId=${connectionId} received=${offset}/${total}`);
    }
    if (offset !== total) throw new Error("Incomplete asset API snapshot");
    const done = await postIngest({ action: "assets_finish", runId, expectedTotal: total });
    console.info(`[assets] connectionId=${connectionId} status=succeeded received=${offset} stored=${done.stored}`);
  } catch (error) {
    await postIngest({ action: "assets_fail", runId, error: error instanceof Error ? error.message.slice(0, 500) : "Unknown error" }).catch(() => undefined);
    throw error;
  }
}

main().catch((error) => {
  console.error(`[assets] connectionId=${connectionId} status=failed error=${error instanceof Error ? error.message : "Unknown error"}`);
  process.exitCode = 1;
});
