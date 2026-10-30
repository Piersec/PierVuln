import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";
import { decryptAssetApiCredentials, decryptWazuhConfig } from "../_shared/wazuh-config-secrets.ts";

const url = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });
const pageSize = 100;

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

async function tokenMatches(candidate: string, expected: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [candidateHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(candidate)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const left = new Uint8Array(candidateHash);
  const right = new Uint8Array(expectedHash);
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

Deno.serve(async (request) => {
  if (request.method !== "GET") return json(405, { error: "Method not allowed" });

  const expectedToken = Deno.env.get("WAZUH_WORKER_CONFIG_TOKEN");
  const workerToken = request.headers.get("x-worker-token") ?? "";
  if (!expectedToken || !workerToken || !(await tokenMatches(workerToken, expectedToken))) {
    return json(401, { error: "Unauthorized" });
  }

  const parsedOffset = Number(new URL(request.url).searchParams.get("offset") ?? "0");
  if (!Number.isSafeInteger(parsedOffset) || parsedOffset < 0 || parsedOffset > 1_000_000) {
    return json(400, { error: "Invalid offset" });
  }

  try {
    const { data: connections, error: connectionError } = await admin
      .from("wazuh_connections")
      .select("id,name,endpoint_url,index_pattern,asset_api_url,mode,tenant_id")
      .eq("is_active", true)
      .order("id")
      .range(parsedOffset, parsedOffset + pageSize - 1);
    if (connectionError) throw connectionError;

    const ids = (connections ?? []).map((connection) => connection.id);
    if (!ids.length) return json(200, { connections: [], hasMore: false, skipped: 0 });

    const [{ data: secrets, error: secretsError }, { data: credentials, error: credentialsError }, { data: mappings, error: mappingsError }, { data: tenantSecrets, error: tenantSecretsError }] = await Promise.all([
      admin.from("wazuh_connection_secrets").select("connection_id,nonce,ciphertext").in("connection_id", ids),
      admin.from("wazuh_ingest_credentials").select("connection_id,token_sha256").in("connection_id", ids),
      admin.from("wazuh_agent_mappings").select("connection_id,tenant_id").in("connection_id", ids).eq("is_active", true),
      admin.from("asset_api_tenant_secrets").select("connection_id,tenant_id,nonce,ciphertext").in("connection_id", ids),
    ]);
    if (secretsError) throw secretsError;
    if (credentialsError) throw credentialsError;
    if (mappingsError) throw mappingsError;
    if (tenantSecretsError) throw tenantSecretsError;

    const tenantIds = [...new Set([
      ...(connections ?? []).flatMap((connection) => connection.mode === "dedicated" && connection.tenant_id ? [connection.tenant_id] : []),
      ...(mappings ?? []).map((mapping) => mapping.tenant_id),
    ])];
    const { data: activeCompanies, error: companiesError } = tenantIds.length
      ? await admin.from("companies").select("id").in("id", tenantIds).eq("is_active", true)
      : { data: [], error: null };
    if (companiesError) throw companiesError;

    const secretById = new Map((secrets ?? []).map((secret) => [secret.connection_id, secret]));
    const digestById = new Map((credentials ?? []).map((credential) => [credential.connection_id, credential.token_sha256]));
    const activeTenantIds = new Set((activeCompanies ?? []).map((company) => company.id));
    const tenantSecretsByConnection = new Map<string, typeof tenantSecrets>();
    for (const secret of tenantSecrets ?? []) {
      tenantSecretsByConnection.set(secret.connection_id, [...(tenantSecretsByConnection.get(secret.connection_id) ?? []), secret]);
    }
    const configured = [];
    let skipped = 0;

    for (const connection of connections ?? []) {
      const encrypted = secretById.get(connection.id);
      const digest = digestById.get(connection.id);
      if (!encrypted || !digest) {
        skipped += 1;
        continue;
      }

      try {
        const config = await decryptWazuhConfig(encrypted);
        if (connection.mode === "shared" && new URL(request.url).searchParams.get("workerProtocol") !== "3") { skipped += 1; continue; }
        const tokenDigest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(config.ingestToken)))]
          .map((part) => part.toString(16).padStart(2, "0")).join("");
        if (tokenDigest !== digest) {
          skipped += 1;
          continue;
        }
        const endpoint = new URL(connection.endpoint_url);
        if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password) {
          skipped += 1;
          continue;
        }
        const linkedTenantIds = connection.mode === "dedicated" && connection.tenant_id
          ? [connection.tenant_id]
          : [...new Set((mappings ?? []).filter((mapping) => mapping.connection_id === connection.id).map((mapping) => mapping.tenant_id))];
        const assetApiTenants = [];
        for (const tenantId of linkedTenantIds) {
          if (!activeTenantIds.has(tenantId)) continue;
          const encryptedTenantSecret = tenantSecretsByConnection.get(connection.id)?.find((secret) => secret.tenant_id === tenantId);
          if (encryptedTenantSecret) {
            try {
              assetApiTenants.push({ tenantId, ...await decryptAssetApiCredentials(encryptedTenantSecret) });
            } catch {
              skipped += 1;
            }
          } else if (connection.mode === "dedicated" && tenantId === connection.tenant_id && config.assetApi) {
            assetApiTenants.push({ tenantId, ...config.assetApi });
          }
        }
        const { assetApi: _legacyAssetApi, ...workerCredentials } = config;
        const indexerTenants = connection.mode === "shared"
          ? linkedTenantIds.filter((id) => activeTenantIds.has(id)).map((tenantId) => ({ tenantId, ...config.indexerTenants?.[tenantId] })).filter((item) => item.username && item.password)
          : undefined;
        const expectedTenants = linkedTenantIds.filter((id) => activeTenantIds.has(id)).length;
        const indexerReady = indexerTenants ? expectedTenants > 0 && indexerTenants.length === expectedTenants : Boolean(config.indexerUsername && config.indexerPassword);
        const { indexerTenants: _storedTenantCredentials, ...safeWorkerCredentials } = workerCredentials;
        configured.push({
          id: connection.id,
          name: connection.name,
          indexerUrl: endpoint.toString(),
          indexPattern: connection.index_pattern,
          assetApiUrl: connection.asset_api_url,
          assetApiTenants,
          ...safeWorkerCredentials,
          indexerTenants, indexerReady,
          indexerUsername: connection.mode === "shared" ? indexerTenants?.[0]?.username ?? "" : config.indexerUsername,
          indexerPassword: connection.mode === "shared" ? indexerTenants?.[0]?.password ?? "" : config.indexerPassword,
        });
      } catch {
        skipped += 1;
      }
    }

    return json(200, {
      connections: configured,
      hasMore: (connections?.length ?? 0) === pageSize,
      skipped,
    });
  } catch (error) {
    console.error(`[wazuh-worker-config] Failed to load connection page code=${(error as { code?: string })?.code ?? "unknown"}`);
    return json(500, { error: "Worker configuration temporarily unavailable" });
  }
});
