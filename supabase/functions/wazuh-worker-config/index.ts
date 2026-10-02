import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";
import { decryptWazuhConfig } from "../_shared/wazuh-config-secrets.ts";

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
      .select("id,name,endpoint_url,index_pattern")
      .eq("is_active", true)
      .order("id")
      .range(parsedOffset, parsedOffset + pageSize - 1);
    if (connectionError) throw connectionError;

    const ids = (connections ?? []).map((connection) => connection.id);
    if (!ids.length) return json(200, { connections: [], hasMore: false, skipped: 0 });

    const [{ data: secrets, error: secretsError }, { data: credentials, error: credentialsError }] = await Promise.all([
      admin.from("wazuh_connection_secrets").select("connection_id,nonce,ciphertext").in("connection_id", ids),
      admin.from("wazuh_ingest_credentials").select("connection_id,token_sha256").in("connection_id", ids),
    ]);
    if (secretsError) throw secretsError;
    if (credentialsError) throw credentialsError;

    const secretById = new Map((secrets ?? []).map((secret) => [secret.connection_id, secret]));
    const digestById = new Map((credentials ?? []).map((credential) => [credential.connection_id, credential.token_sha256]));
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
        configured.push({
          id: connection.id,
          name: connection.name,
          indexerUrl: endpoint.toString(),
          indexPattern: connection.index_pattern,
          ...config,
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
