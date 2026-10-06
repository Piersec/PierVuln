import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const service = createClient(supabaseUrl, serviceKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

type Item = {
  documentId: string;
  agentId: string | null;
  agentName: string | null;
  agentGroups: string[];
  hostOs: string | null;
  packageName: string | null;
  packageVersion: string | null;
  packageType: string | null;
  packageArchitecture: string | null;
  vulnerabilityId: string;
  description: string | null;
  severity: string;
  cvssBase: number | null;
  references: string[];
  sourceStatus: string | null;
};

function json(status: number, value: Record<string, unknown>) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function str(value: unknown, max: number): string | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const normalized = String(value).trim();
  return normalized ? normalized.slice(0, max) : null;
}

function stringArray(value: unknown, maxItems: number, maxLength: number): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((entry) => str(entry, maxLength)).filter((entry): entry is string => Boolean(entry)))].slice(0, maxItems);
}

function normalizeItem(input: unknown): Item {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Invalid item shape");
  const row = input as Record<string, unknown>;
  const documentId = typeof row.documentId === "string" ? row.documentId : "";
  if (!documentId || documentId.trim() !== documentId || documentId.length > 512) {
    throw new Error("Missing, padded, or oversized document ID");
  }
  const score = typeof row.cvssBase === "number" ? row.cvssBase : null;
  const severityValue = str(row.severity, 40)?.toLowerCase();
  const severity = ["critical", "high", "medium", "low", "informational"].includes(severityValue ?? "")
    ? severityValue![0].toUpperCase() + severityValue!.slice(1)
    : "Unknown";
  return {
    documentId,
    agentId: str(row.agentId, 128),
    agentName: str(row.agentName, 256),
    agentGroups: stringArray(row.agentGroups, 100, 256),
    hostOs: str(row.hostOs, 256),
    packageName: str(row.packageName, 512),
    packageVersion: str(row.packageVersion, 256),
    packageType: str(row.packageType, 128),
    packageArchitecture: str(row.packageArchitecture, 128),
    vulnerabilityId: str(row.vulnerabilityId, 128) ?? "UNKNOWN",
    description: str(row.description, 50_000),
    severity,
    cvssBase: score !== null && Number.isFinite(score) && score >= 0 && score <= 10 ? score : null,
    references: stringArray(row.references, 50, 2048),
    sourceStatus: str(row.sourceStatus, 128),
  };
}

function secureEquals(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let i = 0; i < left.length; i += 1) mismatch |= left[i] ^ right[i];
  return mismatch === 0;
}

async function sha256(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map((part) => part.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (request) => {
  if (request.method !== "POST") return json(405, { error: "Method not allowed" });
  const bodySize = Number(request.headers.get("content-length") ?? 0);
  if (bodySize > 6_000_000) return json(413, { error: "Batch too large" });
  const connectionId = request.headers.get("x-connection-id") ?? "";
  const bearer = request.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1] ?? "";
  if (!/^[0-9a-f-]{36}$/i.test(connectionId) || bearer.length < 40 || bearer.length > 512) {
    return json(401, { error: "Unauthorized" });
  }

  const { data: credential, error: credentialError } = await service
    .from("wazuh_ingest_credentials")
    .select("token_sha256")
    .eq("connection_id", connectionId)
    .maybeSingle();
  const suppliedHash = await sha256(bearer);
  if (credentialError || !credential || !secureEquals(credential.token_sha256, suppliedHash)) {
    return json(401, { error: "Unauthorized" });
  }

  const { data: connection, error: connectionError } = await service
    .from("wazuh_connections")
    .select("id,is_active")
    .eq("id", connectionId)
    .maybeSingle();
  if (connectionError || !connection?.is_active) return json(404, { error: "Connection unavailable" });

  let payload: Record<string, unknown>;
  try {
    payload = await request.json() as Record<string, unknown>;
  } catch {
    return json(400, { error: "Invalid JSON" });
  }

  const action = payload.action;
  try {
    if (action === "protocol") {
      const { data, error } = await service.rpc("wazuh_snapshot_protocol");
      if (error) throw error;
      return json(200, { snapshotProtocol: Number(data) });
    }

    if (action === "start") {
      if (payload.snapshotProtocol !== 2) return json(426, { error: "Connector snapshot protocol 2 is required" });
      const requestId = str(payload.requestId, 36);
      if (!requestId || !/^[0-9a-f-]{36}$/i.test(requestId)) return json(400, { error: "Invalid sync request ID" });
      const version = str(payload.indexerVersion, 160);
      if (!version) return json(400, { error: "Indexer version required" });
      const { data, error } = await service.rpc("register_wazuh_sync", {
        p_connection_id: connectionId,
        p_indexer_version: version,
        p_request_id: requestId,
      });
      if (error) throw error;
      return json(201, { runId: data });
    }

    const runId = str(payload.runId, 36);
    if (!runId || !/^[0-9a-f-]{36}$/i.test(runId)) return json(400, { error: "Invalid sync run" });

    if (action === "page") {
      if (!Number.isInteger(payload.pageNumber) || Number(payload.pageNumber) < 0) return json(400, { error: "Invalid page number" });
      if (!Array.isArray(payload.items) || payload.items.length > 500) return json(400, { error: "Invalid page size" });
      const items = payload.items.map(normalizeItem);
      const payloadHash = await sha256(JSON.stringify(items));
      const { data, error } = await service.rpc("ingest_wazuh_batch", {
        p_connection_id: connectionId,
        p_run_id: runId,
        p_page_number: Number(payload.pageNumber),
        p_payload_sha256: payloadHash,
        p_items: items,
      });
      if (error) throw error;
      return json(200, data as Record<string, unknown>);
    }

    if (action === "finish") {
      if (!Number.isInteger(payload.expectedPages) || Number(payload.expectedPages) < 1
          || !Number.isSafeInteger(payload.expectedDocuments) || Number(payload.expectedDocuments) < 0) {
        return json(400, { error: "Invalid expected pagination totals" });
      }
      const { data, error } = await service.rpc("complete_wazuh_sync", {
        p_connection_id: connectionId,
        p_run_id: runId,
        p_expected_pages: Number(payload.expectedPages),
        p_expected_documents: Number(payload.expectedDocuments),
        p_indexer_version: str(payload.indexerVersion, 160) ?? "unknown",
      });
      if (error) throw error;
      const result = data as Record<string, unknown>;
      return json(result.completed === true || result.pending === true ? 200 : 409, result);
    }

    if (action === "fail") {
      const { data: run, error: runError } = await service.from("sync_runs")
        .select("id").eq("id", runId).eq("connection_id", connectionId).maybeSingle();
      if (runError || !run) return json(404, { error: "Sync run not found" });
      const { data, error } = await service.rpc("fail_wazuh_sync", {
        p_connection_id: connectionId,
        p_run_id: runId,
        p_error_summary: str(payload.error, 1500) ?? "Connector reported failure",
      });
      if (error) throw error;
      return json(200, { failed: data === true });
    }

    return json(400, { error: "Unsupported action" });
  } catch (error) {
    console.error(`[wazuh-ingest] action=${String(action)} connection=${connectionId} error=${error instanceof Error ? error.message.slice(0, 300) : "unknown"}`);
    return json(500, { error: "Ingestion failed; the snapshot was not finalized" });
  }
});
