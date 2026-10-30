import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(supabaseUrl, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });
const maxBodyBytes = 1_000_000;
const maxRawPayloadBytes = 4096;
const severities = new Set(["critical", "high", "medium", "low", "informational", "unknown"]);

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function cleanString(value: unknown, max: number, required = false): string | null {
  if (typeof value !== "string") return required ? "" : null;
  const clean = value.trim();
  if (!clean && required) return "";
  return clean ? clean.slice(0, max) : null;
}

function integer(value: unknown, min: number, max: number): number | null | undefined {
  if (value === undefined || value === null || value === "") return null;
  if (!Number.isInteger(value) || Number(value) < min || Number(value) > max) return undefined;
  return Number(value);
}

function stringList(value: unknown, maxItems = 16): string[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > maxItems || value.some((item) => typeof item !== "string" || item.length > 120)) return null;
  return value.map((item) => item.trim()).filter(Boolean);
}

function normalizeEvent(input: unknown, index: number): Record<string, unknown> | string {
  if (!input || typeof input !== "object" || Array.isArray(input)) return `events[${index}] must be an object`;
  const event = input as Record<string, unknown>;
  const sourceId = cleanString(event.source_id, 128, true);
  const sourceName = cleanString(event.source_name, 160, true);
  const sourceEventId = cleanString(event.source_event_id, 512, true);
  const title = cleanString(event.title, 500, true);
  const occurredAt = cleanString(event.occurred_at, 80, true);
  const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i;
  const parsedAt = occurredAt ? Date.parse(occurredAt) : Number.NaN;
  if (!sourceId || !sourceName || !sourceEventId || !title) return `events[${index}] requires source_id, source_name, source_event_id and title`;
  if (!occurredAt || !isoTimestamp.test(occurredAt) || !Number.isFinite(parsedAt)) return `events[${index}].occurred_at must be an ISO 8601 timestamp with a time zone`;
  if (parsedAt < Date.now() - 30 * 24 * 60 * 60 * 1000) return `events[${index}].occurred_at is older than the 30-day ingestion window`;
  if (parsedAt > Date.now() + 5 * 60 * 1000) return `events[${index}].occurred_at cannot be more than 5 minutes in the future`;
  if (typeof event.severity !== "string" || !severities.has(event.severity)) return `events[${index}].severity is invalid`;

  const ruleLevel = integer(event.rule_level, 0, 255);
  const sourcePort = integer(event.src_port, 0, 65535);
  const destinationPort = integer(event.dst_port, 0, 65535);
  if (ruleLevel === undefined || sourcePort === undefined || destinationPort === undefined) return `events[${index}] contains an invalid numeric field`;
  const mitreIds = stringList(event.mitre_ids);
  const mitreTactics = stringList(event.mitre_tactics);
  const mitreTechniques = stringList(event.mitre_techniques);
  if (!mitreIds || !mitreTactics || !mitreTechniques) return `events[${index}] contains an invalid MITRE field`;
  if (event.raw_payload !== undefined && event.raw_payload !== null
      && (typeof event.raw_payload !== "object" || Array.isArray(event.raw_payload)
        || new TextEncoder().encode(JSON.stringify(event.raw_payload)).byteLength > maxRawPayloadBytes)) {
    return `events[${index}].raw_payload must be an object no larger than 4 KB`;
  }

  const normalized: Record<string, unknown> = {
    source_id: sourceId, source_name: sourceName, source_event_id: sourceEventId,
    occurred_at: new Date(parsedAt).toISOString(), severity: event.severity, title,
    mitre_ids: mitreIds, mitre_tactics: mitreTactics, mitre_techniques: mitreTechniques,
  };
  const strings: Record<string, number> = {
    source_category: 80, source_vendor: 120, source_product: 120, source_index: 160,
    source_document_id: 512, severity_original: 80, message: 12000, rule_id: 128,
    rule_description: 1000, agent_id: 128, agent_name: 256, agent_ip: 64, src_ip: 64,
    dst_ip: 64, network_protocol: 32, service: 120, src_user: 256, dst_user: 256,
    source_action: 120, normalized_action: 120, file_path: 2048, file_action: 120,
    file_hash_before: 256, file_hash_after: 256, file_owner_after: 256,
    change_actor: 256, change_process: 512,
  };
  for (const [key, max] of Object.entries(strings)) normalized[key] = cleanString(event[key], max);
  normalized.rule_level = ruleLevel;
  normalized.src_port = sourcePort;
  normalized.dst_port = destinationPort;
  normalized.raw_payload = event.raw_payload ?? null;
  return normalized;
}

async function digest(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map((part) => part.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (request) => {
  if (request.method !== "POST") return json(405, { error: "Use POST." });
  const authorization = request.headers.get("authorization")?.match(/^Bearer\s+(pv_soc_[0-9a-f]{64})$/i)?.[1];
  if (!authorization) return json(401, { error: "Chave de ingestão inválida." });

  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > maxBodyBytes) return json(413, { error: "Lote excede 1 MB." });
  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > maxBodyBytes) return json(413, { error: "Lote excede 1 MB." });
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch { return json(400, { error: "JSON inválido." }); }
  if (!input || typeof input !== "object" || Array.isArray(input) || !Array.isArray((input as Record<string, unknown>).events)) {
    return json(400, { error: "Envie um objeto com uma lista `events`." });
  }
  const events = (input as { events: unknown[] }).events;
  if (events.length < 1 || events.length > 100) return json(400, { error: "Cada lote deve conter de 1 a 100 alertas." });
  const normalized = events.map(normalizeEvent);
  const invalid = normalized.find((event) => typeof event === "string");
  if (invalid) return json(400, { error: invalid });

  const tokenHash = await digest(authorization);
  const { data: credential, error: credentialError } = await admin.from("soc_ingest_credentials")
    .select("id,tenant_id").eq("token_sha256", tokenHash).is("revoked_at", null).maybeSingle();
  if (credentialError || !credential) return json(401, { error: "Chave de ingestão inválida ou revogada." });
  const { data: company, error: companyError } = await admin.from("companies")
    .select("is_active").eq("id", credential.tenant_id).maybeSingle();
  if (companyError) return json(503, { error: "Não foi possível confirmar a empresa. Tente novamente." });
  if (!company?.is_active) return json(403, { error: "A empresa está inativa; o lote não foi aceito." });

  const { data, error } = await admin.rpc("ingest_soc_alert_batch", {
    p_credential_id: credential.id,
    p_events: normalized,
  });
  if (error) {
    console.error(`[soc-alert-ingest] batch rejected code=${error.code ?? "unknown"}`);
    await admin.from("soc_ingest_credentials").update({ last_error: "Lote rejeitado por validação no banco." }).eq("id", credential.id);
    return json(400, { error: "O lote não passou pela validação do banco." });
  }
  return json(200, data as Record<string, unknown>);
});
