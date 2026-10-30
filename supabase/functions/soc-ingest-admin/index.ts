import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const url = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const publicKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const admin = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "authorization, apikey, content-type, x-client-info",
      "access-control-allow-methods": "POST, OPTIONS",
    },
  });
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function text(value: unknown, max: number): string | null {
  if (typeof value !== "string" || value.length > max) return null;
  const result = value.trim();
  return result || null;
}

async function sha256(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "authorization, apikey, content-type, x-client-info",
    "access-control-allow-methods": "POST, OPTIONS",
  } });
  if (request.method !== "POST") return json(405, { error: "Use POST." });
  const jwt = request.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!jwt) return json(401, { error: "Sessão obrigatória." });

  const userClient = createClient(url, publicKey, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { Authorization: `Bearer ${jwt}` } },
  });
  const { data: auth, error: authError } = await userClient.auth.getUser(jwt);
  if (authError || !auth.user) return json(401, { error: "Sessão inválida." });
  const { data: context, error: contextError } = await userClient.rpc("current_user_context");
  if (contextError || context?.is_internal_admin !== true) return json(403, { error: "Acesso administrativo necessário." });

  let input: Record<string, unknown>;
  try { input = await request.json() as Record<string, unknown>; }
  catch { return json(400, { error: "JSON inválido." }); }
  const action = input.action;

  try {
    if (action === "list") {
      const { data, error } = await admin.from("soc_ingest_credentials")
        .select("id,tenant_id,name,token_prefix,created_at,revoked_at,last_received_at,last_batch_events,last_inserted,last_duplicates,last_error")
        .order("created_at", { ascending: false }).limit(500);
      if (error) throw error;
      return json(200, { credentials: data ?? [] });
    }

    if (action === "create") {
      const tenantId = text(input.tenantId, 36);
      const name = text(input.name, 80) ?? "n8n";
      if (!tenantId || !/^[0-9a-f-]{36}$/i.test(tenantId)) return json(400, { error: "Selecione uma empresa válida." });
      const { data: company, error: companyError } = await admin.from("companies")
        .select("id,is_active").eq("id", tenantId).maybeSingle();
      if (companyError) throw companyError;
      if (!company) return json(404, { error: "Empresa não encontrada." });
      if (!company.is_active) return json(409, { error: "Ative a empresa antes de gerar a chave de ingestão." });
      const { count, error: countError } = await admin.from("soc_ingest_credentials")
        .select("id", { count: "exact", head: true }).eq("tenant_id", tenantId).is("revoked_at", null);
      if (countError) throw countError;
      if ((count ?? 0) >= 5) return json(409, { error: "Esta empresa já possui cinco chaves ativas. Revogue uma antes de criar outra." });
      const token = `pv_soc_${randomToken()}`;
      const { data, error } = await admin.from("soc_ingest_credentials").insert({
        tenant_id: tenantId, name, token_prefix: token.slice(0, 16), token_sha256: await sha256(token),
        created_by: auth.user.id,
      }).select("id,tenant_id,name,token_prefix,created_at").single();
      if (error) throw error;
      return json(200, { credential: data, token });
    }

    if (action === "revoke") {
      const id = text(input.id, 36);
      if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return json(400, { error: "Chave inválida." });
      const { data, error } = await admin.from("soc_ingest_credentials")
        .update({ revoked_at: new Date().toISOString() }).eq("id", id).is("revoked_at", null)
        .select("id,tenant_id").maybeSingle();
      if (error) throw error;
      if (!data) return json(404, { error: "A chave já foi revogada ou não existe." });
      return json(200, { revoked: true, id: data.id, tenant_id: data.tenant_id });
    }
    return json(400, { error: "Ação inválida." });
  } catch (error) {
    console.error(`[soc-ingest-admin] action=${String(action)} code=${(error as { code?: string })?.code ?? "unknown"}`);
    return json(500, { error: "Não foi possível concluir a operação." });
  }
});
