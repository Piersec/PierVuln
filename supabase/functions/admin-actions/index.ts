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

function text(value: unknown, max = 200): string | null {
  if (typeof value !== "string") return null;
  const result = value.trim();
  return result ? result.slice(0, max) : null;
}

function slugify(value: string) {
  return value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);
}

function randomToken() {
  const data = crypto.getRandomValues(new Uint8Array(32));
  return [...data].map((part) => part.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map((part) => part.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "authorization, apikey, content-type, x-client-info",
        "access-control-allow-methods": "POST, OPTIONS",
        "cache-control": "no-store",
      },
    });
  }
  if (request.method !== "POST") return json(405, { error: "Method not allowed" });
  const jwt = request.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!jwt) return json(401, { error: "Authentication required" });

  const userClient = createClient(url, publicKey, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { Authorization: `Bearer ${jwt}` } },
  });
  const { data: userData, error: userError } = await userClient.auth.getUser(jwt);
  if (userError || !userData.user) {
    console.error(`[admin-actions] authentication code=${userError?.code ?? "unknown"} status=${userError?.status ?? "unavailable"}`);
    const unavailable = !userError?.status || userError.status >= 500;
    return json(unavailable ? 503 : 401, { error: unavailable ? "A validação de acesso está temporariamente indisponível. Tente novamente." : "Sua sessão não pôde ser validada. Entre novamente." });
  }
  const { data: context, error: contextError } = await userClient.rpc("current_user_context");
  if (contextError || context?.is_internal_admin !== true) return json(403, { error: "Internal administrator required" });

  let input: Record<string, unknown>;
  try { input = await request.json() as Record<string, unknown>; }
  catch { return json(400, { error: "Invalid JSON" }); }
  const action = input.action;

  try {
    if (action === "panel_data") {
      const { data, error } = await admin.rpc("admin_panel_data", {
        p_search: text(input.search, 160) ?? "", p_scope: text(input.scope, 36) ?? "",
        p_page: Math.max(0, Math.floor(Number(input.page) || 0)),
      });
      if (error) throw error;
      for (const connection of data.connections ?? []) {
        try {
          const endpoint = new URL(connection.endpoint_url);
          endpoint.username = ""; endpoint.password = "";
          connection.endpoint_url = endpoint.toString();
        } catch { connection.endpoint_url = "Endpoint indisponível"; }
      }
      return json(200, data);
    }

    if (action === "update_company" || action === "update_connection") {
      const id = text(input.id, 36);
      if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return json(400, { error: "Identificador inválido." });
      const changes: Record<string, unknown> = {};
      if (input.name !== undefined) {
        const name = text(input.name, 160);
        if (!name || name.length < 2) return json(400, { error: "Informe um nome com pelo menos dois caracteres." });
        changes.name = name;
      }
      if (input.isActive !== undefined) {
        if (typeof input.isActive !== "boolean") return json(400, { error: "Estado inválido." });
        changes.is_active = input.isActive;
      }
      if (action === "update_connection" && input.endpointUrl !== undefined) {
        try {
          const endpoint = new URL(String(input.endpointUrl));
          if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password) throw new Error();
          changes.endpoint_url = endpoint.toString();
        } catch { return json(400, { error: "Informe uma URL HTTPS sem credenciais." }); }
      }
      if (!Object.keys(changes).length) return json(400, { error: "Nenhuma alteração informada." });
      const { data, error } = await admin.from(action === "update_company" ? "companies" : "wazuh_connections")
        .update(changes).eq("id", id).select("id").maybeSingle();
      if (error) throw error;
      if (!data) return json(404, { error: "Registro não encontrado." });
      return json(200, { updated: true, entityId: id });
    }

    if (action === "update_membership") {
      const id = text(input.id, 36);
      const role = text(input.role, 20);
      if (!id || !/^[0-9a-f-]{36}$/i.test(id) || !role || !["owner", "admin", "analyst", "viewer"].includes(role)
        || typeof input.isActive !== "boolean") return json(400, { error: "Vínculo ou perfil inválido." });
      const { data, error } = await admin.from("company_memberships").update({ role, is_active: input.isActive })
        .eq("id", id).select("id,user_id").maybeSingle();
      if (error) throw error;
      if (!data) return json(404, { error: "Vínculo não encontrado." });
      return json(200, { updated: true, entityId: data.user_id });
    }

    if (action === "resend_invite") {
      const id = text(input.id, 36);
      if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return json(400, { error: "Usuário inválido." });
      const { data, error } = await admin.auth.admin.getUserById(id);
      if (error || !data.user?.email) return json(404, { error: "Usuário não encontrado." });
      if (data.user.email_confirmed_at || !data.user.invited_at) return json(409, { error: "Este usuário não tem convite pendente." });
      const appBaseUrl = Deno.env.get("APP_BASE_URL");
      if (!appBaseUrl?.startsWith("https://")) return json(503, { error: "URL do convite não configurada." });
      const { error: inviteError } = await admin.auth.admin.inviteUserByEmail(data.user.email, { redirectTo: `${appBaseUrl.replace(/\/$/, "")}/onboarding` });
      if (inviteError) return json(409, { error: "Não foi possível reenviar o convite. Confira a configuração de e-mail e tente novamente." });
      return json(200, { invited: true, entityId: id });
    }

    if (action === "create_company") {
      const name = text(input.name, 160);
      if (!name || name.length < 2) return json(400, { error: "Company name is required" });
      const baseSlug = slugify(name);
      if (!baseSlug) return json(400, { error: "Company name cannot become a valid slug" });
      let slug = baseSlug;
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const { data, error } = await admin.from("companies").insert({ name, slug }).select("id,name,slug").single();
        if (!error) return json(201, data);
        if (error.code !== "23505") throw error;
        slug = `${baseSlug}-${crypto.randomUUID().slice(0, 6)}`;
      }
      return json(409, { error: "Could not create a unique company slug" });
    }

    if (action === "invite_user") {
      const email = text(input.email, 320)?.toLowerCase();
      const tenantId = text(input.tenantId, 36);
      const role = text(input.role, 20);
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !tenantId || !/^[0-9a-f-]{36}$/i.test(tenantId)) {
        return json(400, { error: "Valid email and company are required" });
      }
      if (!role || !["owner", "admin", "analyst", "viewer"].includes(role)) return json(400, { error: "Invalid role" });
      const { data: company, error: companyError } = await admin.from("companies").select("id").eq("id", tenantId).eq("is_active", true).maybeSingle();
      if (companyError || !company) return json(404, { error: "Company not found" });
      const appBaseUrl = Deno.env.get("APP_BASE_URL");
      if (!appBaseUrl || !appBaseUrl.startsWith("https://")) return json(503, { error: "App invite URL is not configured" });
      const { data: existing, error: lookupError } = await admin.rpc("admin_lookup_user", { p_email: email });
      if (lookupError) throw lookupError;
      const { data: invite, error: inviteError } = existing?.email_confirmed
        ? { data: { user: { id: String(existing.id) } }, error: null }
        : await admin.auth.admin.inviteUserByEmail(email, { redirectTo: `${appBaseUrl.replace(/\/$/, "")}/onboarding` });
      if (inviteError || !invite.user) return json(409, { error: "Convite não enviado. Confira a configuração de e-mail." });
      const { error: membershipError } = await admin.from("company_memberships").upsert({
        company_id: tenantId,
        user_id: invite.user.id,
        role,
        invited_by: userData.user.id,
        is_active: true,
      }, { onConflict: "company_id,user_id" });
      if (membershipError) {
        throw membershipError;
      }
      return json(201, { invited: !existing?.email_confirmed, entityId: invite.user.id });
    }

    if (action === "invite_pier_user") {
      const fullName = text(input.fullName, 160);
      const email = text(input.email, 320)?.toLowerCase();
      if (!fullName || !/^\S+\s+\S+/.test(fullName) || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return json(400, { error: "Nome completo e e-mail válido são obrigatórios" });
      }
      const appBaseUrl = Deno.env.get("APP_BASE_URL");
      if (!appBaseUrl || !appBaseUrl.startsWith("https://")) return json(503, { error: "App invite URL is not configured" });
      const { data: existing, error: lookupError } = await admin.rpc("admin_lookup_user", { p_email: email });
      if (lookupError) throw lookupError;
      const { data: invite, error: inviteError } = existing?.email_confirmed
        ? { data: { user: { id: String(existing.id) } }, error: null }
        : await admin.auth.admin.inviteUserByEmail(email, {
          data: { full_name: fullName },
          redirectTo: `${appBaseUrl.replace(/\/$/, "")}/onboarding`,
        });
      if (inviteError || !invite.user) {
        const needsSmtp = inviteError?.message.toLowerCase().includes("email address not authorized");
        return json(needsSmtp ? 503 : 409, {
          error: needsSmtp
            ? "O Supabase só envia convites para membros do projeto até que um SMTP personalizado seja configurado."
            : "Convite não enviado. Confira se o usuário já existe e a configuração de e-mail.",
        });
      }
      const { error: accessError } = await admin.rpc("add_internal_admin_invite", {
        p_user_id: invite.user.id,
        p_created_by: userData.user.id,
      });
      if (accessError) {
        throw accessError;
      }
      return json(201, { invited: !existing?.email_confirmed, entityId: invite.user.id });
    }

    if (action === "create_connection") {
      const name = text(input.name, 160);
      const endpointUrl = text(input.endpointUrl, 2048);
      const mode = text(input.mode, 20);
      const tenantId = text(input.tenantId, 36);
      if (!name || name.length < 2 || !endpointUrl || !endpointUrl.startsWith("https://")) {
        return json(400, { error: "Connection name and HTTPS Indexer URL are required" });
      }
      try {
        const endpoint = new URL(endpointUrl);
        if (endpoint.username || endpoint.password) throw new Error();
      } catch { return json(400, { error: "Informe uma URL HTTPS sem credenciais." }); }
      if (mode !== "dedicated" && mode !== "shared") return json(400, { error: "Invalid connection mode" });
      if ((mode === "dedicated" && (!tenantId || !/^[0-9a-f-]{36}$/i.test(tenantId))) || (mode === "shared" && tenantId)) {
        return json(400, { error: "Tenant assignment does not match connection mode" });
      }
      const ingestToken = randomToken();
      const { data: connectionId, error } = await admin.rpc("create_wazuh_connection", {
        p_tenant_id: tenantId || null,
        p_name: name,
        p_mode: mode,
        p_endpoint_url: endpointUrl,
        p_index_pattern: "wazuh-states-vulnerabilities-*",
        p_token_sha256: await sha256(ingestToken),
      });
      if (error) throw error;
      return json(201, { connectionId, ingestToken });
    }

    if (action === "set_agent_mapping") {
      const connectionId = text(input.connectionId, 36);
      const tenantId = text(input.tenantId, 36);
      const matchType = text(input.matchType, 20);
      const matchValue = text(input.matchValue, 256);
      if (!connectionId || !tenantId || !matchValue || !/^[0-9a-f-]{36}$/i.test(connectionId)
          || !/^[0-9a-f-]{36}$/i.test(tenantId) || !["agent_id", "group"].includes(matchType ?? "")) {
        return json(400, { error: "Invalid mapping" });
      }
      const { data: connection, error: connectionError } = await admin.from("wazuh_connections")
        .select("id,mode").eq("id", connectionId).eq("is_active", true).maybeSingle();
      if (connectionError || connection?.mode !== "shared") return json(404, { error: "Shared connection not found" });
      const { data: company, error: companyError } = await admin.from("companies")
        .select("id").eq("id", tenantId).eq("is_active", true).maybeSingle();
      if (companyError || !company) return json(404, { error: "Company not found" });
      const { data, error } = await admin.from("wazuh_agent_mappings").upsert({
        connection_id: connectionId,
        tenant_id: tenantId,
        match_type: matchType,
        match_value: matchValue,
        is_active: true,
        created_by: userData.user.id,
      }, { onConflict: "connection_id,match_type,match_value" }).select("id").single();
      if (error) throw error;
      return json(200, { mappingId: data.id, entityId: data.id });
    }

    if (action === "disable_agent_mapping") {
      const mappingId = text(input.mappingId, 36);
      if (!mappingId || !/^[0-9a-f-]{36}$/i.test(mappingId)) return json(400, { error: "Invalid mapping" });
      const { error } = await admin.from("wazuh_agent_mappings").update({ is_active: false }).eq("id", mappingId);
      if (error) throw error;
      return json(200, { disabled: true });
    }

    return json(400, { error: "Unsupported admin action" });
  } catch (error) {
    console.error(`[admin-actions] action=${String(action)} code=${(error as { code?: string })?.code ?? "unknown"}`);
    return json(500, { error: "Admin action failed" });
  }
});
