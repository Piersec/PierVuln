import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";
import { decryptAssetApiCredentials, decryptWazuhConfig, encryptAssetApiCredentials, encryptWazuhConfig, type AssetApiCredentials, type WazuhConnectionCredentials } from "../_shared/wazuh-config-secrets.ts";

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

function prefixesOverlap(first: string, second: string) {
  const a = first.replace(/\*$/, "").toLocaleLowerCase("en-US");
  const b = second.replace(/\*$/, "").toLocaleLowerCase("en-US");
  return a.startsWith(b) || b.startsWith(a);
}

function slugify(value: string) {
  return value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);
}

function randomToken() {
  const data = crypto.getRandomValues(new Uint8Array(32));
  return [...data].map((part) => part.toString(16).padStart(2, "0")).join("");
}

function secret(value: unknown, max: number): string | null {
  if (typeof value !== "string" || value.length > max || !value.trim()) return null;
  return value;
}

async function sha256(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map((part) => part.toString(16).padStart(2, "0")).join("");
}

async function storeConnectionConfig(connectionId: string, credentials: WazuhConnectionCredentials) {
  const encrypted = await encryptWazuhConfig(credentials);
  const { error } = await admin.rpc("store_wazuh_connection_secret", {
    p_connection_id: connectionId,
    p_nonce: encrypted.nonce,
    p_ciphertext: encrypted.ciphertext,
    p_token_sha256: await sha256(credentials.ingestToken),
  });
  if (error) throw error;
}

function readIndexerCredentials(input: Record<string, unknown>, ingestToken: string): WazuhConnectionCredentials | null {
  const indexerUsername = text(input.indexerUsername, 256);
  const indexerPassword = secret(input.indexerPassword, 4096);
  if (input.caCertificate !== undefined && input.caCertificate !== null && typeof input.caCertificate !== "string") return null;
  const caCertificate = typeof input.caCertificate === "string" && input.caCertificate.trim()
    ? input.caCertificate
    : null;
  if (!indexerUsername || !indexerPassword || (typeof input.caCertificate === "string" && input.caCertificate.length > 65536)) {
    return null;
  }
  if (caCertificate && (!caCertificate.includes("-----BEGIN CERTIFICATE-----") || !caCertificate.includes("-----END CERTIFICATE-----"))) {
    return null;
  }
  return { indexerUsername, indexerPassword, ingestToken, caCertificate };
}

function readCaCertificate(value: unknown): string | null {
  if (typeof value !== "string" || !value.trim() || value.length > 65536) return null;
  const pem = value.trim();
  const certificates = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!certificates?.length || pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, "").trim()) return null;
  if (certificates.some((certificate) => !/^-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----$/.test(certificate))) return null;
  return pem;
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
      if (data.connections?.length) {
        const ids = data.connections.map((connection: { id: string }) => connection.id);
        const [{ data: assetSources, error: sourcesError }, { data: tenantAssetSecrets, error: tenantSecretsError }, { data: connectionSecrets, error: connectionSecretsError }, { data: assetRuns, error: runsError }] = await Promise.all([
          admin.from("wazuh_connections").select("id,mode,tenant_id,asset_api_url").in("id", ids),
          admin.from("asset_api_tenant_secrets").select("connection_id,tenant_id").in("connection_id", ids),
          admin.from("wazuh_connection_secrets").select("connection_id,nonce,ciphertext").in("connection_id", ids),
          admin.from("asset_sync_runs").select("connection_id,tenant_id,status,finished_at,agents_received,agents_stored,error_summary")
            .in("connection_id", ids).order("started_at", { ascending: false }).limit(Math.min(ids.length * 20, 1000)),
        ]);
        if (sourcesError) throw sourcesError;
        if (tenantSecretsError) throw tenantSecretsError;
        if (connectionSecretsError) throw connectionSecretsError;
        if (runsError) throw runsError;
        const sourceById = new Map((assetSources ?? []).map((source) => [source.id, source]));
        const configuredByConnection = new Map<string, Set<string>>();
        for (const item of tenantAssetSecrets ?? []) {
          const configured = configuredByConnection.get(item.connection_id) ?? new Set<string>();
          configured.add(item.tenant_id);
          configuredByConnection.set(item.connection_id, configured);
        }
        const secretById = new Map((connectionSecrets ?? []).map((secret) => [secret.connection_id, secret]));
        const runById = new Map<string, NonNullable<typeof assetRuns>[number]>();
        for (const run of assetRuns ?? []) if (!runById.has(run.connection_id)) runById.set(run.connection_id, run);
        const runsByTenant = new Map<string, Record<string, NonNullable<typeof assetRuns>[number]>>();
        for (const run of assetRuns ?? []) {
          if (!run.tenant_id) continue;
          const byTenant = runsByTenant.get(run.connection_id) ?? {};
          if (!byTenant[run.tenant_id]) byTenant[run.tenant_id] = run;
          runsByTenant.set(run.connection_id, byTenant);
        }
        for (const connection of data.connections) {
          const source = sourceById.get(connection.id);
          connection.asset_api_url = source?.asset_api_url ?? null;
          const configured = configuredByConnection.get(connection.id) ?? new Set<string>();
          const legacy = secretById.get(connection.id);
          connection.indexer_credentials_configured = Boolean(legacy);
          if (source?.mode === "dedicated" && source.tenant_id && legacy) {
            try {
              const config = await decryptWazuhConfig(legacy);
              if (config.assetApi?.username && config.assetApi.password) configured.add(source.tenant_id);
            } catch { /* Keep stored credentials hidden when decryption fails. */ }
          }
          connection.asset_api_configured_tenant_ids = [...configured];
          connection.latest_asset_sync = runById.get(connection.id) ?? null;
          connection.latest_asset_sync_by_tenant = runsByTenant.get(connection.id) ?? {};
        }
      }
      return json(200, data);
    }

    if (action === "battle_data") {
      const { data, error } = await admin.rpc("admin_battle_data");
      if (error) throw error;
      return json(200, { companies: data });
    }

    if (action === "set_company_logo") {
      const id = text(input.id, 36);
      const theme = input.theme;
      if (!id || !/^[0-9a-f-]{36}$/i.test(id) || (theme !== "dark" && theme !== "light"))
        return json(400, { error: "Empresa ou tema inválido." });
      const column = theme === "dark" ? "logo_dark_path" : "logo_light_path";
      const { data: company, error: companyError } = await admin.from("companies").select(`id,${column}`).eq("id", id).maybeSingle();
      if (companyError) throw companyError;
      if (!company) return json(404, { error: "Empresa não encontrada." });
      const previous = company[column] as string | null;
      if (input.image === null) {
        const { error } = await admin.from("companies").update({ [column]: null }).eq("id", id);
        if (error) throw error;
        if (previous) await admin.storage.from("company-logos").remove([previous]);
        return json(200, { entityId: id, path: null });
      }
      const image = input.image;
      if (typeof image !== "string" || image.length > 1_400_000) return json(400, { error: "A logo deve ter até 1 MB." });
      const match = /^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/]+={0,2})$/.exec(image);
      if (!match) return json(400, { error: "Use uma imagem PNG, JPG ou WebP." });
      const binary = Uint8Array.from(atob(match[2]), (character) => character.charCodeAt(0));
      if (binary.length > 1_048_576 || binary.length === 0) return json(400, { error: "A logo deve ter até 1 MB." });
      const mime = match[1];
      const valid = mime === "image/png" ? binary[0] === 137 && binary[1] === 80 && binary[2] === 78 && binary[3] === 71
        : mime === "image/jpeg" ? binary[0] === 255 && binary[1] === 216 && binary.at(-2) === 255 && binary.at(-1) === 217
        : binary[0] === 82 && binary[1] === 73 && binary[2] === 70 && binary[3] === 70 && binary[8] === 87 && binary[9] === 69 && binary[10] === 66 && binary[11] === 80;
      if (!valid) return json(400, { error: "O arquivo da logo não corresponde ao formato informado." });
      const extension = mime === "image/png" ? "png" : mime === "image/jpeg" ? "jpg" : "webp";
      const path = `${id}/${theme}-${crypto.randomUUID()}.${extension}`;
      const { error: uploadError } = await admin.storage.from("company-logos").upload(path, binary, { contentType: mime, cacheControl: "31536000" });
      if (uploadError) throw uploadError;
      const { error: updateError } = await admin.from("companies").update({ [column]: path }).eq("id", id);
      if (updateError) {
        await admin.storage.from("company-logos").remove([path]);
        throw updateError;
      }
      if (previous) await admin.storage.from("company-logos").remove([previous]);
      return json(200, { entityId: id, path });
    }

    if (action === "delete_company") {
      const id = text(input.id, 36);
      if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return json(400, { error: "Empresa inválida." });
      const { data: company, error: lookupError } = await admin.from("companies").select("logo_dark_path,logo_light_path").eq("id", id).maybeSingle();
      if (lookupError) throw lookupError;
      if (!company) return json(404, { error: "Empresa não encontrada." });
      const { error } = await admin.from("companies").delete().eq("id", id);
      if (error?.code === "23503") return json(409, { error: "A empresa possui vínculos ou dados. Desative-a para preservar o histórico." });
      if (error) throw error;
      const paths = [company.logo_dark_path, company.logo_light_path].filter((path): path is string => Boolean(path));
      if (paths.length) await admin.storage.from("company-logos").remove(paths);
      return json(200, { entityId: id });
    }

    if (action === "delete_connection") {
      const id = text(input.id, 36);
      const confirmName = text(input.confirmName, 160);
      if (!id || !/^[0-9a-f-]{36}$/i.test(id) || !confirmName) return json(400, { error: "Integração ou confirmação inválida." });
      const { data: connection, error: lookupError } = await admin.from("wazuh_connections")
        .select("id,name,is_active").eq("id", id).maybeSingle();
      if (lookupError) throw lookupError;
      if (!connection) return json(404, { error: "Integração não encontrada." });
      if (connection.is_active) return json(409, { error: "Desative a integração antes de excluí-la." });
      if (confirmName !== connection.name) return json(400, { error: "O nome digitado não corresponde à integração." });

      const checks = await Promise.all([
        admin.from("sync_runs").select("connection_id", { count: "exact", head: true }).eq("connection_id", id),
        admin.from("wazuh_findings").select("connection_id", { count: "exact", head: true }).eq("connection_id", id),
        admin.from("asset_agents").select("connection_id", { count: "exact", head: true }).eq("connection_id", id),
        admin.from("asset_sync_runs").select("connection_id", { count: "exact", head: true }).eq("connection_id", id),
        admin.from("archive_manifests").select("connection_id", { count: "exact", head: true }).eq("connection_id", id),
        admin.from("snapshot_publication_jobs").select("connection_id", { count: "exact", head: true }).eq("connection_id", id),
      ]);
      const failedCheck = checks.find((check) => check.error);
      if (failedCheck?.error) throw failedCheck.error;
      if (checks.some((check) => (check.count ?? 0) > 0)) {
        return json(409, { error: "Esta integração tem histórico ou dados associados. Ela foi preservada; desative-a em vez de excluir." });
      }
      const { data: deleted, error: deleteError } = await admin.from("wazuh_connections").delete()
        .eq("id", id).eq("is_active", false).select("id").maybeSingle();
      if (deleteError?.code === "23503") return json(409, { error: "Há dados associados à integração. Ela foi preservada; desative-a para manter o histórico." });
      if (deleteError) throw deleteError;
      if (!deleted) return json(409, { error: "A integração foi alterada durante a operação. Atualize a tela e tente novamente." });
      return json(200, { deleted: true, entityId: id });
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
      const credentials = readIndexerCredentials(input, "pending");
      if (!name || name.length < 2 || !endpointUrl || !endpointUrl.startsWith("https://")) {
        return json(400, { error: "Informe o nome da integração e o endpoint HTTPS do Indexer." });
      }
      if (!credentials) return json(400, { error: "Informe usuário e senha válidos do Indexer e um certificado CA em PEM, se necessário." });
      try {
        const endpoint = new URL(endpointUrl);
        if (endpoint.username || endpoint.password) throw new Error();
      } catch { return json(400, { error: "Informe uma URL HTTPS sem credenciais." }); }
      if (mode !== "dedicated" && mode !== "shared") return json(400, { error: "Selecione integração dedicada ou compartilhada." });
      if ((mode === "dedicated" && (!tenantId || !/^[0-9a-f-]{36}$/i.test(tenantId))) || (mode === "shared" && tenantId)) {
        return json(400, { error: "A empresa selecionada não corresponde ao tipo de integração." });
      }
      const ingestToken = randomToken();
      credentials.ingestToken = ingestToken;
      const { data: connectionId, error } = await admin.rpc("create_wazuh_connection", {
        p_tenant_id: tenantId || null,
        p_name: name,
        p_mode: mode,
        p_endpoint_url: endpointUrl,
        p_index_pattern: "wazuh-states-vulnerabilities-*",
        p_token_sha256: await sha256(ingestToken),
      });
      if (error) throw error;
      try {
        await storeConnectionConfig(String(connectionId), credentials);
      } catch (storeError) {
        await admin.from("wazuh_connections").delete().eq("id", connectionId);
        throw storeError;
      }
      return json(201, { connectionId, configured: true });
    }

    if (action === "configure_connection") {
      const connectionId = text(input.connectionId, 36);
      if (!connectionId || !/^[0-9a-f-]{36}$/i.test(connectionId)) return json(400, { error: "Selecione uma conexão válida." });
      const ingestToken = randomToken();
      const credentials = readIndexerCredentials(input, ingestToken);
      if (!credentials) return json(400, { error: "Informe usuário e senha válidos do Indexer e um certificado CA em PEM, se necessário." });
      const { data: connection, error: connectionError } = await admin.from("wazuh_connections")
        .select("id").eq("id", connectionId).maybeSingle();
      if (connectionError) throw connectionError;
      if (!connection) return json(404, { error: "Integração não encontrada." });
      await storeConnectionConfig(connectionId, credentials);
      return json(200, { connectionId, configured: true, tokenRotated: true });
    }

    if (action === "configure_asset_api_endpoint") {
      const connectionId = text(input.connectionId, 36);
      const endpoint = text(input.assetApiUrl, 2048);
      if (!connectionId || !/^[0-9a-f-]{36}$/i.test(connectionId) || !endpoint) {
        return json(400, { error: "Selecione uma integração e informe o endereço da API." });
      }
      let parsed: URL;
      try { parsed = new URL(endpoint); } catch { return json(400, { error: "Endereço HTTPS inválido." }); }
      if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
        return json(400, { error: "Informe um endereço HTTPS sem credenciais ou parâmetros." });
      }
      const { data: connection, error: connectionError } = await admin.from("wazuh_connections")
        .select("id").eq("id", connectionId).maybeSingle();
      if (connectionError) throw connectionError;
      if (!connection) return json(404, { error: "Integração não encontrada." });
      const { error } = await admin.from("wazuh_connections").update({ asset_api_url: parsed.toString() }).eq("id", connectionId);
      if (error) throw error;
      return json(200, { configured: true, connectionId });
    }

    if (action === "configure_asset_api" || action === "disable_asset_api") {
      const connectionId = text(input.connectionId, 36);
      if (!connectionId || !/^[0-9a-f-]{36}$/i.test(connectionId)) return json(400, { error: "Selecione uma integração válida." });
      const { data: connection, error: connectionError } = await admin.from("wazuh_connections")
        .select("id,mode,tenant_id,asset_api_url").eq("id", connectionId).maybeSingle();
      if (connectionError) throw connectionError;
      if (!connection) return json(404, { error: "Integração não encontrada." });
      const tenantId = text(input.tenantId, 36);
      if (!tenantId || !/^[0-9a-f-]{36}$/i.test(tenantId)) return json(400, { error: "Selecione uma empresa válida." });
      let tenantLinked = connection.mode === "dedicated" && connection.tenant_id === tenantId;
      if (connection.mode === "shared") {
        const { data: mapping, error: mappingError } = await admin.from("wazuh_agent_mappings")
          .select("id").eq("connection_id", connectionId).eq("tenant_id", tenantId).limit(1).maybeSingle();
        if (mappingError) throw mappingError;
        tenantLinked = Boolean(mapping);
      }
      if (!tenantLinked) return json(409, { error: "Empresa não vinculada a esta integração." });

      const [{ data: tenantSecret, error: tenantSecretError }, { data: connectionSecret, error: connectionSecretError }] = await Promise.all([
        admin.from("asset_api_tenant_secrets").select("connection_id,tenant_id,nonce,ciphertext")
          .eq("connection_id", connectionId).eq("tenant_id", tenantId).maybeSingle(),
        admin.from("wazuh_connection_secrets").select("connection_id,nonce,ciphertext").eq("connection_id", connectionId).maybeSingle(),
      ]);
      if (tenantSecretError) throw tenantSecretError;
      if (connectionSecretError) throw connectionSecretError;
      if (action === "configure_asset_api" && !connectionSecret) return json(409, { error: "Configure o acesso ao Indexer antes das credenciais do Manager." });
      if (action === "configure_asset_api" && !connection.asset_api_url) return json(409, { error: "Configure o endpoint comum do Manager antes das credenciais das empresas." });
      const legacySecret = connectionSecret;
      let existing: AssetApiCredentials | null = tenantSecret ? await decryptAssetApiCredentials(tenantSecret) : null;
      let legacyConfig: WazuhConnectionCredentials | null = null;
      if (legacySecret) {
        legacyConfig = await decryptWazuhConfig(legacySecret);
        if (!existing && connection.mode === "dedicated") existing = legacyConfig.assetApi ?? null;
      }
      if (action === "disable_asset_api") {
        const { error: deleteError } = await admin.from("asset_api_tenant_secrets").delete()
          .eq("connection_id", connectionId).eq("tenant_id", tenantId);
        if (deleteError) throw deleteError;
        if (connection.mode === "dedicated" && legacyConfig?.assetApi && legacySecret) {
          delete legacyConfig.assetApi;
          await storeConnectionConfig(connectionId, legacyConfig);
        }
        const { count, error: countError } = await admin.from("asset_api_tenant_secrets")
          .select("tenant_id", { count: "exact", head: true }).eq("connection_id", connectionId);
        if (countError) throw countError;
        if ((count ?? 0) === 0) {
          const { error: endpointError } = await admin.from("wazuh_connections").update({ asset_api_url: null }).eq("id", connectionId);
          if (endpointError) throw endpointError;
        }
        return json(200, { configured: false, connectionId, tenantId });
      }
      if (typeof input.assetApiUsername === "string" && input.assetApiUsername.length > 256) {
        return json(400, { error: "O usuário da API excede o limite permitido." });
      }
      const submittedUsername = text(input.assetApiUsername, 256);
      const submittedPassword = secret(input.assetApiPassword, 4096);
      if (typeof input.assetApiPassword === "string" && input.assetApiPassword.trim() && !submittedPassword) {
        return json(400, { error: "A senha da API excede o limite permitido." });
      }
      const username = submittedUsername ?? existing?.username ?? null;
      const password = submittedPassword ?? existing?.password ?? null;
      if (!username || !password) return json(400, { error: "Informe usuário e senha da API." });
      if (input.assetApiCaCertificate !== undefined && input.assetApiCaCertificate !== null
          && typeof input.assetApiCaCertificate !== "string") return json(400, { error: "Certificado CA inválido." });
      const submittedCa = typeof input.assetApiCaCertificate === "string" && input.assetApiCaCertificate.trim()
        ? readCaCertificate(input.assetApiCaCertificate)
        : null;
      if (typeof input.assetApiCaCertificate === "string" && input.assetApiCaCertificate.trim() && !submittedCa) {
        return json(400, { error: "Certificado CA inválido." });
      }
      const caCertificate = submittedCa ?? existing?.caCertificate ?? null;
      const encryptedApi = await encryptAssetApiCredentials({ username, password, caCertificate });
      const { error: storeApiError } = await admin.from("asset_api_tenant_secrets").upsert({
        connection_id: connectionId, tenant_id: tenantId,
        nonce: encryptedApi.nonce, ciphertext: encryptedApi.ciphertext, updated_at: new Date().toISOString(),
      }, { onConflict: "connection_id,tenant_id" });
      if (storeApiError) throw storeApiError;
      return json(200, { configured: true, connectionId, tenantId });
    }

    if (action === "update_connection_ca") {
      const connectionId = text(input.connectionId, 36);
      const caCertificate = readCaCertificate(input.caCertificate);
      if (!connectionId || !/^[0-9a-f-]{36}$/i.test(connectionId) || !caCertificate) {
        return json(400, { error: "Informe uma conexão válida e um certificado CA em PEM." });
      }
      const { data: connection, error: connectionError } = await admin.from("wazuh_connections")
        .select("id").eq("id", connectionId).maybeSingle();
      if (connectionError) throw connectionError;
      if (!connection) return json(404, { error: "Fonte não encontrada." });
      const { data: encrypted, error: secretError } = await admin.from("wazuh_connection_secrets")
        .select("connection_id,nonce,ciphertext").eq("connection_id", connectionId).maybeSingle();
      if (secretError) throw secretError;
      if (!encrypted) return json(409, { error: "Configure as credenciais da conexão antes de trocar o certificado CA." });
      const current = await decryptWazuhConfig(encrypted);
      await storeConnectionConfig(connectionId, { ...current, caCertificate });
      return json(200, { connectionId, configured: true, tokenRotated: false });
    }

    if (action === "set_agent_mapping") {
      const connectionId = text(input.connectionId, 36);
      const tenantId = text(input.tenantId, 36);
      const matchType = text(input.matchType, 20);
      const matchValue = text(input.matchValue, 256);
      if (!connectionId || !tenantId || !matchValue || !/^[0-9a-f-]{36}$/i.test(connectionId)
          || !/^[0-9a-f-]{36}$/i.test(tenantId)
          || !["agent_id", "group", "agent_name_prefix"].includes(matchType ?? "")
          || (matchType === "agent_name_prefix" && !/^[A-Za-z0-9._-]+\*$/.test(matchValue ?? ""))) {
        return json(400, { error: "Informe conexão, empresa, tipo e valor válidos para a regra." });
      }
      const { data: connection, error: connectionError } = await admin.from("wazuh_connections")
        .select("id,mode").eq("id", connectionId).maybeSingle();
      if (connectionError) throw connectionError;
      if (connection?.mode !== "shared") return json(404, { error: "Integração compartilhada não encontrada." });
      const { data: company, error: companyError } = await admin.from("companies")
        .select("id").eq("id", tenantId).eq("is_active", true).maybeSingle();
      if (companyError) throw companyError;
      if (!company) return json(404, { error: "Empresa não encontrada ou inativa." });
      const { data: existing, error: existingError } = await admin.from("wazuh_agent_mappings")
        .select("id,tenant_id").eq("connection_id", connectionId).eq("match_type", matchType).eq("match_value", matchValue).maybeSingle();
      if (existingError) throw existingError;
      if (existing && existing.tenant_id !== tenantId) return json(409, { error: "Este valor já está atribuído a outra empresa." });
      if (matchType === "agent_name_prefix") {
        const { data: prefixes, error: prefixesError } = await admin.from("wazuh_agent_mappings")
          .select("tenant_id,match_value").eq("connection_id", connectionId).eq("match_type", "agent_name_prefix").eq("is_active", true);
        if (prefixesError) throw prefixesError;
        const overlap = (prefixes ?? []).some((mapping) => mapping.tenant_id !== tenantId && prefixesOverlap(matchValue, mapping.match_value));
        if (overlap) return json(409, { error: "Este prefixo se sobrepõe ao prefixo ativo de outra empresa." });
      }
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

    if (action === "update_agent_mapping") {
      const mappingId = text(input.mappingId, 36);
      const matchType = text(input.matchType, 20);
      const matchValue = text(input.matchValue, 256);
      if (!mappingId || !/^[0-9a-f-]{36}$/i.test(mappingId) || !matchValue
          || !["agent_id", "group", "agent_name_prefix"].includes(matchType ?? "")
          || (matchType === "agent_name_prefix" && !/^[A-Za-z0-9._-]+\*$/.test(matchValue))) {
        return json(400, { error: "Informe tipo e valor válidos para a regra." });
      }
      const { data: mapping, error: mappingError } = await admin.from("wazuh_agent_mappings")
        .select("id,connection_id,tenant_id").eq("id", mappingId).maybeSingle();
      if (mappingError) throw mappingError;
      if (!mapping) return json(404, { error: "Regra não encontrada." });
      const [{ data: connection, error: connectionError }, { data: company, error: companyError }] = await Promise.all([
        admin.from("wazuh_connections").select("id,mode").eq("id", mapping.connection_id).maybeSingle(),
        admin.from("companies").select("id").eq("id", mapping.tenant_id).eq("is_active", true).maybeSingle(),
      ]);
      if (connectionError) throw connectionError;
      if (companyError) throw companyError;
      if (!connection || connection.mode !== "shared" || !company) return json(409, { error: "A integração ou empresa desta regra não está disponível." });
      const { data: duplicate, error: duplicateError } = await admin.from("wazuh_agent_mappings")
        .select("id").eq("connection_id", mapping.connection_id).eq("match_type", matchType).eq("match_value", matchValue).neq("id", mappingId).maybeSingle();
      if (duplicateError) throw duplicateError;
      if (duplicate) return json(409, { error: "Já existe outra regra com esse tipo e valor." });
      if (matchType === "agent_name_prefix") {
        const { data: prefixes, error: prefixesError } = await admin.from("wazuh_agent_mappings")
          .select("tenant_id,match_value").eq("connection_id", mapping.connection_id).eq("match_type", "agent_name_prefix").eq("is_active", true).neq("id", mappingId);
        if (prefixesError) throw prefixesError;
        const overlap = (prefixes ?? []).some((item) => item.tenant_id !== mapping.tenant_id && prefixesOverlap(matchValue, item.match_value));
        if (overlap) return json(409, { error: "Este prefixo se sobrepõe ao prefixo ativo de outra empresa." });
      }
      const { error: updateError } = await admin.from("wazuh_agent_mappings")
        .update({ match_type: matchType, match_value: matchValue }).eq("id", mappingId);
      if (updateError?.code === "23505") return json(409, { error: "Já existe outra regra com esse tipo e valor." });
      if (updateError) throw updateError;
      return json(200, { updated: true, entityId: mappingId });
    }

    if (action === "delete_agent_mapping") {
      const mappingId = text(input.mappingId, 36);
      const confirmValue = text(input.confirmValue, 256);
      if (!mappingId || !/^[0-9a-f-]{36}$/i.test(mappingId) || !confirmValue) return json(400, { error: "Regra ou confirmação inválida." });
      const { data: mapping, error: mappingError } = await admin.from("wazuh_agent_mappings")
        .select("id,match_value").eq("id", mappingId).maybeSingle();
      if (mappingError) throw mappingError;
      if (!mapping) return json(404, { error: "Regra não encontrada." });
      if (confirmValue !== mapping.match_value) return json(400, { error: "O valor digitado não corresponde à regra." });
      const { error: deleteError } = await admin.from("wazuh_agent_mappings").delete().eq("id", mappingId);
      if (deleteError) throw deleteError;
      return json(200, { deleted: true, entityId: mappingId });
    }

    if (action === "create_shared_company") {
      const connectionId = text(input.connectionId, 36);
      const tenantId = text(input.tenantId, 36);
      const name = text(input.name, 161);
      const prefix = text(input.agentNamePrefix, 81);
      const group = text(input.group, 161);
      if (!connectionId || !/^[0-9a-f-]{36}$/i.test(connectionId)
          || (tenantId !== null && !/^[0-9a-f-]{36}$/i.test(tenantId))
          || (!tenantId && (!name || name.length > 160 || name.length < 2))
          || !prefix || prefix.length > 80 || !/^[A-Za-z0-9._-]+$/.test(prefix)
          || !group || group.length > 160 || !/^[A-Za-z0-9._-]+$/.test(group)) {
        return json(400, { error: "Informe o nome da empresa, o prefixo e o grupo válidos." });
      }
      const slug = name ? slugify(name) : null;
      if (!tenantId && !slug) return json(400, { error: "O nome não gerou um identificador válido para a empresa." });
      if (!tenantId) {
        const { data: existing, error: lookupError } = await admin.from("companies")
          .select("id").eq("slug", slug).maybeSingle();
        if (lookupError) throw lookupError;
        if (existing) return json(409, { error: "Já existe uma empresa com esse nome. Selecione-a como empresa cadastrada." });
      }

      const { data, error } = await admin.rpc("configure_shared_company", {
        p_connection_id: connectionId,
        p_tenant_id: tenantId,
        p_company_name: name ?? null,
        p_company_slug: slug,
        p_agent_name_prefix: prefix,
        p_group: group,
        p_created_by: userData.user.id,
      });
      if (error?.code === "23505") return json(409, { error: "Esse grupo ou prefixo já está vinculado a outra empresa." });
      if (error?.code === "22023") return json(400, { error: "Confira o nome, o prefixo e o grupo informados." });
      if (error?.code === "P0002") return json(404, { error: "O indexador compartilhado não está ativo." });
      if (error) throw error;
      return json(tenantId ? 200 : 201, data as Record<string, unknown>);
    }

    if (action === "disable_agent_mapping") {
      const mappingId = text(input.mappingId, 36);
      if (!mappingId || !/^[0-9a-f-]{36}$/i.test(mappingId)) return json(400, { error: "Invalid mapping" });
      const { error } = await admin.from("wazuh_agent_mappings").update({ is_active: false }).eq("id", mappingId);
      if (error) throw error;
      return json(200, { disabled: true });
    }

    if (action === "activate_company_mappings") {
      const connectionId = text(input.connectionId, 36);
      const tenantId = text(input.tenantId, 36);
      if (!connectionId || !tenantId || !/^[0-9a-f-]{36}$/i.test(connectionId) || !/^[0-9a-f-]{36}$/i.test(tenantId)) {
        return json(400, { error: "Selecione uma integração e uma empresa válidas." });
      }
      const { data: connection, error: connectionError } = await admin.from("wazuh_connections")
        .select("id,mode").eq("id", connectionId).maybeSingle();
      if (connectionError) throw connectionError;
      if (!connection || connection.mode !== "shared") return json(404, { error: "Integração compartilhada não encontrada." });
      const { data: company, error: companyError } = await admin.from("companies")
        .select("id").eq("id", tenantId).eq("is_active", true).maybeSingle();
      if (companyError) throw companyError;
      if (!company) return json(404, { error: "Empresa não encontrada ou inativa." });
      const [{ data: inactivePrefixes, error: inactivePrefixError }, { data: activePrefixes, error: activePrefixError }] = await Promise.all([
        admin.from("wazuh_agent_mappings").select("match_value").eq("connection_id", connectionId)
          .eq("tenant_id", tenantId).eq("match_type", "agent_name_prefix").eq("is_active", false),
        admin.from("wazuh_agent_mappings").select("tenant_id,match_value").eq("connection_id", connectionId)
          .eq("match_type", "agent_name_prefix").eq("is_active", true).neq("tenant_id", tenantId),
      ]);
      if (inactivePrefixError) throw inactivePrefixError;
      if (activePrefixError) throw activePrefixError;
      const overlap = (inactivePrefixes ?? []).some((candidate) =>
        (activePrefixes ?? []).some((active) => prefixesOverlap(candidate.match_value, active.match_value)));
      if (overlap) return json(409, { error: "Uma regra se sobrepõe ao prefixo ativo de outra empresa. Edite-a antes de ativar." });
      const { data: updated, error: updateError } = await admin.from("wazuh_agent_mappings")
        .update({ is_active: true }).eq("connection_id", connectionId).eq("tenant_id", tenantId)
        .eq("is_active", false).select("id");
      if (updateError) throw updateError;
      return json(200, { activated: updated?.length ?? 0, entityId: tenantId });
    }

    return json(400, { error: "Unsupported admin action" });
  } catch (error) {
    console.error(`[admin-actions] action=${String(action)} code=${(error as { code?: string })?.code ?? "unknown"}`);
    return json(500, { error: "Admin action failed" });
  }
});
