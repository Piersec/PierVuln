import { createClient } from "@supabase/supabase-js";
import { buildOverviewQuery, parseOverviewRequest, parseOverviewResponse, scopeFromMappings, VULNERABILITY_INDEX, type Scope } from "@/src/lib/book-soc/overview";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

export async function POST(request: Request) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  const token = request.headers.get("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  if (!url || !key || !token) return Response.json({ error: "Sessão necessária." }, { status: 401 });

  // Quem decide o acesso é o banco, com o token do próprio usuário.
  const scoped = createClient(url, key, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } });
  const { data: context, error: contextError } = await scoped.rpc("current_user_context");
  if (contextError) return Response.json({ error: "Não foi possível verificar o acesso." }, { status: 502 });
  if ((context as { is_internal_admin?: boolean } | null)?.is_internal_admin !== true) {
    return Response.json({ error: "Acesso restrito à equipe Pier." }, { status: 403 });
  }

  const pedido = parseOverviewRequest(await request.json().catch(() => null));
  if (!pedido) return Response.json({ error: "Pedido inválido." }, { status: 400 });

  // Índice fixo da Yamam: a própria conta do Wazuh (yamam_ro) limita a leitura a esse escopo.
  // Com índice fixo, o recorte por empresa do banco não é usado.
  const fixedIndex = process.env.WAZUH_INDEXER_INDEX;
  if (fixedIndex && !/^[a-z0-9._*-]+$/.test(fixedIndex)) {
    return Response.json({ error: "Índice configurado inválido." }, { status: 503 });
  }

  // Recorte da empresa: conexão dedicada não precisa de filtro; compartilhada usa os agentes mapeados.
  let scope: Scope | undefined;
  if (pedido.companyId && !fixedIndex) {
    const companyId = pedido.companyId;
    const [{ data: connections, error: connectionsError }, { data: mappings, error: mappingsError }] = await Promise.all([
      scoped.from("wazuh_connections").select("mode").eq("tenant_id", companyId).eq("is_active", true),
      scoped.from("wazuh_agent_mappings").select("match_type, match_value").eq("tenant_id", companyId).eq("is_active", true),
    ]);
    if (connectionsError || mappingsError) return Response.json({ error: "Não foi possível ler o recorte da empresa." }, { status: 502 });
    const dedicated = (connections ?? []).some((c) => c.mode === "dedicated");
    if (!dedicated) {
      if ((mappings ?? []).length === 0) return Response.json({ error: "Empresa sem agentes Wazuh vinculados." }, { status: 404 });
      scope = scopeFromMappings(mappings ?? []) ?? undefined;
      if (!scope) return Response.json({ error: "Recorte por grupo ainda não é suportado nesta visão." }, { status: 422 });
    }
  }

  const indexerUrl = process.env.WAZUH_INDEXER_URL;
  const username = process.env.WAZUH_INDEXER_USERNAME;
  const password = process.env.WAZUH_INDEXER_PASSWORD;
  if (!indexerUrl || !username || !password || new URL(indexerUrl).protocol !== "https:") {
    return Response.json({ error: "Wazuh não configurado neste ambiente." }, { status: 503 });
  }

  try {
    const response = await fetch(`${indexerUrl.replace(/\/$/, "")}/${fixedIndex ?? VULNERABILITY_INDEX}/_search`, {
      method: "POST",
      redirect: "error",
      headers: {
        "content-type": "application/json",
        authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
      },
      body: JSON.stringify(buildOverviewQuery(scope)),
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) return Response.json({ error: "O Wazuh não respondeu à consulta." }, { status: 502 });
    const overview = parseOverviewResponse(await response.json());
    return Response.json({ ...overview, consultadoEm: new Date().toISOString() });
  } catch {
    return Response.json({ error: "Não foi possível consultar o Wazuh." }, { status: 502 });
  }
}
