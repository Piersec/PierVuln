import { createHash } from "node:crypto";
import { requireInternal } from "@/src/lib/book-soc/auth";
import { findClient, loadClients } from "@/src/lib/book-soc/clients";
import { buildAlertsQuery, parseAlertsRequest, parseAlertsResponse, type AlertsResult } from "@/src/lib/book-soc/alerts";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

// Resultados só em memória, por instância do servidor, por pouco tempo. Nada vai para o banco.
const TTL_MS = 60_000;
const MAX_ENTRIES = 50;
const cache = new Map<string, { at: number; result: AlertsResult }>();

export async function POST(request: Request) {
  const denied = await requireInternal(request);
  if (denied) return denied;

  const pedido = parseAlertsRequest(await request.json().catch(() => null));
  if (!pedido) return Response.json({ error: "Pedido inválido." }, { status: 400 });
  const client = findClient(loadClients(), pedido.client);
  if (!client) return Response.json({ error: "Cliente não configurado neste ambiente." }, { status: 404 });
  if (!client.alertsIndex) return Response.json({ error: "Alertas não estão configurados para este cliente." }, { status: 404 });

  const key = createHash("sha256").update(JSON.stringify([client.slug, pedido.start, pedido.end, pedido.filtros])).digest("hex");
  const cached = cache.get(key);
  if (cached && Date.now() - cached.at < TTL_MS) {
    return Response.json({ ...cached.result, consultadoEm: new Date(cached.at).toISOString() });
  }

  try {
    const response = await fetch(`${client.url}/${client.alertsIndex}/_search`, {
      method: "POST",
      redirect: "error",
      headers: {
        "content-type": "application/json",
        authorization: `Basic ${Buffer.from(`${client.user}:${client.password}`).toString("base64")}`,
      },
      body: JSON.stringify(buildAlertsQuery(pedido, client.excludedGroups)),
      signal: AbortSignal.timeout(55_000),
    });
    if (!response.ok) return Response.json({ error: "O Wazuh não respondeu à consulta de alertas." }, { status: 502 });
    const result = parseAlertsResponse(await response.json());
    const at = Date.now();
    if (cache.size >= MAX_ENTRIES) cache.delete(cache.keys().next().value as string);
    cache.set(key, { at, result });
    return Response.json({ ...result, consultadoEm: new Date(at).toISOString() });
  } catch (error) {
    // Registra só o código do erro (por exemplo, de TLS), nunca credenciais nem o corpo da resposta.
    console.error("[book-soc] consulta de alertas falhou:", client.slug, (error as { cause?: { code?: string } })?.cause?.code ?? (error as Error)?.name);
    return Response.json({ error: "Não foi possível consultar os alertas no Wazuh." }, { status: 502 });
  }
}
