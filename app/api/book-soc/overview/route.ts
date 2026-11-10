import { requireInternal } from "@/src/lib/book-soc/auth";
import { findClient, loadClients } from "@/src/lib/book-soc/clients";
import { buildOverviewQuery, parseOverviewRequest, parseOverviewResponse, type Overview } from "@/src/lib/book-soc/overview";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

// Resultados só em memória, por instância do servidor, por pouco tempo. Nada vai para o banco.
const TTL_MS = 60_000;
const cache = new Map<string, { at: number; overview: Overview }>();

export async function POST(request: Request) {
  const denied = await requireInternal(request);
  if (denied) return denied;

  const pedido = parseOverviewRequest(await request.json().catch(() => null));
  if (!pedido) return Response.json({ error: "Pedido inválido." }, { status: 400 });
  const client = findClient(loadClients(), pedido.client);
  if (!client) return Response.json({ error: "Cliente não configurado neste ambiente." }, { status: 404 });

  const cached = cache.get(client.slug);
  if (cached && Date.now() - cached.at < TTL_MS) {
    return Response.json({ ...cached.overview, consultadoEm: new Date(cached.at).toISOString() });
  }

  try {
    const response = await fetch(`${client.url}/${client.index}/_search`, {
      method: "POST",
      redirect: "error",
      headers: {
        "content-type": "application/json",
        authorization: `Basic ${Buffer.from(`${client.user}:${client.password}`).toString("base64")}`,
      },
      body: JSON.stringify(buildOverviewQuery()),
      signal: AbortSignal.timeout(45_000),
    });
    if (!response.ok) return Response.json({ error: "O Wazuh não respondeu à consulta." }, { status: 502 });
    const overview = parseOverviewResponse(await response.json());
    const at = Date.now();
    cache.set(client.slug, { at, overview });
    return Response.json({ ...overview, consultadoEm: new Date(at).toISOString() });
  } catch (error) {
    // Registra só o código do erro (por exemplo, de TLS), nunca credenciais nem o corpo da resposta.
    console.error("[book-soc] consulta ao Indexer falhou:", client.slug, (error as { cause?: { code?: string } })?.cause?.code ?? (error as Error)?.name);
    return Response.json({ error: "Não foi possível consultar o Wazuh." }, { status: 502 });
  }
}
