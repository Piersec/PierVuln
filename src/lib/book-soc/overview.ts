// Visão executiva do Book SOC: estado atual das vulnerabilidades no Indexer.
// O índice de estados guarda a situação atual (não eventos com data), então não há período.
// Só agregados saem do servidor; documentos individuais nunca são devolvidos.

export const VULNERABILITY_INDEX = "wazuh-states-vulnerabilities-*";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type OverviewRequest = { companyId?: string };

export function parseOverviewRequest(body: unknown): OverviewRequest | null {
  if (!body || typeof body !== "object") return null;
  const { companyId } = body as Record<string, unknown>;
  if (companyId === undefined) return {};
  if (typeof companyId !== "string" || !uuid.test(companyId)) return null;
  return { companyId };
}

// Recorte da empresa, com as mesmas regras da ingestão do PierVuln:
// agent_id exato ou prefixo do nome do agente (sem diferenciar maiúsculas).
export type Scope = { agentIds: string[]; namePrefixes: string[] };

export function scopeFromMappings(rows: { match_type: unknown; match_value: unknown }[]): Scope | null {
  const agentIds: string[] = [];
  const namePrefixes: string[] = [];
  for (const row of rows) {
    const value = String(row.match_value ?? "");
    if (row.match_type === "agent_id") agentIds.push(value);
    else if (row.match_type === "agent_name_prefix" && /^[A-Za-z0-9._-]+\*$/.test(value)) namePrefixes.push(value.slice(0, -1));
  }
  return agentIds.length + namePrefixes.length === 0 ? null : { agentIds, namePrefixes };
}

// scope undefined = conexão dedicada (sem recorte).
export function buildOverviewQuery(scope?: Scope) {
  const should = scope ? [
    ...(scope.agentIds.length ? [{ terms: { "agent.id": scope.agentIds } }] : []),
    ...scope.namePrefixes.map((prefix) => ({ prefix: { "agent.name": { value: prefix.toLowerCase(), case_insensitive: true } } })),
  ] : [];
  return {
    size: 0,
    track_total_hits: true,
    query: scope ? { bool: { should, minimum_should_match: 1 } } : { match_all: {} },
    aggs: {
      severidade: { terms: { field: "vulnerability.severity", size: 10 } },
      cve: { terms: { field: "vulnerability.id", size: 10 } },
      agente: { terms: { field: "agent.name", size: 10 } },
    },
  };
}

export type Overview = {
  total: number;
  porSeveridade: { severidade: string; registros: number }[];
  porCve: { cve: string; registros: number }[];
  porAgente: { agente: string; registros: number }[];
};

type Bucket = { key: unknown; doc_count: unknown };

function buckets(raw: unknown): Bucket[] {
  const list = (raw as { buckets?: unknown } | undefined)?.buckets;
  return Array.isArray(list) ? list.filter((b): b is Bucket => !!b && typeof b === "object") : [];
}

export function parseOverviewResponse(raw: unknown): Overview {
  const response = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const hits = response.hits as { total?: { value?: unknown } } | undefined;
  const total = Number(hits?.total?.value ?? 0);
  if (!Number.isSafeInteger(total) || total < 0) throw new Error("O Indexer devolveu uma contagem inválida.");
  const aggs = (response.aggregations ?? {}) as Record<string, unknown>;
  const count = (b: Bucket) => Number(b.doc_count) || 0;
  return {
    total,
    porSeveridade: buckets(aggs.severidade).map((b) => ({ severidade: String(b.key), registros: count(b) })),
    porCve: buckets(aggs.cve).map((b) => ({ cve: String(b.key), registros: count(b) })),
    porAgente: buckets(aggs.agente).map((b) => ({ agente: String(b.key), registros: count(b) })),
  };
}
