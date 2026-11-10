// Painel de alertas do Book SOC, com as mesmas regras do Book original.
// Só agregados saem do servidor. Nenhum evento individual é devolvido.

export const MAX_RANGE_DAYS = 93;
export const DEFAULT_EXCLUDED_GROUPS = ["vulnerability-detector"];
// Brasil não usa horário de verão desde 2019; a janela do Book é -03:00 (Brasília).
const OFFSET = "-03:00";
const dateOnly = /^\d{4}-\d{2}-\d{2}$/;

export type AlertFilters = { nivelMinimo: number; nivelMaximo: number; decoder: string | null; regrasIncluidas: string[]; regrasExcluidas: string[] };
export type AlertsRequest = { client: string; start: string; end: string; filtros: AlertFilters };

export const DEFAULT_FILTERS: AlertFilters = { nivelMinimo: 12, nivelMaximo: 16, decoder: null, regrasIncluidas: [], regrasExcluidas: [] };

const ruleId = /^[1-9][0-9]{0,5}$/;

export function normalizeFilters(value: unknown): AlertFilters | null {
  if (value === undefined || value === null) return { ...DEFAULT_FILTERS };
  if (typeof value !== "object" || Array.isArray(value)) return null;
  const input = value as Record<string, unknown>;
  const allowed = ["nivelMinimo", "nivelMaximo", "decoder", "regrasIncluidas", "regrasExcluidas"];
  if (Object.keys(input).some((key) => !allowed.includes(key))) return null;

  const level = (raw: unknown, fallback: number) => (raw === undefined || raw === null || raw === "" ? fallback : raw);
  const min = level(input.nivelMinimo, DEFAULT_FILTERS.nivelMinimo);
  const max = level(input.nivelMaximo, DEFAULT_FILTERS.nivelMaximo);
  if (!Number.isInteger(min) || !Number.isInteger(max)) return null;
  const nivelMinimo = min as number, nivelMaximo = max as number;
  if (nivelMinimo < 0 || nivelMaximo > 16 || nivelMinimo > nivelMaximo) return null;

  let decoder: string | null = null;
  if (input.decoder !== undefined && input.decoder !== null && input.decoder !== "") {
    if (typeof input.decoder !== "string" || !/^[\w. -]{1,128}$/.test(input.decoder)) return null;
    decoder = input.decoder;
  }

  const rules = (raw: unknown): string[] | null => {
    if (raw === undefined || raw === null) return [];
    if (!Array.isArray(raw) || raw.length > 20 || raw.some((item) => typeof item !== "string" || !ruleId.test(item))) return null;
    return [...new Set(raw as string[])].sort((a, b) => Number(a) - Number(b));
  };
  const regrasIncluidas = rules(input.regrasIncluidas), regrasExcluidas = rules(input.regrasExcluidas);
  if (!regrasIncluidas || !regrasExcluidas) return null;
  if (regrasIncluidas.some((id) => regrasExcluidas.includes(id))) return null;
  return { nivelMinimo, nivelMaximo, decoder, regrasIncluidas, regrasExcluidas };
}

export function parseAlertsRequest(body: unknown): AlertsRequest | null {
  if (!body || typeof body !== "object") return null;
  const { client, start, end, filtros } = body as Record<string, unknown>;
  if (typeof client !== "string" || !/^[a-z0-9-]{1,48}$/.test(client)) return null;
  if (typeof start !== "string" || typeof end !== "string" || !dateOnly.test(start) || !dateOnly.test(end)) return null;
  const from = Date.parse(`${start}T00:00:00Z`), to = Date.parse(`${end}T00:00:00Z`);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from > to) return null;
  if ((to - from) / 86_400_000 + 1 > MAX_RANGE_DAYS) return null;
  const normalized = normalizeFilters(filtros);
  return normalized ? { client, start, end, filtros: normalized } : null;
}

// O fim do período é exclusivo: o dia final entra por inteiro (até 00:00 do dia seguinte), no horário de Brasília.
export function periodWindow(start: string, end: string) {
  const next = new Date(Date.parse(`${end}T00:00:00Z`) + 86_400_000).toISOString().slice(0, 10);
  return { gte: `${start}T00:00:00${OFFSET}`, lt: `${next}T00:00:00${OFFSET}` };
}

export function filterLabel(filters: AlertFilters) {
  const parts = [`Níveis ${filters.nivelMinimo}–${filters.nivelMaximo}`, filters.decoder ? `Decoder: ${filters.decoder}` : "Todas as origens"];
  if (filters.regrasIncluidas.length) parts.push(`Somente regras: ${filters.regrasIncluidas.join(", ")}`);
  if (filters.regrasExcluidas.length) parts.push(`Excluir regras: ${filters.regrasExcluidas.join(", ")}`);
  return parts.join(" · ");
}

export function buildAlertsQuery(request: Pick<AlertsRequest, "start" | "end" | "filtros">, excludedGroups: string[] = DEFAULT_EXCLUDED_GROUPS) {
  const window = periodWindow(request.start, request.end);
  const f = request.filtros;
  const review: Record<string, unknown> = {
    bool: {
      filter: [
        { range: { "rule.level": { gte: f.nivelMinimo, lte: f.nivelMaximo } } },
        ...(f.decoder ? [{ term: { "decoder.name": f.decoder } }] : []),
        ...(f.regrasIncluidas.length ? [{ terms: { "rule.id": f.regrasIncluidas } }] : []),
      ],
      ...(f.regrasExcluidas.length ? { must_not: [{ terms: { "rule.id": f.regrasExcluidas } }] } : {}),
    },
  };
  const description = { top_hits: { size: 1, _source: false, docvalue_fields: ["rule.description"] } };
  return {
    size: 0,
    track_total_hits: true,
    query: { range: { timestamp: window } },
    aggs: {
      escopo: {
        filter: { bool: { must_not: [{ terms: { "rule.groups": excludedGroups } }] } },
        aggs: {
          decoders: { terms: { field: "decoder.name", size: 40 } },
          revisao: {
            filter: review,
            aggs: {
              regras: {
                terms: { field: "rule.id", size: 20 },
                aggs: { nivel: { terms: { field: "rule.level", size: 3 } }, exemplo: description },
              },
            },
          },
          admins: {
            filter: {
              bool: {
                filter: [
                  { terms: { "data.win.system.eventID": ["4728", "4729"] } },
                  { wildcard: { "data.win.eventdata.targetSid": { value: "S-1-5-21-*-512", case_insensitive: true } } },
                ],
              },
            },
          },
        },
      },
    },
  };
}

export type AlertsResult = {
  volume: number;
  escopo: number;
  revisao: number;
  admins: number;
  decoders: { nome: string; registros: number }[];
  regras: { id: string; descricao: string | null; nivel: number | null; registros: number; participacao: number }[];
  outrasRegras: number;
};

type Bucket = Record<string, unknown> & { key?: unknown; doc_count?: unknown };
const buckets = (raw: unknown): Bucket[] => {
  const list = (raw as { buckets?: unknown } | undefined)?.buckets;
  return Array.isArray(list) ? list.filter((b): b is Bucket => !!b && typeof b === "object") : [];
};
const count = (value: unknown) => { const n = Number(value); return Number.isFinite(n) && n >= 0 ? n : 0; };

export function parseAlertsResponse(raw: unknown): AlertsResult {
  const response = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const hits = response.hits as { total?: { value?: unknown } } | undefined;
  const volume = Number(hits?.total?.value ?? 0);
  if (!Number.isSafeInteger(volume) || volume < 0) throw new Error("O Indexer devolveu uma contagem inválida.");
  const escopo = ((response.aggregations ?? {}) as Record<string, any>).escopo ?? {};
  const revisaoAgg = escopo.revisao ?? {};
  const revisao = count(revisaoAgg.doc_count);

  const regras = buckets(revisaoAgg.regras).map((bucket) => {
    const registros = count(bucket.doc_count);
    const nivel = buckets(bucket.nivel)[0]?.key;
    const hit = (bucket.exemplo as any)?.hits?.hits?.[0]?.fields?.["rule.description"];
    return {
      id: String(bucket.key),
      descricao: Array.isArray(hit) && typeof hit[0] === "string" ? hit[0] : null,
      nivel: typeof nivel === "number" ? nivel : Number.isFinite(Number(nivel)) && nivel !== undefined ? Number(nivel) : null,
      registros,
      participacao: revisao > 0 ? registros / revisao : 0,
    };
  });
  const listed = regras.reduce((sum, rule) => sum + rule.registros, 0);

  return {
    volume,
    escopo: count(escopo.doc_count),
    revisao,
    admins: count(escopo.admins?.doc_count),
    decoders: buckets(escopo.decoders).map((b) => ({ nome: String(b.key), registros: count(b.doc_count) })),
    regras,
    outrasRegras: Math.max(0, revisao - listed),
  };
}
