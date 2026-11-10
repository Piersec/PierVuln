// Visão executiva do Book SOC: estado atual das vulnerabilidades, lido direto do Indexer.
// Só agregados saem do servidor; documentos individuais nunca são devolvidos.
// A idade usa vulnerability.detected_at, a data de detecção registrada na própria fonte.

export type OverviewRequest = { client: string };

export function parseOverviewRequest(body: unknown): OverviewRequest | null {
  if (!body || typeof body !== "object") return null;
  const { client } = body as Record<string, unknown>;
  return typeof client === "string" && /^[a-z0-9-]{1,48}$/.test(client) ? { client } : null;
}

export const AGE_LABELS = ["Até 7 dias", "8–30 dias", "31–90 dias", "Mais de 90 dias"];

// `now` vem do servidor da aplicação: o relógio do cluster do Indexer não é referência para a idade.
export function buildOverviewQuery(now: Date = new Date()) {
  const day = 86_400_000;
  const bound = (days: number) => new Date(now.getTime() - days * day).toISOString();
  return {
    size: 0,
    track_total_hits: true,
    query: { match_all: {} },
    aggs: {
      severidade: { terms: { field: "vulnerability.severity", size: 10 } },
      hosts: { cardinality: { field: "agent.id" } },
      cves: { cardinality: { field: "vulnerability.id" } },
      idade: {
        date_range: {
          field: "vulnerability.detected_at",
          ranges: [{ from: bound(7) }, { from: bound(30), to: bound(7) }, { from: bound(90), to: bound(30) }, { to: bound(90) }],
        },
      },
      meses: {
        date_histogram: { field: "vulnerability.detected_at", calendar_interval: "month", min_doc_count: 0, format: "yyyy-MM" },
      },
      topCves: {
        terms: { field: "vulnerability.id", size: 10, order: { hosts: "desc" } },
        aggs: {
          hosts: { cardinality: { field: "agent.id" } },
          severidade: { terms: { field: "vulnerability.severity", size: 1 } },
          cvss: { max: { field: "vulnerability.score.base" } },
        },
      },
    },
  };
}

export type Overview = {
  total: number;
  hosts: number;
  cves: number;
  porSeveridade: { severidade: string; registros: number }[];
  idade: { label: string; registros: number }[];
  meses: { mes: string; registros: number }[];
  topCves: { cve: string; severidade: string; cvss: number | null; registros: number; hosts: number }[];
};

type Bucket = Record<string, unknown> & { key?: unknown; doc_count?: unknown };

function buckets(raw: unknown): Bucket[] {
  const list = (raw as { buckets?: unknown } | undefined)?.buckets;
  return Array.isArray(list) ? list.filter((b): b is Bucket => !!b && typeof b === "object") : [];
}

// Faixa sem limite inferior ("mais de 90 dias") conta como o mais antigo possível.
const lowerBound = (bucket: Bucket) => { const n = Number((bucket as { from?: unknown }).from); return Number.isFinite(n) ? n : -Infinity; };
const count = (value: unknown) => { const n = Number(value); return Number.isFinite(n) && n >= 0 ? n : 0; };
const value = (raw: unknown) => count((raw as { value?: unknown } | undefined)?.value);

export function parseOverviewResponse(raw: unknown): Overview {
  const response = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const hits = response.hits as { total?: { value?: unknown } } | undefined;
  const total = Number(hits?.total?.value ?? 0);
  if (!Number.isSafeInteger(total) || total < 0) throw new Error("O Indexer devolveu uma contagem inválida.");
  const aggs = (response.aggregations ?? {}) as Record<string, unknown>;

  // O date_range devolve as faixas ordenadas pelo limite inferior (a mais antiga primeiro), não na ordem pedida.
  // Ordena da mais recente para a mais antiga: até 7, 8–30, 31–90 e mais de 90 dias.
  const idadeBuckets = buckets(aggs.idade).sort((a, b) => lowerBound(b) - lowerBound(a));
  const idade = AGE_LABELS.map((label, index) => ({ label, registros: count(idadeBuckets[index]?.doc_count) }));

  return {
    total,
    hosts: value(aggs.hosts),
    cves: value(aggs.cves),
    porSeveridade: buckets(aggs.severidade).map((b) => ({ severidade: String(b.key), registros: count(b.doc_count) })),
    idade,
    meses: buckets(aggs.meses).map((b) => ({ mes: String((b as { key_as_string?: unknown }).key_as_string ?? b.key), registros: count(b.doc_count) })),
    topCves: buckets(aggs.topCves).map((b) => {
      const severidade = buckets(b.severidade)[0]?.key;
      const cvss = (b.cvss as { value?: unknown } | undefined)?.value;
      return {
        cve: String(b.key), severidade: severidade === undefined ? "—" : String(severidade),
        cvss: typeof cvss === "number" && Number.isFinite(cvss) ? Math.round(cvss * 10) / 10 : null,
        registros: count(b.doc_count), hosts: value(b.hosts),
      };
    }),
  };
}

// Últimos `size` meses terminando no mês atual, preenchendo com zero os meses sem registro.
export function lastMonths(meses: Overview["meses"], size = 6, now = new Date()) {
  const byMonth = new Map(meses.map((item) => [item.mes, item.registros]));
  return Array.from({ length: size }, (_, index) => {
    const date = new Date(now.getFullYear(), now.getMonth() - (size - 1 - index), 1);
    const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
    return { key, registros: byMonth.get(key) ?? 0 };
  });
}
