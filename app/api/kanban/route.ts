import { createClient } from "@supabase/supabase-js";
import { getEpss, getKev } from "@/src/lib/cve-intelligence";
import { emptyKanbanFilters, type KanbanFilters, type KanbanSummary } from "@/src/lib/kanban";

export const maxDuration = 60;
const states = ["open", "in_progress", "awaiting_validation", "resolved"];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const validCve = /^CVE-\d{4}-\d{4,19}$/;

export async function POST(request: Request) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  const token = request.headers.get("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  if (!url || !key || !token) return Response.json({ error: "Sessão necessária." }, { status: 401 });
  const body = await request.json().catch(() => null);
  if (!body || !states.includes(body.status) || (body.companyId && !uuid.test(body.companyId))
    || !Number.isInteger(body.page) || body.page < 0 || body.page > 100000
    || typeof body.search !== "string" || body.search.length > 160 || !body.filters || typeof body.filters !== "object") {
    return Response.json({ error: "Consulta inválida." }, { status: 400 });
  }
  const filters = { ...emptyKanbanFilters, ...body.filters } as KanbanFilters;
  if (Object.values(filters).some((value) => typeof value !== "string")
    || !["", "yes", "no"].includes(filters.kev) || !["", "yes", "no"].includes(filters.criticalAsset)
    || !["", "Critical", "High", "Medium", "Low", "Informational", "Unknown"].includes(filters.severity)
    || [filters.dateFrom, filters.dateTo].some((date) => date && (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(Date.parse(date))))) {
    return Response.json({ error: "Filtros inválidos." }, { status: 400 });
  }
  for (const [min, max, ceiling] of [[filters.epssMin, filters.epssMax, 100], [filters.cvssMin, filters.cvssMax, 10]] as const) {
    if ([min, max].some((value) => value !== "" && (!Number.isFinite(Number(value)) || Number(value) < 0 || Number(value) > ceiling))
      || min !== "" && max !== "" && Number(min) > Number(max)) return Response.json({ error: "Faixa inválida." }, { status: 400 });
  }
  if (filters.dateFrom && filters.dateTo && filters.dateFrom > filters.dateTo) return Response.json({ error: "Datas inválidas." }, { status: 400 });
  const client = createClient(url, key, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false, autoRefreshToken: false } });
  const { data: user, error: authError } = await client.auth.getUser(token);
  if (authError || !user.user) return Response.json({ error: "Sessão inválida." }, { status: 401 });
  try {
    const { data, error } = await client.rpc("get_kanban_groups", { p_company_id: body.companyId || null, p_search: body.search.trim() }).abortSignal(request.signal);
    if (error) throw new Error("Não foi possível consultar os CVEs.");
    let groups = (data ?? []) as KanbanSummary[];
    groups = groups.filter((group) => group.status === body.status
      && (!filters.severity || group.severity === filters.severity)
      && (filters.cvssMin === "" || group.cvss != null && group.cvss >= Number(filters.cvssMin))
      && (filters.cvssMax === "" || group.cvss != null && group.cvss <= Number(filters.cvssMax))
      && (!filters.criticalAsset || group.criticalAsset === (filters.criticalAsset === "yes"))
      && (!filters.dateFrom || group.firstDetected.slice(0, 10) >= filters.dateFrom)
      && (!filters.dateTo || group.firstDetected.slice(0, 10) <= filters.dateTo));
    if (!groups.length) return Response.json({ items: [], total: 0, page: 0 }, { headers: { "cache-control": "private, no-store" } });
    const catalog = await getKev();
    const kev = new Set(catalog.vulnerabilities.map((item) => item.cveID));
    groups = groups.filter((group) => !filters.kev || kev.has(group.cve) === (filters.kev === "yes"));
    const epss = new Map<string, number>();
    const hasEpssRange = filters.epssMin !== "" || filters.epssMax !== "";
    if (hasEpssRange) {
      const cves = [...new Set(groups.map((group) => group.cve).filter((cve) => validCve.test(cve)))];
      for (let start = 0; start < cves.length; start += 800) {
        if (request.signal.aborted) throw new Error("Consulta interrompida.");
        const chunks = Array.from({ length: Math.ceil(Math.min(800, cves.length - start) / 100) }, (_, i) => cves.slice(start + i * 100, start + (i + 1) * 100));
        const replies = await Promise.all(chunks.map(getEpss));
        for (const rows of replies) for (const row of rows) {
          const value = Number(row.epss);
          if (Number.isFinite(value) && value >= 0 && value <= 1) epss.set(row.cve, value);
        }
      }
      groups = groups.filter((group) => {
        const value = epss.get(group.cve);
        return value != null && value * 100 >= Number(filters.epssMin || 0) && value * 100 <= Number(filters.epssMax || 100);
      });
    }
    if (!hasEpssRange) {
      const knownExploited = [...new Set(groups.map((group) => group.cve).filter((cve) => kev.has(cve) && validCve.test(cve)))];
      for (let start = 0; start < knownExploited.length; start += 100) {
        const rows = await getEpss(knownExploited.slice(start, start + 100)).catch(() => []);
        for (const row of rows) { const value = Number(row.epss); if (Number.isFinite(value) && value >= 0 && value <= 1) epss.set(row.cve, value); }
      }
    }
    const mandatory = (group: KanbanSummary) => kev.has(group.cve) && (epss.get(group.cve) ?? 0) >= 0.088;
    groups.sort((a, b) => Number(mandatory(b)) - Number(mandatory(a)) || (b.cvss ?? -1) - (a.cvss ?? -1)
      || b.caseCount - a.caseCount || a.key.localeCompare(b.key));
    const page = Math.min(body.page, Math.max(0, Math.ceil(groups.length / 5) - 1));
    const items = groups.slice(page * 5, page * 5 + 5);
    if (!hasEpssRange) {
      const cves = [...new Set(items.map((group) => group.cve).filter((cve) => validCve.test(cve)))];
      const missing = cves.filter((cve) => !epss.has(cve));
      if (missing.length) {
        const rows = await getEpss(missing).catch(() => []);
        for (const row of rows) { const value = Number(row.epss); if (Number.isFinite(value) && value >= 0 && value <= 1) epss.set(row.cve, value); }
      }
    }
    return Response.json({ items: items.map((group) => {
      const probability = epss.get(group.cve) ?? null;
      return { ...group, intelligence: { kev: kev.has(group.cve), epss: probability },
        mandatory: kev.has(group.cve) && probability != null && probability >= 0.088,
        score: Math.min(100, Math.round((group.cvss ?? 0) * 6 + (kev.has(group.cve) ? 25 : 0) + (probability ?? 0) * 15)) };
    }), total: groups.length, page }, { headers: { "cache-control": "private, no-store" } });
  } catch {
    return Response.json({ error: "Não foi possível consultar os filtros. Tente novamente." }, { status: 503 });
  }
}
