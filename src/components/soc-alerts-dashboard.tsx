"use client";

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import Link from "next/link";
import { Activity, AlertTriangle, RefreshCw } from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import type { SupabaseClient } from "@supabase/supabase-js";
import { visibleText } from "@/src/lib/visible-text";

type Period = "24h" | "7d" | "30d";
type CaseFilter = "all" | "linked" | "unlinked";
type Severity = "critical" | "high" | "medium" | "low" | "informational" | "unknown";
type Summary = {
  total: number; critical_high: number; unknown: number; sources: number;
  severity: Record<Severity, number>;
  series: { bucket: string; count: number }[];
  top_sources: { id: string; name: string; category: string | null; count: number }[];
  top_rules: { id: string; name: string | null; count: number }[];
  bucket_unit: "hour" | "day";
};
type Alert = {
  id: string; source_id: string; source_name: string; source_category: string | null;
  source_event_id: string; occurred_at: string; severity: Severity; severity_original: string | null;
  title: string; message: string | null; rule_id: string | null; rule_description: string | null;
  rule_level: number | null; agent_id: string | null; agent_name: string | null; src_ip: string | null;
  dst_ip: string | null; src_port: number | null; dst_port: number | null; network_protocol: string | null;
  service: string | null; source_action: string | null; normalized_action: string | null;
  mitre_ids: string[]; file_path: string | null; file_action: string | null;
  file_hash_before: string | null; file_hash_after: string | null; raw_payload: Record<string, unknown> | null;
  file_owner_after: string | null; change_actor: string | null; change_process: string | null; agent_ip: string | null;
  soc_case_alerts?: { alert_id: string }[];
};

const severityLabels: Record<Severity, string> = {
  critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo",
  informational: "Informativo", unknown: "Sem classificação",
};
const severityOrder: Severity[] = ["critical", "high", "medium", "low", "informational", "unknown"];
const pageSize = 50;

function sinceFor(period: Period, now: Date) {
  const since = new Date(now);
  since.setTime(since.getTime() - (period === "24h" ? 24 : period === "7d" ? 7 * 24 : 30 * 24) * 60 * 60 * 1000);
  return since;
}

function formatCount(value: number) { return value.toLocaleString("pt-BR"); }
function formatDate(value: string) { return new Date(value).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" }); }
function formatBucket(value: string, unit: "hour" | "day") {
  const date = new Date(value);
  return unit === "hour" ? date.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit" })
    : date.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" });
}

export function SocAlertsDashboard({ client, companyId, canManage }: { client: SupabaseClient; companyId: string; canManage: boolean }) {
  const [period, setPeriod] = useState<Period>("24h");
  const [severity, setSeverity] = useState("");
  const [caseFilter, setCaseFilter] = useState<CaseFilter>("all");
  const [filteredCount, setFilteredCount] = useState(0);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [listLoading, setListLoading] = useState(true);
  const [error, setError] = useState("");
  const [reloadId, setReloadId] = useState(0);
  const [realtimeCompanyId, setRealtimeCompanyId] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [createAlert, setCreateAlert] = useState<Alert | null>(null);
  const [createSeverity, setCreateSeverity] = useState("");
  const [createNotes, setCreateNotes] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");
  const [createdCases, setCreatedCases] = useState<Record<string, string>>({});
  const range = useMemo(() => {
    const until = new Date();
    return { since: sinceFor(period, until).toISOString(), until: until.toISOString() };
  }, [period, reloadId]);
  const realtimeConnected = companyId ? realtimeCompanyId === companyId : realtimeCompanyId === "*";
  const refreshing = summaryLoading || listLoading;

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search.trim()), 250);
    return () => clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    let active = true;
    let refreshTimer: ReturnType<typeof setTimeout> | undefined;
    const requestRefresh = () => {
      if (refreshTimer) return;
      refreshTimer = setTimeout(() => {
        refreshTimer = undefined;
        if (active) setReloadId((value) => value + 1);
      }, 2500);
    };
    const channel = client.channel(`soc-alerts-${companyId || "all"}`)
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "soc_alerts", ...(companyId ? { filter: `tenant_id=eq.${companyId}` } : {}) }, requestRefresh)
      .subscribe((status) => { if (active) setRealtimeCompanyId(status === "SUBSCRIBED" ? companyId || "*" : ""); });
    const fallback = setInterval(requestRefresh, 60_000);
    return () => {
      active = false;
      if (refreshTimer) clearTimeout(refreshTimer);
      clearInterval(fallback);
      void client.removeChannel(channel);
    };
  }, [client, companyId]);

  const loadSummary = useCallback(async (signal: AbortSignal) => {
    setSummaryLoading(true);
    try {
      const { data, error: queryError } = await client.rpc("get_soc_alert_summary", {
        p_tenant_id: companyId || null, p_since: range.since, p_until: range.until,
      }).abortSignal(signal);
      if (queryError) throw queryError;
      setSummary(data as Summary);
      setError("");
    } catch {
      if (!signal.aborted) setError("Não foi possível atualizar o resumo. Os últimos dados carregados foram mantidos.");
    } finally { if (!signal.aborted) setSummaryLoading(false); }
  }, [client, companyId, range]);

  const loadAlerts = useCallback(async (signal: AbortSignal) => {
    setListLoading(true);
    try {
      let query = client.from("soc_alerts").select(
        "id,source_id,source_name,source_category,source_event_id,occurred_at,severity,severity_original,title,message,rule_id,rule_description,rule_level,agent_id,agent_name,agent_ip,src_ip,dst_ip,src_port,dst_port,network_protocol,service,source_action,normalized_action,mitre_ids,file_path,file_action,file_hash_before,file_hash_after,file_owner_after,change_actor,change_process,raw_payload,soc_case_alerts(alert_id)", { count: "exact" },
      ).gte("occurred_at", range.since).lt("occurred_at", range.until)
        .order("occurred_at", { ascending: false }).order("id", { ascending: false })
        .range(page * pageSize, page * pageSize + pageSize - 1).abortSignal(signal);
      if (companyId) query = query.eq("tenant_id", companyId);
      if (severity) query = query.eq("severity", severity);
      if (caseFilter === "linked") query = query.not("soc_case_alerts", "is", null);
      if (caseFilter === "unlinked") query = query.is("soc_case_alerts", null);
      const term = debouncedSearch.replace(/[%,()]/g, " ").trim();
      if (term) query = query.or(`title.ilike.%${term}%,source_name.ilike.%${term}%,agent_name.ilike.%${term}%,rule_id.ilike.%${term}%`);
      const { data, error: queryError, count } = await query;
      if (queryError) throw queryError;
      const received = (data ?? []) as Alert[];
      setAlerts(received);
      setFilteredCount(count ?? 0);
      setHasMore((page + 1) * pageSize < (count ?? 0));
      setError("");
    } catch {
      if (!signal.aborted) setError("Não foi possível atualizar a lista. Os últimos dados carregados foram mantidos.");
    } finally { if (!signal.aborted) setListLoading(false); }
  }, [caseFilter, client, companyId, debouncedSearch, page, range, severity]);

  useEffect(() => {
    const controller = new AbortController();
    void loadSummary(controller.signal);
    return () => controller.abort();
  }, [loadSummary]);

  useEffect(() => {
    const controller = new AbortController();
    void loadAlerts(controller.signal);
    return () => controller.abort();
  }, [loadAlerts]);

  function changePeriod(next: Period) { setPage(0); setPeriod(next); }
  function changeSeverity(next: string) { setPage(0); setSeverity(next); }
  function changeSearch(next: string) { setPage(0); setSearch(next); }
  function changeCaseFilter(next: CaseFilter) { setPage(0); setCaseFilter(next); }

  async function createIncident(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!createAlert || !canManage || !createSeverity) return;
    setCreating(true); setCreateError("");
    const { data, error: rpcError } = await client.rpc("create_soc_case_from_alert", {
      p_alert_id: createAlert.id, p_case_severity: createSeverity, p_assigned_to: null, p_notes: createNotes.trim(),
    });
    setCreating(false);
    if (rpcError || !data) { setCreateError("Não foi possível abrir o incidente. O alerta permanece preservado na fila."); return; }
    setCreatedCases((current) => ({ ...current, [createAlert.id]: String(data) }));
    setCaseFilter("linked"); setPage(0); setReloadId((value) => value + 1); setCreateAlert(null); setCreateNotes("");
  }

  const count = (key: Severity) => summary?.severity?.[key] ?? 0;
  const buckets = useMemo(() => (summary?.series ?? []).map((item) => ({ ...item, label: formatBucket(item.bucket, summary?.bucket_unit ?? "hour") })), [summary]);
  const receivedInWindow = summary?.total ?? 0;

  return <section className="soc-dashboard" id="alerts">
    <div className="page-heading soc-dashboard-heading"><div><span className="page-kicker">CENTRO DE OPERAÇÕES</span><h1>Alertas SOC</h1><p>Eventos de segurança recebidos de forma segregada por empresa.</p></div>
      <div className="soc-dashboard-actions"><span className={`soc-live-state${realtimeConnected ? " is-connected" : ""}`} role="status"><i aria-hidden="true" />{realtimeConnected ? "Ao vivo" : "Atualização automática"}</span><select aria-label="Período de alertas" value={period} onChange={(event) => changePeriod(event.target.value as Period)}><option value="24h">Últimas 24 horas</option><option value="7d">Últimos 7 dias</option><option value="30d">Últimos 30 dias</option></select><button className="button button-secondary" disabled={refreshing} onClick={() => setReloadId((value) => value + 1)}><RefreshCw size={15} aria-hidden="true" />{refreshing ? "Atualizando…" : "Atualizar"}</button></div>
    </div>
    {error && <div className="inline-alert" role="alert">{error}</div>}
    <div className="soc-kpis" aria-label="Resumo dos alertas">
      <article className="soc-kpi"><span>Alertas recebidos</span><strong>{summary ? formatCount(summary.total) : "—"}</strong><small>Período selecionado</small></article>
      <article className="soc-kpi soc-kpi-critical"><span>Críticos e altos</span><strong>{summary ? formatCount(summary.critical_high) : "—"}</strong><small>{summary ? `${formatCount(count("critical"))} críticos · ${formatCount(count("high"))} altos` : "Resumo indisponível"}</small></article>
      <article className="soc-kpi"><span>Fontes com alertas</span><strong>{summary ? formatCount(summary.sources) : "—"}</strong><small>Fontes distintas no período</small></article>
      <article className="soc-kpi"><span>Sem classificação</span><strong>{summary ? formatCount(summary.unknown) : "—"}</strong><small>Severidade desconhecida na origem</small></article>
    </div>

    <div className="soc-analytics-grid">
      <article className="panel soc-panel soc-trend-panel"><header><div><h2>Volume de alertas</h2><p>Eventos por {summary?.bucket_unit === "day" ? "dia" : "hora"} no período selecionado.</p></div><span>{formatCount(receivedInWindow)} alertas</span></header>
        <div className="soc-chart">{summaryLoading && !summary ? <div className="soc-chart-loading" aria-label="Carregando gráfico" /> : !summary?.total ? <div className="soc-chart-empty"><Activity size={22} aria-hidden="true" /><span>Nenhum alerta recebido neste período.</span></div> : <ResponsiveContainer width="100%" height="100%"><AreaChart data={buckets} margin={{ top: 14, right: 12, bottom: 0, left: -16 }}><defs><linearGradient id="soc-alert-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--accent)" stopOpacity={0.42} /><stop offset="100%" stopColor="var(--accent)" stopOpacity={0.02} /></linearGradient></defs><CartesianGrid stroke="var(--line)" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="label" tick={{ fill: "var(--muted)", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "var(--line)" }} minTickGap={22} /><YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11 }} tickLine={false} axisLine={false} /><Tooltip contentStyle={{ background: "var(--surface-raised)", border: "1px solid var(--line)", borderRadius: 10, color: "var(--ink)" }} labelStyle={{ color: "var(--muted-strong)" }} /><Area type="monotone" dataKey="count" name="Alertas" stroke="var(--accent)" strokeWidth={2.5} fill="url(#soc-alert-fill)" /></AreaChart></ResponsiveContainer>}</div>
      </article>
      <article className="panel soc-panel soc-severity-panel"><header><div><h2>Alertas por gravidade</h2><p>Distribuição no período.</p></div></header><div className="soc-severity-list">{severityOrder.map((key) => <div className={`soc-severity-row severity-${key}`} key={key}><span><i aria-hidden="true" />{severityLabels[key]}</span><strong>{summary ? formatCount(count(key)) : summaryLoading ? "—" : "0"}</strong></div>)}</div></article>
      <article className="panel soc-panel"><header><div><h2>Principais fontes</h2><p>Fontes com mais eventos recebidos.</p></div></header>{summary?.top_sources.length ? <ol className="soc-ranking-list">{summary.top_sources.map((item) => <li key={item.id}><span><strong>{visibleText(item.name)}</strong><small>{visibleText(item.category ?? item.id)}</small></span><b>{formatCount(item.count)}</b></li>)}</ol> : <div className="soc-panel-empty">Ainda sem dados de fontes.</div>}</article>
      <article className="panel soc-panel"><header><div><h2>Regras mais acionadas</h2><p>IDs e descrições informados pela origem.</p></div></header>{summary?.top_rules.length ? <ol className="soc-ranking-list">{summary.top_rules.map((item) => <li key={item.id}><span><strong>{visibleText(item.name ?? item.id)}</strong><small>{visibleText(item.id)}</small></span><b>{formatCount(item.count)}</b></li>)}</ol> : <div className="soc-panel-empty">Ainda sem regras recebidas.</div>}</article>
    </div>

    <section className="panel soc-alert-list-panel"><header className="soc-alert-list-heading"><div><h2>Fila de alertas</h2><p>Eventos técnicos da origem; incidentes têm fluxo próprio e histórico de atendimento.</p></div><span>{summary ? `${formatCount(summary.total)} no período` : "Resumo indisponível"}</span></header>
      <div className="soc-alert-filters soc-alert-filters-three"><label className="sr-only" htmlFor="soc-alert-search">Buscar alertas</label><input id="soc-alert-search" type="search" placeholder="Buscar título, fonte, agente ou regra…" value={search} onChange={(event) => changeSearch(event.target.value)} /><label className="sr-only" htmlFor="soc-alert-severity">Filtrar gravidade</label><select id="soc-alert-severity" value={severity} onChange={(event) => changeSeverity(event.target.value)}><option value="">Todas as gravidades</option>{severityOrder.map((key) => <option value={key} key={key}>{severityLabels[key]}</option>)}</select><label className="sr-only" htmlFor="soc-alert-case">Vínculo com incidente</label><select id="soc-alert-case" value={caseFilter} onChange={(event) => changeCaseFilter(event.target.value as CaseFilter)}><option value="all">Com ou sem incidente</option><option value="linked">Com incidente</option><option value="unlinked">Sem incidente</option></select></div>
      {listLoading && !alerts.length ? <div className="soc-alert-skeletons" aria-label="Carregando alertas">{Array.from({ length: 5 }, (_, index) => <div className="soc-alert-skeleton" key={index} />)}</div> : !alerts.length ? <div className="soc-alert-empty"><AlertTriangle size={22} aria-hidden="true" /><strong>Nenhum alerta encontrado</strong><p>{caseFilter === "linked" ? "Não há alertas vinculados a incidentes nesta busca." : caseFilter === "unlinked" ? "Não há alertas sem incidente nesta busca." : "Quando houver alertas para os filtros selecionados, eles aparecerão aqui."}</p>{canManage && !companyId && <small>Selecione uma empresa para iniciar atendimentos.</small>}</div> : <div className="soc-alert-table-wrap"><table className="soc-alert-table"><thead><tr><th>Gravidade</th><th>Data e hora</th><th>Alerta / regra</th><th>Fonte</th><th>Ativo</th><th>Origem</th><th>Incidente</th><th>Detalhes</th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id}><td><span className={`soc-severity-badge severity-${alert.severity}`}>{severityLabels[alert.severity]}</span></td><td><time dateTime={alert.occurred_at}>{formatDate(alert.occurred_at)}</time></td><td><strong>{visibleText(alert.title)}</strong>{alert.rule_id && <small>{visibleText(alert.rule_id)}{alert.rule_description ? ` · ${visibleText(alert.rule_description)}` : ""}</small>}</td><td>{visibleText(alert.source_name)}</td><td>{visibleText(alert.agent_name ?? alert.agent_id ?? "—")}</td><td>{visibleText(alert.src_ip ?? "—")}{alert.src_port ? `:${alert.src_port}` : ""}</td><td>{createdCases[alert.id] ? <Link href={`/incidentes?company=${companyId}`} className="soc-inline-link">Incidente criado →</Link> : canManage && companyId && !(alert.soc_case_alerts?.length) ? <button className="button button-secondary soc-case-edit-button" onClick={() => { setCreateAlert(alert); setCreateSeverity(["critical","high","medium","low"].includes(alert.severity) ? alert.severity : ""); }}>Abrir incidente</button> : alert.soc_case_alerts?.length ? <Link href={`/incidentes?company=${companyId}`} className="soc-inline-link">Ver incidente →</Link> : "—"}</td><td><details className="soc-alert-details"><summary>Ver</summary><div><p>{visibleText(alert.message ?? "Sem descrição adicional.")}</p><dl>{alert.agent_ip && <><dt>IP do ativo</dt><dd>{visibleText(alert.agent_ip)}</dd></>}{alert.dst_ip && <><dt>Destino</dt><dd>{visibleText(alert.dst_ip)}{alert.dst_port ? `:${alert.dst_port}` : ""}</dd></>}{alert.network_protocol && <><dt>Protocolo</dt><dd>{visibleText(alert.network_protocol)}</dd></>}{alert.service && <><dt>Serviço</dt><dd>{visibleText(alert.service)}</dd></>}{alert.source_action && <><dt>Ação da origem</dt><dd>{visibleText(alert.source_action)}</dd></>}{alert.normalized_action && <><dt>Ação normalizada</dt><dd>{visibleText(alert.normalized_action)}</dd></>}{alert.file_path && <><dt>Arquivo</dt><dd>{visibleText(alert.file_path)}</dd></>}{alert.change_actor && <><dt>Autor informado</dt><dd>{visibleText(alert.change_actor)}</dd></>}{alert.change_process && <><dt>Processo informado</dt><dd>{visibleText(alert.change_process)}</dd></>}{alert.file_owner_after && <><dt>Proprietário atual</dt><dd>{visibleText(alert.file_owner_after)}</dd></>}{alert.file_hash_before && <><dt>Hash anterior</dt><dd>{visibleText(alert.file_hash_before)}</dd></>}{alert.file_hash_after && <><dt>Hash atual</dt><dd>{visibleText(alert.file_hash_after)}</dd></>}{alert.mitre_ids.length > 0 && <><dt>MITRE ATT&amp;CK</dt><dd>{alert.mitre_ids.map(visibleText).join(", ")}</dd></>}{alert.severity_original && <><dt>Severidade original</dt><dd>{visibleText(alert.severity_original)}</dd></>}{alert.source_event_id && <><dt>ID de origem</dt><dd>{visibleText(alert.source_event_id)}</dd></>}</dl>{alert.raw_payload && <details><summary>Payload resumido da origem</summary><pre>{JSON.stringify(alert.raw_payload, null, 2)}</pre></details>}</div></details></td></tr>)}</tbody></table></div>}
      <footer className="soc-pagination"><span>Página {page + 1} · {formatCount(alerts.length)} desta página · {formatCount(filteredCount)} resultados nos filtros · {formatCount(receivedInWindow)} no período</span><div><button className="button button-secondary" disabled={!page || refreshing} onClick={() => setPage((value) => Math.max(0, value - 1))}>Anterior</button><button className="button button-secondary" disabled={!hasMore || refreshing} onClick={() => setPage((value) => value + 1)}>Próxima</button></div></footer>
    </section>
    {createAlert && <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !creating) setCreateAlert(null); }}><section className="panel soc-case-dialog" role="dialog" aria-modal="true" aria-labelledby="soc-create-case-title"><header><div><span className="page-kicker">NOVO ATENDIMENTO</span><h2 id="soc-create-case-title">Abrir incidente</h2></div><button type="button" className="button button-secondary" onClick={() => setCreateAlert(null)}>Fechar</button></header><p className="soc-create-alert-source">{visibleText(createAlert.title)} · severidade da origem: {severityLabels[createAlert.severity]}</p><form onSubmit={(event) => void createIncident(event)}><label>Severidade do incidente<select required value={createSeverity} onChange={(event) => setCreateSeverity(event.target.value)}><option value="">Selecione a severidade</option>{Object.entries({ critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa" }).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label>Notas iniciais<textarea maxLength={4000} rows={4} value={createNotes} onChange={(event) => setCreateNotes(event.target.value)} placeholder="Contexto inicial (opcional)"/></label>{createError && <div className="inline-alert" role="alert">{createError}</div>}<div className="soc-case-dialog-actions"><button type="button" className="button button-secondary" disabled={creating} onClick={() => setCreateAlert(null)}>Cancelar</button><button className="button button-primary" disabled={creating || !createSeverity}>{creating ? "Abrindo…" : "Criar e vincular"}</button></div></form></section></div>}
  </section>;
}
