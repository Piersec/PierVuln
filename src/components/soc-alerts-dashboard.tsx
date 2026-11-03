"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
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
type AiPriority = "critical" | "high" | "medium" | "low";
type AiTriage = {
  status: "completed" | "unavailable";
  priority: AiPriority | null;
  confidence: number | null;
  summary: string;
  recommended_action: string;
  model: string | null;
};
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
const aiPriorityOrder: AiPriority[] = ["critical", "high", "medium", "low"];
const aiPriorityLabels: Record<AiPriority, string> = { critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa" };
const pageSize = 50;

function readAiTriage(rawPayload: Record<string, unknown> | null): AiTriage | null {
  const value = rawPayload?.ai_triage;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  const priority = aiPriorityOrder.includes(candidate.priority as AiPriority) ? candidate.priority as AiPriority : null;
  const confidenceValue = candidate.confidence;
  const confidence = typeof confidenceValue === "number" && Number.isFinite(confidenceValue)
    ? Math.max(0, Math.min(1, confidenceValue)) : null;
  const status = candidate.status === "completed" && priority ? "completed" : "unavailable";
  return {
    status,
    priority,
    confidence,
    summary: typeof candidate.summary === "string" ? candidate.summary : "",
    recommended_action: typeof candidate.recommended_action === "string" ? candidate.recommended_action : "",
    model: typeof candidate.model === "string" ? candidate.model : null,
  };
}

function AlertDetailField({ label, value }: { label: string; value: string | null | undefined }) {
  if (value == null || value === "") return null;
  return <div><dt>{label}</dt><dd>{visibleText(value)}</dd></div>;
}

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
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const alertDialogRef = useRef<HTMLElement | null>(null);
  const alertDialogCloseRef = useRef<HTMLButtonElement | null>(null);
  const alertTriggerRef = useRef<HTMLButtonElement | null>(null);
  const range = useMemo(() => {
    const until = new Date();
    return { since: sinceFor(period, until).toISOString(), until: until.toISOString() };
  }, [period, reloadId]);
  const realtimeConnected = companyId ? realtimeCompanyId === companyId : realtimeCompanyId === "*";
  const refreshing = summaryLoading || listLoading;

  useEffect(() => {
    if (!selectedAlert) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const focusFrame = window.requestAnimationFrame(() => alertDialogCloseRef.current?.focus());
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setSelectedAlert(null);
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = alertDialogRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      alertTriggerRef.current?.focus();
    };
  }, [selectedAlert]);

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

  function openAlertDetails(alert: Alert, trigger: HTMLButtonElement) {
    alertTriggerRef.current = trigger;
    setSelectedAlert(alert);
  }

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
  const selectedTriage = selectedAlert ? readAiTriage(selectedAlert.raw_payload) : null;

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
      {listLoading && !alerts.length ? <div className="soc-alert-skeletons" aria-label="Carregando alertas">{Array.from({ length: 5 }, (_, index) => <div className="soc-alert-skeleton" key={index} />)}</div> : !alerts.length ? <div className="soc-alert-empty"><AlertTriangle size={22} aria-hidden="true" /><strong>Nenhum alerta encontrado</strong><p>{caseFilter === "linked" ? "Não há alertas vinculados a incidentes nesta busca." : caseFilter === "unlinked" ? "Não há alertas sem incidente nesta busca." : "Quando houver alertas para os filtros selecionados, eles aparecerão aqui."}</p>{canManage && !companyId && <small>Selecione uma empresa para iniciar atendimentos.</small>}</div> : <div className="soc-alert-table-wrap"><table className="soc-alert-table"><thead><tr><th>Gravidade</th><th>Data e hora</th><th>Alerta / regra</th><th>Fonte</th><th>Ativo</th><th>Origem</th><th>Incidente</th><th>Detalhes</th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id}><td><span className={`soc-severity-badge severity-${alert.severity}`}>{severityLabels[alert.severity]}</span></td><td><time dateTime={alert.occurred_at}>{formatDate(alert.occurred_at)}</time></td><td><button type="button" className="soc-alert-open-title" onClick={(event) => openAlertDetails(alert, event.currentTarget)}><strong>{visibleText(alert.title)}</strong>{alert.rule_id && <small>{visibleText(alert.rule_id)}{alert.rule_description ? ` · ${visibleText(alert.rule_description)}` : ""}</small>}</button></td><td>{visibleText(alert.source_name)}</td><td>{visibleText(alert.agent_name ?? alert.agent_id ?? "—")}</td><td>{visibleText(alert.src_ip ?? "—")}{alert.src_port ? `:${alert.src_port}` : ""}</td><td>{createdCases[alert.id] ? <Link href={`/incidentes?company=${companyId}`} className="soc-inline-link">Incidente criado →</Link> : canManage && companyId && !(alert.soc_case_alerts?.length) ? <button className="button button-secondary soc-case-edit-button" onClick={() => { setCreateAlert(alert); setCreateSeverity(["critical","high","medium","low"].includes(alert.severity) ? alert.severity : ""); }}>Abrir incidente</button> : alert.soc_case_alerts?.length ? <Link href={`/incidentes?company=${companyId}`} className="soc-inline-link">Ver incidente →</Link> : "—"}</td><td><button type="button" className="button button-secondary soc-alert-open-button" onClick={(event) => openAlertDetails(alert, event.currentTarget)}>Ver alerta</button></td></tr>)}</tbody></table></div>}
      <footer className="soc-pagination"><span>Página {page + 1} · {formatCount(alerts.length)} desta página · {formatCount(filteredCount)} resultados nos filtros · {formatCount(receivedInWindow)} no período</span><div><button className="button button-secondary" disabled={!page || refreshing} onClick={() => setPage((value) => Math.max(0, value - 1))}>Anterior</button><button className="button button-secondary" disabled={!hasMore || refreshing} onClick={() => setPage((value) => value + 1)}>Próxima</button></div></footer>
    </section>
    {selectedAlert && <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelectedAlert(null); }}>
      <section className="panel soc-case-dialog soc-alert-dialog" role="dialog" aria-modal="true" aria-labelledby="soc-alert-dialog-title" aria-describedby="soc-alert-dialog-help" ref={alertDialogRef}>
        <header>
          <div className="soc-alert-dialog-heading">
            <span className="page-kicker">ANÁLISE DO ALERTA</span>
            <h2 id="soc-alert-dialog-title">{visibleText(selectedAlert.title)}</h2>
            <div className="soc-alert-dialog-meta"><span className={`soc-severity-badge severity-${selectedAlert.severity}`}>{severityLabels[selectedAlert.severity]}</span><time dateTime={selectedAlert.occurred_at}>{formatDate(selectedAlert.occurred_at)}</time></div>
          </div>
          <button ref={alertDialogCloseRef} type="button" className="button button-secondary" onClick={() => setSelectedAlert(null)}>Fechar</button>
        </header>
        <p id="soc-alert-dialog-help" className="soc-alert-dialog-help">Triagem automática para apoiar a análise. Valide a recomendação antes de agir.</p>
        <section className="soc-ai-triage" aria-labelledby="soc-ai-triage-title">
          <header className="soc-ai-triage-heading"><div><h3 id="soc-ai-triage-title">Triagem da IA</h3><p>Resumo e recomendação para este alerta.</p></div><span className={`soc-ai-triage-state${selectedTriage?.status === "completed" ? " is-complete" : " is-unavailable"}`}>{selectedTriage?.status === "completed" ? "Triagem gerada" : "Sem triagem"}</span></header>
          {selectedTriage?.status === "completed" ? <>
            <div className="soc-ai-triage-metrics"><div><span>Prioridade sugerida</span><strong className={`soc-ai-priority severity-${selectedTriage.priority}`}>{selectedTriage.priority ? aiPriorityLabels[selectedTriage.priority] : "Não informada"}</strong></div>{selectedTriage.confidence !== null && <div><span>Confiança informada</span><strong>{Math.round(selectedTriage.confidence * 100)}%</strong></div>}{selectedTriage.model && <div><span>Modelo</span><strong>{visibleText(selectedTriage.model)}</strong></div>}</div>
            <div className="soc-ai-triage-copy"><h4>Resumo</h4><p>{visibleText(selectedTriage.summary) || "A triagem chegou sem resumo."}</p></div>
            <div className="soc-ai-triage-copy"><h4>Ação recomendada</h4><p>{visibleText(selectedTriage.recommended_action) || "Analise os dados do evento e siga o procedimento da equipe."}</p></div>
          </> : <div className="soc-ai-triage-empty"><strong>Este alerta não tem triagem registrada.</strong><p>Use os dados recebidos abaixo para fazer a análise manual.</p></div>}
          <p className="soc-ai-human-review">Revisão humana necessária. A recomendação não altera a gravidade original.</p>
        </section>
        <section className="soc-alert-event" aria-labelledby="soc-alert-event-title">
          <h3 id="soc-alert-event-title">Dados do alerta</h3>
          {selectedAlert.message && <p className="soc-alert-event-message">{visibleText(selectedAlert.message)}</p>}
          <dl className="soc-alert-detail-grid">
            <AlertDetailField label="Fonte" value={selectedAlert.source_name}/>
            <AlertDetailField label="Categoria" value={selectedAlert.source_category}/>
            <AlertDetailField label="Regra" value={selectedAlert.rule_description}/>
            <AlertDetailField label="ID da regra" value={selectedAlert.rule_id}/>
            <AlertDetailField label="Nível original" value={selectedAlert.rule_level == null ? null : String(selectedAlert.rule_level)}/>
            <AlertDetailField label="Severidade original" value={selectedAlert.severity_original}/>
            <AlertDetailField label="Ativo" value={selectedAlert.agent_name}/>
            <AlertDetailField label="ID do ativo" value={selectedAlert.agent_id}/>
            <AlertDetailField label="IP do ativo" value={selectedAlert.agent_ip}/>
            <AlertDetailField label="IP de origem" value={selectedAlert.src_ip == null ? null : selectedAlert.src_port == null ? selectedAlert.src_ip : `${selectedAlert.src_ip}:${selectedAlert.src_port}`}/>
            <AlertDetailField label="Destino" value={selectedAlert.dst_ip == null ? null : selectedAlert.dst_port == null ? selectedAlert.dst_ip : `${selectedAlert.dst_ip}:${selectedAlert.dst_port}`}/>
            <AlertDetailField label="Protocolo" value={selectedAlert.network_protocol}/>
            <AlertDetailField label="Serviço" value={selectedAlert.service}/>
            <AlertDetailField label="Ação da origem" value={selectedAlert.source_action}/>
            <AlertDetailField label="Ação normalizada" value={selectedAlert.normalized_action}/>
            <AlertDetailField label="Arquivo" value={selectedAlert.file_path}/>
            <AlertDetailField label="Autor informado" value={selectedAlert.change_actor}/>
            <AlertDetailField label="Processo informado" value={selectedAlert.change_process}/>
            <AlertDetailField label="MITRE ATT&amp;CK" value={selectedAlert.mitre_ids.length ? selectedAlert.mitre_ids.join(", ") : null}/>
            <AlertDetailField label="ID do evento" value={selectedAlert.source_event_id}/>
          </dl>
          {selectedAlert.raw_payload && <details className="soc-alert-source-payload"><summary>Payload técnico recebido</summary><pre>{JSON.stringify(selectedAlert.raw_payload, null, 2)}</pre></details>}
        </section>
      </section>
    </div>}
    {createAlert && <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !creating) setCreateAlert(null); }}><section className="panel soc-case-dialog" role="dialog" aria-modal="true" aria-labelledby="soc-create-case-title"><header><div><span className="page-kicker">NOVO ATENDIMENTO</span><h2 id="soc-create-case-title">Abrir incidente</h2></div><button type="button" className="button button-secondary" onClick={() => setCreateAlert(null)}>Fechar</button></header><p className="soc-create-alert-source">{visibleText(createAlert.title)} · severidade da origem: {severityLabels[createAlert.severity]}</p><form onSubmit={(event) => void createIncident(event)}><label>Severidade do incidente<select required value={createSeverity} onChange={(event) => setCreateSeverity(event.target.value)}><option value="">Selecione a severidade</option>{Object.entries({ critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa" }).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label>Notas iniciais<textarea maxLength={4000} rows={4} value={createNotes} onChange={(event) => setCreateNotes(event.target.value)} placeholder="Contexto inicial (opcional)"/></label>{createError && <div className="inline-alert" role="alert">{createError}</div>}<div className="soc-case-dialog-actions"><button type="button" className="button button-secondary" disabled={creating} onClick={() => setCreateAlert(null)}>Cancelar</button><button className="button button-primary" disabled={creating || !createSeverity}>{creating ? "Abrindo…" : "Criar e vincular"}</button></div></form></section></div>}
  </section>;
}
