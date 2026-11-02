"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Activity, MapPin, RefreshCw, ShieldAlert } from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";
import type { SupabaseClient } from "@supabase/supabase-js";
import { visibleText } from "@/src/lib/visible-text";
import { SocDemoThreatMap, type DemoMapRoute } from "@/src/components/soc-demo-threat-map";
import { SocIncidents } from "@/src/components/soc-incidents";

export type SocModulePage = "analytics" | "risk" | "incidents" | "monitoring" | "threat-map" | "fim";
type Period = "24h" | "7d" | "30d" | "year";
type Severity = "critical" | "high" | "medium" | "low" | "informational" | "unknown";
type AlertsSummary = {
  total: number; critical_high: number; unknown: number; sources: number;
  severity: Record<Severity, number>;
  series: { bucket: string; count: number }[];
  top_sources: { id: string; name: string; category: string | null; count: number }[];
  top_rules: { id: string; name: string | null; count: number }[];
  bucket_unit: "hour" | "day"; queried_at: string;
};
type CaseSummary = {
  as_of: string; open: number; analyzing: number; closed_in_period: number;
  assigned: number; unassigned: number; severity: Record<"critical" | "high" | "medium" | "low", number>;
  severity_by_status: Record<"open" | "analyzing" | "closed", Record<"critical" | "high" | "medium" | "low", number>>;
  assigned_severity: Record<"critical" | "high" | "medium" | "low", number>;
  unassigned_severity: Record<"critical" | "high" | "medium" | "low", number>;
  mtta_samples: number; mtta_p50_seconds: number | null; mttr_samples: number; mttr_p50_seconds: number | null;
};
type RiskSummary = {
  queried_at: string; total: number; severity: Record<Severity, number>; hosts_without_identity: number;
  hosts: { agent_id: string | null; agent_name: string | null; total: number; critical: number; high: number; medium: number; low: number; other: number }[];
  firewall_events: number; firewall_severity: Record<"critical" | "high" | "medium" | "low", number>;
};
type FimSummary = {
  queried_at: string; total: number; modified: number; added: number; deleted: number; unknown: number;
  owner_fields_present: number; series: { bucket: string; modified: number; added: number; deleted: number; unknown: number }[];
  top_hosts: { name: string; agent_id: string | null; count: number }[];
  top_rules: { name: string | null; id: string | null; count: number }[];
  top_users: { name: string; agent_id: string | null; agent_name: string | null; count: number }[];
};
type ThreatSummary = {
  queried_at: string; total: number; geolocation_available: boolean; geo_routes?: DemoMapRoute[]; geo_countries?: { name: string; count: number }[]; events_with_mitre: number; events_with_geo: number;
  tactics: { name: string; count: number }[]; techniques: { name: string; count: number }[];
  events: { id: string; occurred_at: string; title: string; source_name: string; agent_name: string | null; src_ip: string | null; dst_ip: string | null; mitre_ids: string[]; mitre_tactics: string[]; mitre_techniques: string[] }[];
};
type CollectionStatus = { queried_at: string; integrations: { name: string; last_received_at: string | null; last_batch_events: number; last_inserted: number; last_duplicates: number; has_error: boolean; revoked: boolean }[] };

const severityLabels: Record<Severity, string> = {
  critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", informational: "Informativo", unknown: "Sem classificação",
};
const severityColors: Record<"critical" | "high" | "medium" | "low", string> = {
  critical: "var(--severity-critical)", high: "var(--severity-high)", medium: "var(--severity-medium)", low: "var(--severity-low)",
};
const severityKeys = ["critical", "high", "medium", "low"] as const;
const caseSeverityLabels = { critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa" } as const;
const periodLabels: Record<Period, string> = { "24h": "Últimas 24 horas", "7d": "Últimos 7 dias", "30d": "Últimos 30 dias", year: "Últimos 12 meses" };

function rangeFor(period: Period, revision: number) {
  const until = new Date(Date.now() + revision * 0);
  const duration = period === "24h" ? 86_400_000 : period === "7d" ? 7 * 86_400_000 : period === "30d" ? 30 * 86_400_000 : 365 * 86_400_000;
  return { since: new Date(until.valueOf() - duration).toISOString(), until: until.toISOString() };
}
function formatCount(value: number | null | undefined) { return Number(value ?? 0).toLocaleString("pt-BR"); }
function formatDate(value: string | null | undefined) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo" }).format(date);
}
function formatDuration(seconds: number | null | undefined) {
  if (seconds == null || !Number.isFinite(Number(seconds))) return "—";
  const totalMinutes = Math.max(0, Math.round(Number(seconds) / 60));
  if (totalMinutes < 60) return `${totalMinutes} min`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return minutes ? `${hours} h ${minutes} min` : `${hours} h`;
}
function seriesLabel(value: string, unit: "hour" | "day") {
  const date = new Date(value);
  return unit === "hour" ? date.toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit", hour: "2-digit" })
    : date.toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit" });
}

type PageData = {
  alerts?: AlertsSummary; cases?: CaseSummary; risk?: RiskSummary; fim?: FimSummary;
  threat?: ThreatSummary; collection?: CollectionStatus;
};

export function SocModulePages({ page, client, companyId, canManage }: {
  page: SocModulePage; client: SupabaseClient; companyId: string; canManage: boolean;
}) {
  const [period, setPeriod] = useState<Period>(page === "incidents" ? "year" : "24h");
  const [revision, setRevision] = useState(0);
  const [data, setData] = useState<PageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const range = useMemo(() => rangeFor(period, revision), [period, revision]);
  const pageTitle: Record<SocModulePage, string> = {
    analytics: "SOC Analytics", risk: "Nível de risco", incidents: "Incidentes",
    monitoring: "Monitoria da coleta", "threat-map": "Mapa de ameaças", fim: "Integridade dos arquivos",
  };
  const load = useCallback(async (signal: AbortSignal) => {
    setLoading(true); setError(""); setData(null);
    const tenant = companyId || null;
    const alertRange = period === "year" ? rangeFor("30d", revision) : range;
    try {
      let next: PageData;
      if (page === "analytics") {
        const [alerts, cases] = await Promise.all([
          client.rpc("get_soc_alert_summary", { p_tenant_id: tenant, p_since: alertRange.since, p_until: alertRange.until }).abortSignal(signal),
          client.rpc("get_soc_case_summary", { p_tenant_id: tenant, p_since: range.since, p_until: range.until }).abortSignal(signal),
        ]);
        if (alerts.error) throw alerts.error;
        if (cases.error) throw cases.error;
        next = { alerts: alerts.data as AlertsSummary, cases: cases.data as CaseSummary };
      } else if (page === "risk") {
        const result = await client.rpc("get_soc_risk_summary", { p_tenant_id: tenant, p_since: range.since, p_until: range.until }).abortSignal(signal);
        if (result.error) throw result.error;
        next = { risk: result.data as RiskSummary };
      } else if (page === "incidents") {
        const result = await client.rpc("get_soc_case_summary", { p_tenant_id: tenant, p_since: range.since, p_until: range.until }).abortSignal(signal);
        if (result.error) throw result.error;
        next = { cases: result.data as CaseSummary };
      } else if (page === "fim") {
        const result = await client.rpc("get_soc_fim_summary", { p_tenant_id: tenant, p_since: range.since, p_until: range.until }).abortSignal(signal);
        if (result.error) throw result.error;
        next = { fim: result.data as FimSummary };
      } else if (page === "threat-map") {
        const result = await client.rpc("get_soc_threat_summary", { p_tenant_id: tenant, p_since: range.since, p_until: range.until }).abortSignal(signal);
        if (result.error) throw result.error;
        next = { threat: result.data as ThreatSummary };
      } else {
        const result = companyId
          ? await client.rpc("get_soc_collection_status", { p_tenant_id: companyId }).abortSignal(signal)
          : { data: null, error: new Error("Selecione uma empresa para consultar a integração.") };
        if (result.error) throw result.error;
        next = { collection: result.data as CollectionStatus };
      }
      if (!signal.aborted) setData(next);
    } catch {
      if (!signal.aborted) setError(page === "monitoring" ? "Não foi possível consultar o recebimento da integração." : "Não foi possível atualizar os dados desta página.");
    } finally { if (!signal.aborted) setLoading(false); }
  }, [client, companyId, page, period, range, revision]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const periods: Period[] = page === "incidents" ? ["24h", "7d", "30d", "year"] : ["24h", "7d", "30d"];
  return <section className="soc-dashboard soc-module-page">
    <div className="page-heading soc-dashboard-heading">
      <div><span className="page-kicker">CENTRO DE OPERAÇÕES</span><h1>{pageTitle[page]}</h1><p>{companyId ? "Dados da empresa selecionada." : "Dados das empresas disponíveis para sua conta."}</p></div>
      <div className="soc-dashboard-actions"><label className="sr-only" htmlFor="soc-module-period">Período</label><select id="soc-module-period" value={period} onChange={(event) => setPeriod(event.target.value as Period)}>{periods.map((value) => <option key={value} value={value}>{periodLabels[value]}</option>)}</select><button className="button button-secondary" disabled={loading} onClick={() => setRevision((value) => value + 1)}><RefreshCw size={15} aria-hidden="true" />{loading ? "Atualizando…" : "Atualizar"}</button></div>
    </div>
    {error && <div className="inline-alert" role="alert">{error}<button className="button button-secondary" onClick={() => setRevision((value) => value + 1)}>Tentar novamente</button></div>}
    {!data && loading && <div className="soc-module-loading" aria-live="polite"><div className="soc-chart-loading"/><div className="soc-chart-loading"/><div className="soc-chart-loading"/></div>}
    {data && page === "analytics" && data.alerts && data.cases && <SocAnalytics data={data} period={period} />}
    {data && page === "risk" && data.risk && <RiskLevel data={data.risk} />}
    {data && page === "incidents" && data.cases && <SocIncidents client={client} companyId={companyId} canManage={canManage} summary={data.cases} since={range.since} until={range.until} onChanged={() => setRevision((value) => value + 1)} />}
    {data && page === "fim" && data.fim && <FileIntegrity data={data.fim} />}
    {data && page === "threat-map" && data.threat && <ThreatMap data={data.threat} />}
    {data && page === "monitoring" && data.collection && <CollectionMonitor data={data.collection} canManage={canManage} />}
  </section>;
}

function Metric({ title, value, note, tone }: { title: string; value: string; note: string; tone?: string }) {
  return <article className={`soc-kpi${tone ? ` ${tone}` : ""}`}><span>{title}</span><strong>{value}</strong><small>{note}</small></article>;
}
function Panel({ title, note, children, className = "" }: { title: string; note?: string; children: React.ReactNode; className?: string }) {
  return <article className={`panel soc-panel ${className}`}><header><div><h2>{title}</h2>{note && <p>{note}</p>}</div></header>{children}</article>;
}
function Empty({ children }: { children: React.ReactNode }) { return <div className="soc-panel-empty">{children}</div>; }
function SeverityRows({ values }: { values: Record<string, number> }) {
  return <div className="soc-severity-list">{severityKeys.map((key) => <div className={`soc-severity-row severity-${key}`} key={key}><span><i aria-hidden="true"/>{caseSeverityLabels[key]}</span><strong>{formatCount(values[key])}</strong></div>)}</div>;
}
function ChartTooltip() { return <Tooltip contentStyle={{ background: "var(--surface-raised)", border: "1px solid var(--line)", borderRadius: 10, color: "var(--ink)" }} labelStyle={{ color: "var(--muted-strong)" }} />; }

function SocAnalytics({ data, period }: { data: PageData; period: Period }) {
  const alerts = data.alerts!; const cases = data.cases!;
  const series = alerts.series.map((item) => ({ ...item, label: seriesLabel(item.bucket, alerts.bucket_unit) }));
  const opened = cases.open + cases.analyzing;
  const historyData = severityKeys.map((key) => ({ name: caseSeverityLabels[key], value: cases.severity[key], fill: severityColors[key] }));
  return <>
    <div className="soc-kpis soc-kpis-four">
      <Metric title="Tempo até o primeiro alerta" value="—" note="Não instrumentado: falta horário confiável do evento de origem." />
      <Metric title="Tempo até atendimento (p50)" value={formatDuration(cases.mtta_p50_seconds)} note={`Casos reconhecidos · N=${formatCount(cases.mtta_samples)}`} />
      <Metric title="Tempo até encerramento (p50)" value={formatDuration(cases.mttr_p50_seconds)} note={`Casos encerrados no período · N=${formatCount(cases.mttr_samples)}`} />
      <Metric title="Incidentes ativos" value={formatCount(opened)} note={`${formatCount(cases.open)} abertos · ${formatCount(cases.analyzing)} em análise`} tone="soc-kpi-critical" />
    </div>
    <div className="soc-analytics-grid soc-analytics-feature-grid">
      <Panel title="Alertas por gravidade" note={`${formatCount(alerts.total)} eventos distintos · ${periodLabels[period]}`} className="soc-severity-panel"><SeverityRows values={alerts.severity}/><p className="soc-data-note">Sem classificação: {formatCount(alerts.unknown)}. A origem e a severidade técnica não confirmam incidente.</p></Panel>
      <Panel title="Histórico de incidentes" note={`${formatCount(opened)} ativos no momento`}>
        <div className="soc-donut-wrap"><Donut values={historyData} center={formatCount(opened)} label="ativos"/><div className="soc-donut-legend">{historyData.map((item) => <span key={item.name}><i style={{ background: item.fill }}/>{item.name}<b>{formatCount(item.value)}</b></span>)}</div></div>
      </Panel>
      <Panel title="Volume de alertas" note={`Série por ${alerts.bucket_unit === "hour" ? "hora" : "dia"} · UTC exibido em São Paulo`} className="soc-panel-wide">
        {alerts.total ? <div className="soc-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={series} margin={{ top: 12, right: 12, bottom: 0, left: -16 }}><defs><linearGradient id="soc-analytics-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--accent)" stopOpacity={.38}/><stop offset="100%" stopColor="var(--accent)" stopOpacity={.02}/></linearGradient></defs><CartesianGrid stroke="var(--line)" strokeDasharray="3 5" vertical={false}/><XAxis dataKey="label" tick={{ fill: "var(--muted)", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "var(--line)" }} minTickGap={24}/><YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11 }} tickLine={false} axisLine={false}/><ChartTooltip/><Area type="monotone" dataKey="count" name="Alertas" stroke="var(--accent)" strokeWidth={2.5} fill="url(#soc-analytics-fill)"/></AreaChart></ResponsiveContainer></div> : <Empty>Nenhum alerta no período.</Empty>}
      </Panel>
      <Panel title="Performance da automação" note="Métricas de IA e escalonamento ainda não têm eventos instrumentados.">
        <div className="soc-instrumented-list">{["Triagem automatizada", "Tempo até sugestão", "Casos escalados"].map((item) => <div key={item}><span>{item}</span><strong>—</strong><small>Não instrumentado</small></div>)}</div>
      </Panel>
    </div>
    <div className="soc-analytics-grid">
      <RankPanel title="Regras mais frequentes" note="Contagem de documentos distintos no período." rows={alerts.top_rules.map((item) => ({ name: item.name || item.id, meta: item.id, count: item.count }))}/>
      <RankPanel title="Fontes com mais alertas" note="Fontes normalizadas pela integração." rows={alerts.top_sources.map((item) => ({ name: item.name, meta: item.category || item.id, count: item.count }))}/>
    </div>
    <div className="soc-page-links"><Link className="button button-secondary" href="/alertas">Abrir fila de alertas <span aria-hidden="true">→</span></Link><Link className="button button-secondary" href="/incidentes">Abrir incidentes <span aria-hidden="true">→</span></Link></div>
  </>;
}

function RiskLevel({ data }: { data: RiskSummary }) {
  const rows = data.hosts;
  const firewall = severityKeys.map((key) => ({ name: caseSeverityLabels[key], value: data.firewall_severity[key], fill: severityColors[key] }));
  return <>
    <div className="soc-risk-heading"><h2>Alertas no período</h2><strong>{formatCount(data.total)}</strong></div>
    <div className="soc-kpis soc-kpis-six"><Metric title="Críticos" value={formatCount(data.severity.critical)} note="Severidade registrada"/><Metric title="Altos" value={formatCount(data.severity.high)} note="Severidade registrada"/><Metric title="Médios" value={formatCount(data.severity.medium)} note="Severidade registrada"/><Metric title="Baixos" value={formatCount(data.severity.low)} note="Severidade registrada"/><Metric title="Informativos" value={formatCount(data.severity.informational)} note="Severidade registrada"/><Metric title="Sem classificação" value={formatCount(data.severity.unknown)} note="Severidade ausente ou não mapeada"/></div>
    <div className="soc-risk-grid">
      <Panel title="Hosts com alertas" note={`${formatCount(rows.length)} hosts no Top 10 · ${formatCount(data.hosts_without_identity)} alertas sem host identificado`} className="soc-risk-hosts">
        {rows.length ? <div className="soc-alert-table-wrap"><table className="soc-alert-table soc-host-table"><thead><tr><th>Host</th><th>Crítico</th><th>Alto</th><th>Médio</th><th>Baixo</th><th>Total</th></tr></thead><tbody>{rows.map((host, index) => <tr key={`${host.agent_id}-${host.agent_name}-${index}`}><td><strong>{visibleText(host.agent_name || "Host sem nome")}</strong><small>{visibleText(host.agent_id || "ID ausente")}</small></td>{severityKeys.map((key) => <td key={key}>{formatCount(host[key])}</td>)}<td><strong>{formatCount(host.total)}</strong></td></tr>)}</tbody></table></div> : <Empty>Nenhum host identificado nesta janela.</Empty>}
      </Panel>
      <div className="soc-risk-side">
        <Panel title="Gravidade em fontes classificadas como firewall" note={`${formatCount(data.firewall_events)} eventos com categoria firewall`}>
          {data.firewall_events ? <div className="soc-donut-wrap"><Donut values={firewall} center={formatCount(data.firewall_events)} label="alertas"/><div className="soc-donut-legend">{firewall.map((item) => <span key={item.name}><i style={{ background: item.fill }}/>{item.name}<b>{formatCount(item.value)}</b></span>)}</div></div> : <Empty>A integração não identificou eventos com a categoria “firewall”.</Empty>}
        </Panel>
        <Panel title="Fila de incidentes" note="Backlog do fluxo interno de atendimento."><Link className="soc-inline-link" href="/incidentes">Ver incidentes e responsáveis <span aria-hidden="true">→</span></Link><p className="soc-data-note">O percentual de risco não aparece até aprovar uma fórmula de cálculo.</p></Panel>
      </div>
    </div>
  </>;
}

function FileIntegrity({ data }: { data: FimSummary }) {
  const series = data.series.map((item) => ({ ...item, label: seriesLabel(item.bucket, data.series.length > 48 ? "day" : "hour") }));
  const actionData = [{ name: "Modificado", value: data.modified, fill: "var(--accent)" }, { name: "Adicionado", value: data.added, fill: "#35c69b" }, { name: "Deletado", value: data.deleted, fill: "var(--danger)" }, ...(data.unknown ? [{ name: "Ação não mapeada", value: data.unknown, fill: "var(--muted)" }] : [])];
  return <>
    <div className="soc-kpis soc-kpis-four"><Metric title="Eventos de integridade" value={formatCount(data.total)} note="Documentos com caminho ou ação de arquivo"/><Metric title="Modificados" value={formatCount(data.modified)} note="Ação reconhecida"/><Metric title="Adicionados" value={formatCount(data.added)} note="Ação reconhecida"/><Metric title="Deletados" value={formatCount(data.deleted)} note={`Não mapeados: ${formatCount(data.unknown)}`}/></div>
    <Panel title="Alertas por tipo de ação ao longo do tempo" note="Ações sem correspondência ficam separadas como não mapeadas." className="soc-panel-wide">
      {data.total ? <div className="soc-chart soc-chart-tall"><ResponsiveContainer width="100%" height="100%"><AreaChart data={series} margin={{ top: 14, right: 14, bottom: 0, left: -14 }}><CartesianGrid stroke="var(--line)" strokeDasharray="3 5" vertical={false}/><XAxis dataKey="label" tick={{ fill: "var(--muted)", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "var(--line)" }} minTickGap={24}/><YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11 }} tickLine={false} axisLine={false}/><ChartTooltip/><Area type="monotone" dataKey="modified" name="Modificado" stackId="fim" stroke="var(--accent)" fill="var(--accent)" fillOpacity={.5}/><Area type="monotone" dataKey="added" name="Adicionado" stackId="fim" stroke="#35c69b" fill="#35c69b" fillOpacity={.5}/><Area type="monotone" dataKey="deleted" name="Deletado" stackId="fim" stroke="var(--danger)" fill="var(--danger)" fillOpacity={.45}/><Area type="monotone" dataKey="unknown" name="Não mapeado" stackId="fim" stroke="var(--muted)" fill="var(--muted)" fillOpacity={.35}/></AreaChart></ResponsiveContainer></div> : <Empty><Activity size={22}/><span>Nenhum evento de arquivo no período.</span></Empty>}
    </Panel>
    <div className="soc-analytics-grid soc-fim-grid">
      <RankPanel title="Top 5 hosts" note="Hosts identificados nos eventos de arquivo." rows={data.top_hosts.map((item) => ({ name: item.name, meta: item.agent_id || "ID ausente", count: item.count }))}/>
      <Panel title="Distribuição de ações" note="Ações normalizadas; registros desconhecidos não entram nas demais fatias."><div className="soc-donut-wrap"><Donut values={actionData} center={formatCount(data.total)} label="eventos"/><div className="soc-donut-legend">{actionData.map((item) => <span key={item.name}><i style={{ background: item.fill }}/>{item.name}<b>{formatCount(item.value)}</b></span>)}</div></div></Panel>
      <RankPanel title="Distribuição de regras" note="Contagem por regra nos eventos de arquivo." rows={data.top_rules.map((item) => ({ name: item.name || "Regra sem descrição", meta: item.id || "ID ausente", count: item.count }))}/>
      <RankPanel title="Top 5 usuários identificados" note="Só mostra change_actor; proprietário do arquivo não é tratado como autor." rows={data.top_users.map((item) => ({ name: item.name, meta: [item.agent_id, item.agent_name].filter(Boolean).join(" · ") || "Host sem identificação", count: item.count }))}/>
    </div>
    {data.owner_fields_present > 0 && <p className="soc-data-note">{formatCount(data.owner_fields_present)} registros contêm proprietário do arquivo. Esse campo não prova quem fez a alteração.</p>}
  </>;
}

function ThreatMap({ data }: { data: ThreatSummary }) {
  return <>
    <div className="soc-map-layout">
      {data.geolocation_available && data.geo_routes?.length ? <SocDemoThreatMap routes={data.geo_routes}/> : <div className="soc-map-canvas" role="img" aria-label="Mapa indisponível: a integração não fornece coordenadas geográficas."><MapPin size={28} aria-hidden="true"/><strong>Geolocalização indisponível</strong><span>A integração atual não envia país nem coordenadas. IPs privados não serão tratados como origem de ataque.</span></div>}
      <div className="soc-map-panels">
        {Boolean(data.geo_countries?.length) && <RankPanel title="Países de origem · Simulação" note="Contagem de alertas com coordenadas fictícias no período selecionado." rows={data.geo_countries!.map((item) => ({ name: item.name, meta: "Origem fictícia", count: item.count }))}/>}
        <RankPanel title="Táticas identificadas" note="Alertas distintos com tática informada." rows={data.tactics.map((item) => ({ name: item.name, meta: "ATT&CK", count: item.count }))}/>
        <RankPanel title="Técnicas identificadas" note="Alertas distintos com técnica informada." rows={data.techniques.map((item) => ({ name: item.name, meta: "ATT&CK", count: item.count }))}/>
      </div>
    </div>
    <Panel title="Alertas recentes" note={`Últimos ${formatCount(data.events.length)} eventos · ${formatCount(data.events_with_mitre)} de ${formatCount(data.total)} alertas têm dados ATT&CK`}>
      {data.events.length ? <div className="soc-alert-table-wrap"><table className="soc-alert-table"><thead><tr><th>Data</th><th>Alerta</th><th>Tática / técnica</th><th>Host</th><th>Origem</th><th>Destino</th></tr></thead><tbody>{data.events.map((event) => <tr key={event.id}><td>{formatDate(event.occurred_at)}</td><td><strong>{visibleText(event.title)}</strong><small>{visibleText(event.source_name)}</small></td><td>{visibleText([...event.mitre_tactics, ...event.mitre_techniques].join(" · ") || "Não informado")}</td><td>{visibleText(event.agent_name || "—")}</td><td>{visibleText(event.src_ip || "—")}</td><td>{visibleText(event.dst_ip || "—")}</td></tr>)}</tbody></table></div> : <Empty>Nenhum alerta no período.</Empty>}
    </Panel>
  </>;
}

function CollectionMonitor({ data, canManage }: { data: CollectionStatus; canManage: boolean }) {
  const active = data.integrations.filter((item) => !item.revoked);
  return <>
    <div className="soc-not-instrumented"><ShieldAlert size={22} aria-hidden="true"/><div><strong>Volume em GB e eventos descartados não estão instrumentados.</strong><p>Esta tela mostra recebimentos confirmados pela integração e a idade do último envio. Ausência de alertas não prova falha na fonte.</p></div></div>
    <div className="soc-kpis soc-kpis-four"><Metric title="Integrações ativas" value={formatCount(active.length)} note="Credenciais de recebimento ativas"/><Metric title="Último lote recebido" value={formatDate(active.map((item) => item.last_received_at).filter(Boolean).sort().at(-1))} note="Horário confirmado pelo servidor"/><Metric title="Eventos no último lote" value={formatCount(active.reduce((sum, item) => sum + item.last_batch_events, 0))} note="Não representa taxa por segundo"/><Metric title="Duplicatas no último lote" value={formatCount(active.reduce((sum, item) => sum + item.last_duplicates, 0))} note="Reenvios deduplicados pelo identificador"/></div>
    <Panel title="Recebimento por integração" note="Sinal do último POST aceito, não estado de saúde dos coletores da origem.">
      {data.integrations.length ? <div className="soc-alert-table-wrap"><table className="soc-alert-table"><thead><tr><th>Integração</th><th>Último recebimento</th><th>Eventos</th><th>Inseridos</th><th>Duplicatas</th><th>Estado</th></tr></thead><tbody>{data.integrations.map((item) => <tr key={item.name}><td><strong>{visibleText(item.name)}</strong></td><td>{formatDate(item.last_received_at)}</td><td>{formatCount(item.last_batch_events)}</td><td>{formatCount(item.last_inserted)}</td><td>{formatCount(item.last_duplicates)}</td><td><span className={`soc-status-pill${item.has_error ? " is-error" : item.revoked ? " is-muted" : item.last_received_at ? " is-ok" : " is-muted"}`}>{item.has_error ? "Falha registrada" : item.revoked ? "Revogada" : item.last_received_at ? "Recebimento confirmado" : "Aguardando primeiro lote"}</span></td></tr>)}</tbody></table></div> : <Empty>Nenhuma integração cadastrada para esta empresa.</Empty>}
    </Panel>
    {canManage && <Link className="button button-secondary" href="/admin/integrations">Gerenciar integração de alertas <span aria-hidden="true">→</span></Link>}
  </>;
}

function Donut({ values, center, label }: { values: { name: string; value: number; fill: string }[]; center: string; label: string }) {
  const hasValues = values.some((item) => item.value > 0);
  const data = hasValues ? values.filter((item) => item.value > 0) : [{ name: "Sem dados", value: 1, fill: "var(--surface-raised)" }];
  return <div className="soc-donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius="68%" outerRadius="88%" stroke="none">{data.map((entry, index) => <Cell key={`${entry.name}-${index}`} fill={entry.fill}/>)}</Pie><ChartTooltip/></PieChart></ResponsiveContainer><div><strong>{center}</strong><span>{label}</span></div></div>;
}
function RankPanel({ title, note, rows }: { title: string; note: string; rows: { name: string; meta: string; count: number }[] }) {
  return <Panel title={title} note={note}>{rows.length ? <ol className="soc-ranking-list">{rows.map((item, index) => <li key={`${item.meta}-${index}`}><span><strong>{visibleText(item.name)}</strong><small>{visibleText(item.meta)}</small></span><b>{formatCount(item.count)}</b></li>)}</ol> : <Empty>Sem dados identificáveis neste período.</Empty>}</Panel>;
}
