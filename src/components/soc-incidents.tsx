"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import Link from "next/link";
import { LockKeyhole } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";
import type { SupabaseClient } from "@supabase/supabase-js";
import { visibleText } from "@/src/lib/visible-text";

type Severity = "critical" | "high" | "medium" | "low";
type CaseStatus = "open" | "analyzing" | "closed";
type CaseClassification = "none" | "positive" | "false_positive";
type AlertEvidence = {
  id: string; source_id: string; source_name: string; source_category: string | null; source_vendor: string | null;
  source_product: string | null; source_event_id: string; source_index: string | null; source_document_id: string | null;
  occurred_at: string; severity: string; severity_original: string | null; title: string; message: string | null;
  rule_id: string | null; rule_description: string | null; rule_level: number | null; agent_id: string | null;
  agent_name: string | null; agent_ip: string | null; src_ip: string | null; dst_ip: string | null; src_port: number | null;
  dst_port: number | null; network_protocol: string | null; service: string | null; src_user: string | null;
  dst_user: string | null; source_action: string | null; normalized_action: string | null; mitre_ids: string[];
  mitre_tactics: string[]; mitre_techniques: string[]; file_path: string | null; file_action: string | null;
  file_hash_before: string | null; file_hash_after: string | null; file_owner_after: string | null;
  change_actor: string | null; change_process: string | null;
};
type Incident = {
  id: string; tenant_id: string; title: string; status: CaseStatus; source_severity: string | null;
  case_severity: Severity; classification: CaseClassification; assigned_to: string | null; notes: string;
  created_by: string | null; created_at: string; updated_at: string; first_ack_at: string | null; resolved_at: string | null;
  companies: { name: string } | { name: string }[] | null;
  soc_case_alerts: { alert_id: string; linked_at: string; soc_alerts: AlertEvidence | AlertEvidence[] | null }[];
};
type Person = { user_id: string; display_name: string };
type CaseEvent = { id: number; actor_id: string | null; action: string; changes: Record<string, unknown>; created_at: string };
type Summary = {
  as_of: string; open: number; analyzing: number; closed_in_period: number; assigned: number; unassigned: number;
  severity_by_status: Record<CaseStatus, Record<Severity, number>>;
  assigned_severity: Record<Severity, number>; unassigned_severity: Record<Severity, number>;
  mtta_samples: number; mtta_p50_seconds: number | null; mttr_samples: number; mttr_p50_seconds: number | null;
};

const severityNames: Record<Severity, string> = { critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa" };
const statusNames: Record<CaseStatus, string> = { open: "Aberto", analyzing: "Em análise", closed: "Fechado" };
const classificationNames: Record<CaseClassification, string> = { none: "Nenhum", positive: "Positivo", false_positive: "Falso positivo" };
const severityOrder: Severity[] = ["critical", "high", "medium", "low"];
const severityFill: Record<Severity, string> = { critical: "var(--soc-severity-critical)", high: "var(--soc-severity-high)", medium: "var(--soc-severity-medium)", low: "var(--soc-severity-low)" };
const pageSize = 25;
const n = (value: number) => Number(value ?? 0).toLocaleString("pt-BR");
const date = (value: string | null) => value ? new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo" }).format(new Date(value)) : "—";
function duration(seconds: number | null) {
  if (seconds == null || !Number.isFinite(Number(seconds))) return "—";
  const minutes = Math.max(0, Math.round(Number(seconds) / 60));
  if (minutes < 60) return minutes + " min";
  const hours = Math.floor(minutes / 60); const rest = minutes % 60;
  return rest ? hours + " h " + rest + " min" : hours + " h";
}
function asAlert(value: AlertEvidence | AlertEvidence[] | null) { return Array.isArray(value) ? value[0] ?? null : value; }
function companyName(value: Incident["companies"]) { return Array.isArray(value) ? value[0]?.name : value?.name; }

export function SocIncidents({ client, companyId, canManage, summary, since, until, onChanged }: {
  client: SupabaseClient; companyId: string; canManage: boolean; summary: Summary;
  since: string; until: string; onChanged: () => void;
}) {
  const [rows, setRows] = useState<Incident[]>([]);
  const [people, setPeople] = useState<Person[]>([]);
  const [events, setEvents] = useState<CaseEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [assignment, setAssignment] = useState("");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<"created_at" | "updated_at">("created_at");
  const [expandedId, setExpandedId] = useState("");
  const [eventCaseId, setEventCaseId] = useState("");
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [modalError, setModalError] = useState("");
  const [selected, setSelected] = useState<Incident | null>(null);
  const eventRequest = useRef(0);
  const [form, setForm] = useState({ title: "", status: "open" as CaseStatus, case_severity: "high" as Severity, classification: "none" as CaseClassification, assigned_to: "", notes: "" });

  const load = useCallback(async () => {
    setLoading(true);
    let query = client.from("soc_cases").select("id,tenant_id,title,status,source_severity,case_severity,classification,assigned_to,notes,created_by,created_at,updated_at,first_ack_at,resolved_at,companies(name),soc_case_alerts(alert_id,linked_at,soc_alerts(id,source_id,source_name,source_category,source_vendor,source_product,source_event_id,source_index,source_document_id,occurred_at,severity,severity_original,title,message,rule_id,rule_description,rule_level,agent_id,agent_name,agent_ip,src_ip,dst_ip,src_port,dst_port,network_protocol,service,src_user,dst_user,source_action,normalized_action,mitre_ids,mitre_tactics,mitre_techniques,file_path,file_action,file_hash_before,file_hash_after,file_owner_after,change_actor,change_process))", { count: "exact" })
      .gte("created_at", since).lt("created_at", until)
      .order(sort, { ascending: false }).order("id", { ascending: false }).range(page * pageSize, page * pageSize + pageSize - 1);
    if (companyId) query = query.eq("tenant_id", companyId);
    if (status) query = query.eq("status", status);
    if (severity) query = query.eq("case_severity", severity);
    if (assignment === "assigned") query = query.not("assigned_to", "is", null);
    if (assignment === "unassigned") query = query.is("assigned_to", null);
    const term = search.trim().replace(/[%,()]/g, " ");
    if (term) query = query.ilike("title", "%" + term + "%");
    const { data, count, error: queryError } = await query;
    if (queryError) setError("Não foi possível carregar incidentes deste período. Mantenho a lista anterior; tente atualizar.");
    else { setRows((data ?? []) as unknown as Incident[]); setTotal(count ?? 0); setError(""); }
    setLoading(false);
  }, [assignment, client, companyId, page, search, severity, since, sort, status, until]);

  useEffect(() => { void load(); }, [load, summary.as_of]);
  useEffect(() => {
    let active = true;
    const tenantId = selected?.tenant_id;
    if (!tenantId || !canManage) { setPeople([]); return; }
    void client.from("company_memberships").select("user_id,user_profiles(display_name)").eq("company_id", tenantId).eq("is_active", true)
      .then(({ data }) => {
        if (!active) return;
        setPeople((data ?? []).map((row) => {
          const profile = Array.isArray(row.user_profiles) ? row.user_profiles[0] : row.user_profiles;
          return { user_id: row.user_id, display_name: profile?.display_name || row.user_id.slice(0, 8) };
        }));
      });
    return () => { active = false; };
  }, [canManage, client, selected?.tenant_id]);

  async function loadEvents(caseId: string) {
    const request = ++eventRequest.current;
    setEventCaseId(caseId); setLoadingEvents(true); setEvents([]);
    const { data } = await client.from("soc_case_events").select("id,actor_id,action,changes,created_at").eq("case_id", caseId).order("created_at", { ascending: false }).limit(50);
    if (request === eventRequest.current) { setEvents((data ?? []) as CaseEvent[]); setLoadingEvents(false); }
  }

  function toggleDetails(row: Incident) {
    if (expandedId === row.id) { setExpandedId(""); eventRequest.current += 1; setLoadingEvents(false); return; }
    setExpandedId(row.id);
    void loadEvents(row.id);
  }

  function edit(row: Incident) {
    setSelected(row);
    setModalError("");
    setForm({ title: row.title, status: row.status, case_severity: row.case_severity, classification: row.classification, assigned_to: row.assigned_to ?? "", notes: row.notes ?? "" });
    void loadEvents(row.id);
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || !canManage) return;
    if (form.status === "closed" && form.classification === "none") { setModalError("Escolha Positivo ou Falso positivo antes de fechar."); return; }
    setBusy(true); setModalError("");
    const { error: updateError } = await client.from("soc_cases").update({ title: form.title.trim(), status: form.status, case_severity: form.case_severity, classification: form.classification, assigned_to: form.assigned_to || null, notes: form.notes }).eq("id", selected.id);
    setBusy(false);
    if (updateError) { setModalError("Não foi possível salvar. Confira a permissão e os campos do incidente."); return; }
    setSelected(null); await load(); onChanged();
  }

  function changeFilter<T extends string>(setter: (value: T) => void, value: T) { setter(value); setPage(0); }
  const maxPage = Math.max(1, Math.ceil(total / pageSize));
  const donutCards: { title: string; count: number; values: Record<Severity, number> }[] = [
    { title: "Incidentes abertos", count: summary.open, values: summary.severity_by_status.open },
    { title: "Em análise", count: summary.analyzing, values: summary.severity_by_status.analyzing },
    { title: "Incidentes fechados", count: summary.closed_in_period, values: summary.severity_by_status.closed },
    { title: "Incidentes atribuídos", count: summary.assigned, values: summary.assigned_severity },
    { title: "Incidentes não atribuídos", count: summary.unassigned, values: summary.unassigned_severity },
  ];

  return <>
    <div className="soc-case-donuts" aria-label="Resumo dos incidentes por estado e atribuição">
      {donutCards.map((card) => <CaseDonut key={card.title} {...card}/>)
      }
    </div>
    <div className="soc-case-timing" aria-label="Tempos de atendimento"><span>Atendimento p50 <strong>{duration(summary.mtta_p50_seconds)}</strong><small>N={n(summary.mtta_samples)}</small></span><span>Encerramento p50 <strong>{duration(summary.mttr_p50_seconds)}</strong><small>N={n(summary.mttr_samples)}</small></span></div>
    <section className="panel soc-alert-list-panel soc-incidents-panel">
      <header className="soc-alert-list-heading"><div><h2>Incidentes: nível de detalhe</h2><p>Casos de atendimento filtrados pelo período; eventos e evidências vêm dos alertas vinculados.</p></div><span>{n(total)} registros</span></header>
      <div className="soc-incident-filters">
        <label className="sr-only" htmlFor="soc-incident-search">Buscar incidentes</label><input id="soc-incident-search" type="search" placeholder="Pesquisar incidente…" value={search} onChange={(event) => changeFilter(setSearch, event.target.value)}/>
        <label className="sr-only" htmlFor="soc-incident-status">Status</label><select id="soc-incident-status" value={status} onChange={(event) => changeFilter(setStatus, event.target.value)}><option value="">Todos os status</option>{Object.entries(statusNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
        <label className="sr-only" htmlFor="soc-incident-severity">Severidade</label><select id="soc-incident-severity" value={severity} onChange={(event) => changeFilter(setSeverity, event.target.value)}><option value="">Todas as severidades</option>{Object.entries(severityNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
        <label className="sr-only" htmlFor="soc-incident-assignment">Responsável</label><select id="soc-incident-assignment" value={assignment} onChange={(event) => changeFilter(setAssignment, event.target.value)}><option value="">Qualquer responsável</option><option value="assigned">Com responsável</option><option value="unassigned">Sem responsável</option></select>
        <label className="sr-only" htmlFor="soc-incident-sort">Ordenação</label><select id="soc-incident-sort" value={sort} onChange={(event) => changeFilter(setSort, event.target.value as typeof sort)}><option value="created_at">Mais recentes</option><option value="updated_at">Atualizados recentemente</option></select>
      </div>
      {error && <div className="inline-alert" role="alert">{error}</div>}
      {loading && !rows.length ? <div className="soc-alert-skeletons" aria-label="Carregando incidentes">{Array.from({ length: 5 }, (_, index) => <div className="soc-alert-skeleton" key={index}/>)}</div>
        : !rows.length ? <div className="soc-alert-empty"><strong>Nenhum incidente neste período</strong><p>{search || status || severity || assignment ? "Ajuste os filtros para ampliar a busca." : "Abra um incidente a partir de um alerta para iniciar o atendimento."}</p><Link className="button button-secondary" href={`/alertas?company=${companyId || "all"}`}>Ir para alertas</Link></div>
          : <div className="soc-alert-table-wrap"><table className="soc-alert-table soc-incident-table"><thead><tr><th>ID</th><th>Data</th><th>Descrição</th><th>Severidade</th><th>Status</th><th>Ação</th></tr></thead><tbody>{rows.map((row) => <IncidentRows key={row.id} row={row} expanded={expandedId === row.id} events={eventCaseId === row.id ? events : []} loadingEvents={eventCaseId === row.id && loadingEvents} canManage={canManage} onToggle={() => toggleDetails(row)} onEdit={() => edit(row)} people={people}/>)}</tbody></table></div>}
      <footer className="soc-pagination"><span>Mostrando {total ? page * pageSize + 1 : 0}–{Math.min((page + 1) * pageSize, total)} de {n(total)} incidentes</span><div><button className="button button-secondary" disabled={page === 0 || loading} onClick={() => setPage((value) => Math.max(0, value - 1))}>Anterior</button><button className="button button-secondary" disabled={(page + 1) * pageSize >= total || loading} onClick={() => setPage((value) => value + 1)}>Próxima</button></div></footer>
    </section>
    {selected && <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) setSelected(null); }}><section className="panel soc-case-dialog" role="dialog" aria-modal="true" aria-labelledby="soc-case-dialog-title"><header><div><span className="page-kicker">ATENDIMENTO</span><h2 id="soc-case-dialog-title">Incidente #{selected.id.slice(0, 8)}</h2></div><button className="button button-secondary" type="button" onClick={() => setSelected(null)}>Fechar</button></header><form onSubmit={(event) => void save(event)}><label>Título<input required maxLength={500} value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })}/></label><div className="soc-case-form-grid"><label>Status<select value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value as CaseStatus })}>{Object.entries(statusNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label>Severidade do incidente<select value={form.case_severity} onChange={(event) => setForm({ ...form, case_severity: event.target.value as Severity })}>{Object.entries(severityNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label>Classificação<select value={form.classification} onChange={(event) => setForm({ ...form, classification: event.target.value as CaseClassification })}>{Object.entries(classificationNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label>Analista<select value={form.assigned_to} onChange={(event) => setForm({ ...form, assigned_to: event.target.value })}><option value="">Sem responsável</option>{people.map((person) => <option key={person.user_id} value={person.user_id}>{visibleText(person.display_name)}</option>)}</select></label></div><label>Notas da análise<textarea maxLength={4000} rows={5} placeholder="Registre evidências e decisões da análise." value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })}/></label>{form.status === "closed" && form.classification === "none" && <p className="soc-form-warning">Escolha Positivo ou Falso positivo para fechar.</p>}{modalError && <div className="inline-alert" role="alert">{modalError}</div>}<div className="soc-case-dialog-actions"><button type="button" className="button button-secondary" disabled={busy} onClick={() => setSelected(null)}>Cancelar</button><button className="button button-primary" disabled={busy}>{busy ? "Salvando…" : "Salvar"}</button></div></form><CaseTimeline events={events} loading={loadingEvents}/></section></div>}
  </>;
}

function CaseDonut({ title, count, values }: { title: string; count: number; values: Record<Severity, number> }) {
  const data = severityOrder.map((name) => ({ name, value: Number(values[name] ?? 0), fill: severityFill[name] }));
  const chartData = data.some((item) => item.value > 0) ? data.filter((item) => item.value > 0) : [{ name: "empty", value: 1, fill: "var(--surface-raised)" }];
  const breakdown = data.map((item) => `${severityNames[item.name]} ${n(item.value)}`).join(", ");
  return <article className="panel soc-case-donut-card"><h2>{title}</h2><div className="soc-case-donut" role="img" aria-label={`${title}: ${n(count)} incidentes. ${breakdown}.`}><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={chartData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius="68%" outerRadius="90%" stroke="none">{chartData.map((item) => <Cell key={item.name} fill={item.fill}/>)}</Pie></PieChart></ResponsiveContainer><span><strong>{n(count)}</strong><small>Incidentes</small></span></div></article>;
}

function IncidentRows({ row, expanded, events, loadingEvents, canManage, onToggle, onEdit, people }: {
  row: Incident; expanded: boolean; events: CaseEvent[]; loadingEvents: boolean; canManage: boolean;
  onToggle: () => void; onEdit: () => void; people: Person[];
}) {
  const linked = (row.soc_case_alerts ?? []).map((item) => ({ link: item, alert: asAlert(item.soc_alerts) }));
  const company = companyName(row.companies);
  const owner = people.find((person) => person.user_id === row.assigned_to)?.display_name;
  return <>
    <tr className={expanded ? "soc-incident-row-expanded" : undefined}>
      <td><span className="soc-incident-id" title={row.id}>#{row.id.slice(0, 8)}</span></td>
      <td><time dateTime={row.created_at}>{date(row.created_at)}</time></td>
      <td><strong>{visibleText(row.title)}</strong><small>{linked.length ? `${linked.length} alerta${linked.length === 1 ? "" : "s"} vinculado${linked.length === 1 ? "" : "s"}` : "Sem alerta de origem vinculado"}</small></td>
      <td><span className={`soc-severity-badge severity-${row.case_severity}`}>{severityNames[row.case_severity]}</span>{row.source_severity && row.source_severity !== row.case_severity && <small className="soc-source-priority">Origem: {visibleText(row.source_severity)}</small>}</td>
      <td><span className={`soc-status-pill ${row.status === "closed" ? "is-muted" : row.status === "analyzing" ? "is-ok" : ""}`}>{row.status === "closed" && <LockKeyhole size={13} aria-hidden="true"/>}{statusNames[row.status]}</span></td>
      <td><div className="soc-incident-actions"><button className="button button-secondary soc-case-edit-button" aria-expanded={expanded} onClick={onToggle}>{expanded ? "Recolher −" : "Detalhar +"}</button>{canManage && <button className="button button-secondary soc-case-edit-button" onClick={onEdit}>Editar</button>}</div></td>
    </tr>
    {expanded && <tr className="soc-incident-detail-row"><td colSpan={6}><article className="soc-incident-detail">
      <DetailSection title="Resumo"><DetailField label="Título" value={row.title}/><DetailField label="Prioridade do incidente" value={severityNames[row.case_severity]}/><DetailField label="Severidade da origem" value={sourceSeverity(row.source_severity)}/></DetailSection>
      <DetailSection title="Detecção">{linked.length ? linked.map(({ alert }) => <div className="soc-evidence-block" key={alert?.id ?? "missing-alert"}><DetailField label="Regra" value={alert?.rule_description || alert?.title || "Não informado pela origem"}/><DetailField label="ID da regra" value={alert?.rule_id}/><DetailField label="Horário do evento" value={alert?.occurred_at ? date(alert.occurred_at) : null}/><DetailField label="Nível informado" value={alert?.rule_level == null ? null : String(alert.rule_level)}/></div>) : <DetailField label="Origem" value="Incidente criado sem alerta vinculado."/>}</DetailSection>
      <DetailSection title="Evidências">{linked.length ? linked.map(({ alert }) => <div className="soc-evidence-block" key={alert?.id ?? "missing-evidence"}><DetailField label="Mensagem" value={alert?.message}/><DetailField label="Indicadores" value={[alert?.src_ip && `IP de origem ${alert.src_ip}`, alert?.dst_ip && `IP de destino ${alert.dst_ip}`, alert?.src_user && `Usuário de origem ${alert.src_user}`, alert?.dst_user && `Usuário de destino ${alert.dst_user}`].filter(Boolean).join(" · ")}/><DetailField label="MITRE ATT&CK" value={[...(alert?.mitre_ids ?? []), ...(alert?.mitre_techniques ?? [])].join(" · ")}/><DetailField label="Correlação" value={alert?.rule_id && alert?.src_ip ? "Agrupado por fonte, regra, IP de origem e janela de uma hora." : "Sem campos suficientes para confirmar correlação por campanha."}/></div>) : <p>Sem evidências de origem vinculadas.</p>}</DetailSection>
      <DetailSection title="Impacto"><p>Impacto no ambiente não foi informado pelos dados recebidos.</p></DetailSection>
      <DetailSection title="Informações adicionais">{linked.map(({ alert }) => alert && <div className="soc-evidence-block" key={alert.id}><DetailField label="Fonte" value={alert.source_name}/><DetailField label="Categoria" value={alert.source_category}/><DetailField label="Fabricante / produto" value={[alert.source_vendor, alert.source_product].filter(Boolean).join(" / ")}/><DetailField label="Índice e documento" value={[alert.source_index, alert.source_document_id].filter(Boolean).join(" · ")}/><DetailField label="ID estável do evento" value={alert.source_event_id}/></div>)}</DetailSection>
      <DetailSection title="Classificação"><DetailField label="Decisão do analista" value={classificationNames[row.classification]}/><DetailField label="Táticas" value={linked.flatMap(({ alert }) => alert?.mitre_tactics ?? []).join(" · ")}/><DetailField label="Técnicas" value={linked.flatMap(({ alert }) => alert?.mitre_techniques ?? []).join(" · ")}/></DetailSection>
      <DetailSection title="Escopo afetado">{linked.map(({ alert }) => alert && <div className="soc-evidence-block" key={alert.id}><DetailField label="Host / agente" value={[alert.agent_name, alert.agent_id].filter(Boolean).join(" · ")}/><DetailField label="IP do agente" value={alert.agent_ip}/><DetailField label="IPs" value={[alert.src_ip && `Origem: ${alert.src_ip}`, alert.dst_ip && `Destino: ${alert.dst_ip}`].filter(Boolean).join(" · ")}/><DetailField label="Portas e protocolo" value={[alert.src_port && `Origem ${alert.src_port}`, alert.dst_port && `Destino ${alert.dst_port}`, alert.network_protocol, alert.service].filter(Boolean).join(" · ")}/><DetailField label="Usuários" value={[alert.src_user && `Origem: ${alert.src_user}`, alert.dst_user && `Destino: ${alert.dst_user}`].filter(Boolean).join(" · ")}/><DetailField label="Arquivo" value={alert.file_path}/></div>)}</DetailSection>
      <DetailSection title="Linha do tempo"><CaseTimeline events={events} loading={loadingEvents}/><DetailField label="Abertura" value={date(row.created_at)}/><DetailField label="Primeiro atendimento" value={date(row.first_ack_at)}/><DetailField label="Encerramento" value={date(row.resolved_at)}/>{linked.map(({ link, alert }) => <DetailField key={link.alert_id} label="Evento de origem" value={date(alert?.occurred_at ?? link.linked_at)}/>)}</DetailSection>
      <DetailSection title="Contenção">{linked.some(({ alert }) => alert?.source_action || alert?.normalized_action) ? linked.map(({ alert }) => (alert?.source_action || alert?.normalized_action) && <p key={alert.id}>A origem reportou “{visibleText(alert.normalized_action || alert.source_action)}”. Execução e resultado não foram confirmados.</p>) : <p>Nenhuma ação de contenção foi reportada pela origem.</p>}</DetailSection>
      <DetailSection title="Erradicação"><p>Nenhuma ação de erradicação foi registrada.</p></DetailSection>
      <DetailSection title="Investigação"><p>{row.notes ? visibleText(row.notes) : "Nenhuma nota de investigação registrada."}</p></DetailSection>
      <DetailSection title="Status do incidente"><DetailField label="Status" value={statusNames[row.status]}/><DetailField label="Severidade da origem" value={sourceSeverity(row.source_severity)}/><DetailField label="Classificação" value={classificationNames[row.classification]}/></DetailSection>
      <DetailSection title="Observações"><p>{row.notes ? visibleText(row.notes) : "Nenhuma observação registrada."}</p></DetailSection>
      <DetailSection title="Propriedades"><DetailField label="Empresa" value={company}/><DetailField label="Responsável" value={owner || row.assigned_to}/><DetailField label="Aberto por" value={row.created_by?.slice(0, 8)}/></DetailSection>
      <DetailSection title="Datas"><DetailField label="Abertura" value={date(row.created_at)}/><DetailField label="Fechamento" value={date(row.resolved_at)}/><DetailField label="Última atualização" value={date(row.updated_at)}/></DetailSection>
      <DetailSection title="Classificação registrada"><DetailField label="Classificação" value={classificationNames[row.classification]}/><DetailField label="Severidade mapeada" value={severityNames[row.case_severity]}/><DetailField label="Status" value={statusNames[row.status]}/></DetailSection>
      {linked.length > 0 && <DetailSection title="Arquivos relacionados">{linked.map(({ alert }) => alert && <div className="soc-evidence-block" key={alert.id}><DetailField label="Caminho" value={alert.file_path}/><DetailField label="Ação de arquivo" value={alert.file_action}/><DetailField label="Autor informado" value={alert.change_actor}/><DetailField label="Proprietário após alteração" value={alert.file_owner_after}/><DetailField label="Processo" value={alert.change_process}/><DetailField label="Hashes antes / depois" value={[alert.file_hash_before, alert.file_hash_after].filter(Boolean).join(" / ")}/></div>)}</DetailSection>}
    </article></td></tr>}
  </>;
}

function sourceSeverity(value: string | null) { return value ? visibleText(value) : "Não informada"; }
function DetailSection({ title, children }: { title: string; children: React.ReactNode }) { return <section><h3>{title}</h3>{children}</section>; }
function DetailField({ label, value }: { label: string; value: string | null | undefined }) { return <p className="soc-detail-field"><strong>{label}</strong><span>{value ? visibleText(value) : "Não informado"}</span></p>; }
function CaseTimeline({ events, loading }: { events: CaseEvent[]; loading: boolean }) {
  return <div className="soc-case-timeline">{loading ? <p>Carregando histórico…</p> : events.length ? <ol>{events.map((item) => <li key={item.id}><strong>{item.action === "created" ? "Incidente criado" : item.action === "alert_linked" ? "Alerta vinculado" : item.action === "alert_unlinked" ? "Alerta desvinculado" : "Dados atualizados"}</strong><time>{date(item.created_at)}</time></li>)}</ol> : <p>Sem eventos de histórico.</p>}</div>;
}
