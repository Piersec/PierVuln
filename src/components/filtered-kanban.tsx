"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { CveKanban, type RemoteKanbanColumn } from "@/src/components/cve-kanban";
import { type KanbanFilters, type KanbanSummary } from "@/src/lib/kanban";
import { visibleText } from "@/src/lib/visible-text";

const stages = ["open", "in_progress", "awaiting_validation", "resolved"];
type Column = RemoteKanbanColumn & { items: KanbanSummary[] };
const blankColumns = () => Object.fromEntries(stages.map((stage) => [stage, { items: [], total: 0, page: 0, loading: false, error: "" }])) as Record<string, Column>;
type Detail = { id: string; workflow_status: string; wazuh_findings: {
  agent_id: string | null; agent_name: string | null; package_name: string | null; package_version: string | null; cvss_base: number | null;
} };

export function FilteredKanban({ client, companyId, accessToken, canManage, companyNames, revision, onWorkflowChange }: {
  client: SupabaseClient; companyId: string; accessToken: string; canManage: boolean;
  companyNames: Record<string, string>; revision: number; onWorkflowChange?: () => void;
}) {
  const [columns, setColumns] = useState(blankColumns);
  const columnsRef = useRef(columns); columnsRef.current = columns;
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<KanbanSummary | null>(null);
  const [details, setDetails] = useState<Detail[]>([]);
  const [detailPage, setDetailPage] = useState(0);
  const [detailTotal, setDetailTotal] = useState(0);
  const [detailLoading, setDetailLoading] = useState(false);
  const [criticalHosts, setCriticalHosts] = useState<Record<string, boolean>>({});
  const dialog = useRef<HTMLDialogElement | null>(null);
  const opener = useRef<HTMLButtonElement | null>(null);
  const requests = useRef(new Map<string, AbortController>());
  const cache = useRef(new Map<string, { savedAt: number; column: Column }>());

  const load = useCallback(async (status: string, filters: KanbanFilters, page: number, force = false) => {
    requests.current.get(status)?.abort();
    if (!Object.values(filters).some(Boolean)) {
      setColumns((current) => ({ ...current, [status]: blankColumns()[status] })); return;
    }
    const controller = new AbortController();
    requests.current.set(status, controller);
    const key = JSON.stringify([companyId, search, status, filters, page, revision]);
    const cached = cache.current.get(key);
    if (!force && cached && Date.now() - cached.savedAt < 5 * 60_000) {
      setColumns((current) => ({ ...current, [status]: cached.column })); return;
    }
    setColumns((current) => ({ ...current, [status]: { items: [], filters, page, total: 0, loading: true, error: "" } }));
    try {
      const response = await fetch("/api/kanban", {
        method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({ companyId, status, filters, page, search }), signal: controller.signal,
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Não foi possível consultar esta coluna.");
      if (controller.signal.aborted) return;
      const column: Column = { items: payload.items, total: payload.total, page: payload.page, filters, loading: false, error: "" };
      if (cache.current.size >= 100) cache.current.clear();
      cache.current.set(key, { savedAt: Date.now(), column });
      setColumns((current) => ({ ...current, [status]: column }));
    } catch (cause) {
      if (!controller.signal.aborted) setColumns((current) => ({ ...current, [status]: { ...current[status], loading: false, error: cause instanceof Error ? cause.message : "Consulta indisponível." } }));
    }
  }, [accessToken, companyId, revision, search]);

  useEffect(() => {
    const timer = setTimeout(() => {
      for (const status of stages) {
        const column = columnsRef.current[status];
        if (column.filters) void load(status, column.filters, 0);
      }
    }, 400);
    const pending = requests.current;
    return () => { clearTimeout(timer); for (const request of pending.values()) request.abort(); };
  }, [load]);

  useEffect(() => {
    if (!selected) return;
    dialog.current?.showModal();
    return () => dialog.current?.close();
  }, [selected?.key]);

  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    setDetailLoading(true); setError(""); setDetails([]);
    void (async () => {
      const { data, error: queryError, count } = await client.from("vulnerability_cases")
        .select("id,workflow_status,wazuh_findings!inner(agent_id,agent_name,package_name,package_version,cvss_base)", { count: "exact" })
        .eq("tenant_id", selected.tenantId).eq("wazuh_findings.vulnerability_id", selected.cve)
        .order("id").range(detailPage * 20, detailPage * 20 + 19).abortSignal(controller.signal);
      if (queryError) throw queryError;
      const rows = (data ?? []) as unknown as Detail[];
      const keys = [...new Set(rows.map((row) => row.wazuh_findings.agent_id || row.wazuh_findings.agent_name).filter((key): key is string => Boolean(key)))];
      const classification = keys.length ? await client.from("asset_classifications").select("agent_key,is_critical")
        .eq("tenant_id", selected.tenantId).in("agent_key", keys).abortSignal(controller.signal) : { data: [], error: null };
      if (classification.error) throw classification.error;
      if (controller.signal.aborted) return;
      setDetails(rows); setDetailTotal(count ?? 0);
      setCriticalHosts(Object.fromEntries((classification.data ?? []).map((row) => [row.agent_key, row.is_critical])));
    })().catch(() => { if (!controller.signal.aborted) setError("Não foi possível consultar os hosts deste CVE."); })
      .finally(() => { if (!controller.signal.aborted) setDetailLoading(false); });
    return () => controller.abort();
  }, [client, detailPage, selected?.key]);

  function refreshColumns() {
    cache.current.clear();
    for (const status of stages) { const column = columnsRef.current[status]; if (column.filters) void load(status, column.filters, column.page, true); }
  }
  async function move(item: KanbanSummary, status: string) {
    if (busy || !canManage) return;
    setBusy(true); setError("");
    try {
      const { data, error: moveError } = await client.rpc("move_kanban_group", { p_company_id: item.tenantId, p_cve: item.cve, p_status: status });
      if (moveError || !data) throw moveError ?? new Error("Nenhum caso ativo foi alterado.");
      refreshColumns(); onWorkflowChange?.();
    } catch { setError("Não foi possível alterar a etapa deste CVE."); }
    finally { setBusy(false); }
  }
  async function markHost(agentKey: string, critical: boolean) {
    if (!selected || busy || !canManage) return;
    setBusy(true); setError("");
    const { error: saveError } = await client.from("asset_classifications").upsert({ tenant_id: selected.tenantId, agent_key: agentKey, is_critical: critical });
    if (saveError) setError("Não foi possível salvar a classificação do host.");
    else { setCriticalHosts((current) => ({ ...current, [agentKey]: critical })); refreshColumns(); }
    setBusy(false);
  }
  function closeDetails() { setSelected(null); requestAnimationFrame(() => opener.current?.focus()); }
  const items = Object.values(columns).flatMap((column) => column.items);
  return <section className="landscape" aria-label="Tratamento por CVE">
    {error && !selected && <p className="landscape-alert" role="alert">{error}</p>}
    <div className="landscape-heading"><div><h2>Tratamento por CVE</h2><p>Aplique os filtros em cada coluna. Cinco CVEs por página, com os detalhes dos hosts disponíveis ao abrir o card.</p></div>
      <input className="board-search" aria-label="Buscar CVE ou host" placeholder="Buscar CVE ou host" maxLength={160} value={search} onChange={(event) => setSearch(event.target.value)} /></div>
    <CveKanban items={items.map((item) => ({ ...item, hosts: new Set<string>(), cases: [] }))} canManage={canManage} busy={busy}
      intelligenceComplete={true} companyNames={companyNames} showCompany={!companyId}
      remote={{ columns, onApply: (status, filters) => { void load(status, filters, 0); }, onPage: (status, page) => { const filters = columns[status].filters; if (filters) void load(status, filters, page); } }}
      onOpen={(key, button) => { const item = items.find((group) => group.key === key); if (item) { opener.current = button; setDetailPage(0); setSelected(item); } }}
      onMove={(key, status) => { const item = items.find((group) => group.key === key); if (item) void move(item, status); }} />
    {selected && <dialog className="cve-dialog" ref={dialog} aria-label={`Tratamento de ${selected.cve}`} onCancel={(event) => { event.preventDefault(); closeDetails(); }}>
      <div className="cve-dialog-heading"><div><h2>{visibleText(selected.cve)}</h2><p>{selected.hostCount} hosts · {selected.caseCount} casos · CVSS {selected.cvss ?? "Indisponível"}</p></div><button className="button button-secondary" onClick={closeDetails}>Fechar</button></div>
      {error && <p className="landscape-alert" role="alert">{error}</p>}
      <div className="cve-actions"><span>Atualizar todos os casos ativos deste CVE</span>{stages.slice(0, 3).map((status) => <button key={status} className="button button-secondary" disabled={!canManage || busy || selected.status === "resolved"} onClick={() => void move(selected, status)}>{status === "open" ? "Reabrir" : status === "in_progress" ? "Em correção" : "Pedir validação"}</button>)}</div>
      <div className="cve-hosts"><h3>Hosts e pacotes</h3><p className="landscape-hint">Marque os hosts críticos para esta empresa. Um CVE atende ao filtro SIM quando afeta pelo menos um host marcado.</p>
        {detailLoading ? <p role="status">Carregando hosts…</p> : <div className="table-scroll"><table><thead><tr><th>Host</th><th>Pacote</th><th>Ativo crítico</th></tr></thead><tbody>{details.map((row) => {
          const finding = row.wazuh_findings; const agentKey = finding.agent_id || finding.agent_name || "";
          return <tr key={row.id}><td>{visibleText(finding.agent_name || finding.agent_id || "Sem identificação")}</td><td>{visibleText([finding.package_name, finding.package_version].filter(Boolean).join(" · "))}</td>
            <td><label><input type="checkbox" aria-label={`Ativo crítico: ${finding.agent_name || agentKey}`} checked={criticalHosts[agentKey] ?? false} disabled={!canManage || busy || !agentKey} onChange={(event) => void markHost(agentKey, event.target.checked)} /> {criticalHosts[agentKey] ? "SIM" : "NÃO"}</label></td></tr>;
        })}</tbody></table></div>}
        <nav className="kanban-pagination" aria-label="Paginação dos hosts"><span>{detailTotal} casos</span><div>
          <button disabled={detailLoading || detailPage === 0} onClick={() => setDetailPage((page) => page - 1)}>Anterior</button><span>{detailPage + 1} / {Math.max(1, Math.ceil(detailTotal / 20))}</span><button disabled={detailLoading || (detailPage + 1) * 20 >= detailTotal} onClick={() => setDetailPage((page) => page + 1)}>Próxima</button>
        </div></nav>
      </div>
    </dialog>}
  </section>;
}
