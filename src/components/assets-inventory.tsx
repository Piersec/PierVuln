"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { visibleText } from "@/src/lib/visible-text";

type AssetStatus = "active" | "disconnected" | "never_connected" | "pending" | "unknown";
type Asset = {
  tenant_id: string;
  connection_id: string;
  agent_id: string;
  agent_name: string;
  ip_address: string | null;
  host_os: string | null;
  agent_groups: string[];
  status: AssetStatus;
  registered_at: string | null;
  last_keep_alive_at: string | null;
  updated_at: string;
};
type SortField = "agent_id" | "agent_name" | "status" | "last_keep_alive_at";
const pageSize = 50;
const statusLabels: Record<AssetStatus, string> = {
  active: "Ativo",
  disconnected: "Desconectado",
  never_connected: "Nunca conectado",
  pending: "Pendente",
  unknown: "Desconhecido",
};
const date = (value: string | null) => value
  ? new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo" }).format(new Date(value))
  : "Nunca";
const assetKey = (asset: Asset) => `${asset.tenant_id}:${asset.connection_id}:${asset.agent_id}`;
const classificationKey = (tenantId: string, agentKey: string) => `${tenantId}:${agentKey}`;

export function AssetsInventory({ client, companyId, revision, editableTenantIds, isInternal }: {
  client: SupabaseClient;
  companyId: string;
  revision: number;
  editableTenantIds: string[];
  isInternal: boolean;
}) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [groupInput, setGroupInput] = useState("");
  const [group, setGroup] = useState("");
  const [status, setStatus] = useState<"" | AssetStatus>("");
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const [resultCount, setResultCount] = useState(0);
  const [activeTotal, setActiveTotal] = useState(0);
  const [disconnectedTotal, setDisconnectedTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [saveError, setSaveError] = useState("");
  const [criticalByKey, setCriticalByKey] = useState<Record<string, boolean>>({});
  const [savingCriticalKey, setSavingCriticalKey] = useState("");
  const [sort, setSort] = useState<{ field: SortField; ascending: boolean }>({ field: "agent_name", ascending: true });
  const activeRequest = useRef<AbortController | null>(null);

  const load = useCallback(async (silent = false) => {
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    const { signal } = controller;
    if (!silent) {
      setLoading(true);
      setRefreshing(true);
    }
    setError("");

    const safeSearch = search.trim().replace(/[^\p{L}\p{N}_.:/ -]/gu, "").slice(0, 80);
    const safeGroup = group.trim().slice(0, 128);
    const createCountQuery = (state?: AssetStatus) => {
      let query = client.from("asset_agents").select("agent_id", { count: "exact", head: true });
      if (companyId) query = query.eq("tenant_id", companyId);
      if (state) query = query.eq("status", state);
      return query.abortSignal(signal);
    };

    try {
      let pageQuery = client.from("asset_agents")
        .select("tenant_id,connection_id,agent_id,agent_name,ip_address,host_os,agent_groups,status,registered_at,last_keep_alive_at,updated_at", { count: "exact" });
      if (companyId) pageQuery = pageQuery.eq("tenant_id", companyId);
      if (safeSearch) pageQuery = pageQuery.or(`agent_id.ilike.%${safeSearch}%,agent_name.ilike.%${safeSearch}%,ip_address.ilike.%${safeSearch}%,host_os.ilike.%${safeSearch}%`);
      if (safeGroup) pageQuery = pageQuery.contains("agent_groups", [safeGroup]);
      if (status) pageQuery = pageQuery.eq("status", status);
      pageQuery = pageQuery.order(sort.field, { ascending: sort.ascending, nullsFirst: false })
        .range(page * pageSize, (page + 1) * pageSize - 1).abortSignal(signal);

      const [pageResult, totalResult, activeResult, disconnectedResult] = await Promise.all([
        pageQuery,
        createCountQuery(),
        createCountQuery("active"),
        createCountQuery("disconnected"),
      ]);
      if (signal.aborted) return;
      const queryError = pageResult.error || totalResult.error || activeResult.error || disconnectedResult.error;
      if (queryError) throw queryError;

      const nextAssets = (pageResult.data ?? []) as Asset[];
      const nextTotal = pageResult.count ?? 0;
      if (page > 0 && nextAssets.length === 0 && nextTotal > 0 && page * pageSize >= nextTotal) {
        setPage(Math.max(0, Math.ceil(nextTotal / pageSize) - 1));
        return;
      }

      const tenantIds = [...new Set(nextAssets.map((asset) => asset.tenant_id))];
      const agentKeys = [...new Set(nextAssets.map((asset) => asset.agent_id || asset.agent_name))];
      let nextCriticalByKey: Record<string, boolean> = {};
      if (tenantIds.length && agentKeys.length) {
        const { data: classifications, error: classificationError } = await client.from("asset_classifications")
          .select("tenant_id,agent_key,is_critical").in("tenant_id", tenantIds).in("agent_key", agentKeys).abortSignal(signal);
        if (signal.aborted) return;
        if (classificationError) throw classificationError;
        nextCriticalByKey = Object.fromEntries((classifications ?? []).map((row) => [
          classificationKey(row.tenant_id, row.agent_key), row.is_critical,
        ]));
      }

      setAssets(nextAssets);
      setTotal(totalResult.count ?? 0);
      setResultCount(nextTotal);
      setActiveTotal(activeResult.count ?? 0);
      setDisconnectedTotal(disconnectedResult.count ?? 0);
      setCriticalByKey(nextCriticalByKey);
    } catch {
      if (!signal.aborted) setError("Não foi possível carregar os ativos desta empresa. Atualize a página ou confira o acesso à empresa.");
    } finally {
      if (!signal.aborted) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, [client, companyId, group, page, search, sort, status]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearch(searchInput.trim());
      setGroup(groupInput.trim());
    }, 280);
    return () => window.clearTimeout(timer);
  }, [groupInput, searchInput]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load(true);
    }, 30_000);
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") void load(true);
    };
    window.addEventListener("focus", refreshWhenVisible);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", refreshWhenVisible);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
      activeRequest.current?.abort();
    };
  }, [load, revision]);

  const filteredCount = resultCount;
  const otherTotal = Math.max(0, total - activeTotal - disconnectedTotal);
  const totalPages = Math.max(1, Math.ceil((filteredCount ?? 0) / pageSize));
  const rangeStart = assets.length ? page * pageSize + 1 : 0;
  const rangeEnd = page * pageSize + assets.length;
  const canEdit = useCallback((tenantId: string) => isInternal || editableTenantIds.includes(tenantId), [editableTenantIds, isInternal]);
  const visibleAssetCount = useMemo(() => assets.length.toLocaleString("pt-BR"), [assets.length]);

  function changeSort(field: SortField) {
    setSort((current) => ({ field, ascending: current.field === field ? !current.ascending : true }));
    setPage(0);
  }

  async function setCritical(asset: Asset, nextValue: boolean) {
    if (!canEdit(asset.tenant_id) || savingCriticalKey) return;
    const agentKey = asset.agent_id || asset.agent_name;
    const key = classificationKey(asset.tenant_id, agentKey);
    const previousValue = criticalByKey[key] ?? false;
    setCriticalByKey((current) => ({ ...current, [key]: nextValue }));
    setSavingCriticalKey(key);
    setSaveError("");
    try {
      const { error: updateError } = await client.from("asset_classifications").upsert({
        tenant_id: asset.tenant_id,
        agent_key: agentKey,
        is_critical: nextValue,
      }, { onConflict: "tenant_id,agent_key" });
      if (updateError) throw updateError;
    } catch {
      setCriticalByKey((current) => ({ ...current, [key]: previousValue }));
      setSaveError("Não foi possível salvar a classificação deste ativo. Confira sua permissão para a empresa.");
    } finally {
      setSavingCriticalKey("");
    }
  }

  function clearFilters() {
    setSearchInput("");
    setSearch("");
    setGroupInput("");
    setGroup("");
    setStatus("");
    setPage(0);
  }

  const sortText = (field: SortField, label: string) => `${label} ${sort.field === field ? sort.ascending ? "↑" : "↓" : "↕"}`;
  const hasFilters = Boolean(searchInput || groupInput || status);

  return <section className="assets-page" aria-busy={loading}>
    <div className="page-heading">
      <div><h1>Ativos</h1><p>Inventário de ativos registrados pela API de gerenciamento.</p></div>
      <span className="result-count">{loading && !total ? "Carregando ativos" : `${total.toLocaleString("pt-BR")} ativos`}</span>
    </div>

    <dl className="assets-summary" aria-label="Resumo dos ativos na empresa selecionada">
      <div><dt>Total de ativos</dt><dd>{loading && !total ? "..." : total.toLocaleString("pt-BR")}</dd></div>
      <div><dt>Conectados</dt><dd>{loading && !total ? "..." : activeTotal.toLocaleString("pt-BR")}</dd></div>
      <div><dt>Desconectados</dt><dd>{loading && !total ? "..." : disconnectedTotal.toLocaleString("pt-BR")}</dd></div>
      {otherTotal > 0 && <div><dt>Outros estados</dt><dd>{otherTotal.toLocaleString("pt-BR")}</dd></div>}
    </dl>

    <div className="assets-toolbar">
      <label className="assets-search"><span>Buscar</span><input type="search" placeholder="Nome, ID, IP ou sistema operacional" value={searchInput} onChange={(event) => { setSearchInput(event.target.value); setPage(0); }} /></label>
      <label><span>Estado</span><select value={status} onChange={(event) => { setStatus(event.target.value as "" | AssetStatus); setPage(0); }}>
        <option value="">Todos os estados</option>
        {(Object.keys(statusLabels) as AssetStatus[]).map((value) => <option key={value} value={value}>{statusLabels[value]}</option>)}
      </select></label>
      <label><span>Grupo</span><input type="search" placeholder="Nome exato do grupo" value={groupInput} onChange={(event) => { setGroupInput(event.target.value); setPage(0); }} /></label>
      <button className="button button-secondary assets-refresh" type="button" disabled={refreshing} onClick={() => void load()}>{refreshing ? "Atualizando..." : "Atualizar"}</button>
      {hasFilters && <button className="assets-clear" type="button" onClick={clearFilters}>Limpar filtros</button>}
    </div>
    <p className="assets-live-note">A lista atualiza a cada 30 segundos enquanto esta página está aberta. Exibindo {visibleAssetCount} nesta página.</p>
    {error && <p className="inline-alert" role="alert">{error}</p>}
    {saveError && <p className="inline-alert" role="alert">{saveError}</p>}

    <div className="assets-table-scroll" role="region" aria-label="Tabela de ativos. Em telas estreitas, deslize horizontalmente para ver todas as colunas." tabIndex={0}>
      <table className="assets-table">
        <caption className="sr-only">Ativos recebidos da API de gerenciamento, com conectividade, grupos e classificação crítica.</caption>
        <thead><tr>
          <th scope="col"><button className="case-sort" type="button" onClick={() => changeSort("agent_id")} aria-label={`Ordenar por ID. ${sortText("agent_id", "ID")}`}>{sortText("agent_id", "ID")}</button></th>
          <th scope="col"><button className="case-sort" type="button" onClick={() => changeSort("agent_name")} aria-label={`Ordenar por ativo. ${sortText("agent_name", "Ativo")}`}>{sortText("agent_name", "Ativo")}</button></th>
          <th scope="col">IP</th><th scope="col">Sistema</th><th scope="col">Grupos</th>
          <th scope="col">Cadastrado em</th>
          <th scope="col"><button className="case-sort" type="button" onClick={() => changeSort("last_keep_alive_at")} aria-label={`Ordenar por último sinal. ${sortText("last_keep_alive_at", "Último sinal")}`}>{sortText("last_keep_alive_at", "Último sinal")}</button></th>
          <th scope="col"><button className="case-sort" type="button" onClick={() => changeSort("status")} aria-label={`Ordenar por estado. ${sortText("status", "Estado")}`}>{sortText("status", "Estado")}</button></th>
          <th scope="col">Ativo crítico</th>
        </tr></thead>
        <tbody>
          {loading && !assets.length ? <tr><td className="assets-table-message" colSpan={9} role="status">Carregando ativos da empresa...</td></tr>
            : assets.length ? assets.map((asset) => {
              const key = assetKey(asset);
              const agentKey = asset.agent_id || asset.agent_name;
              const criticalKey = classificationKey(asset.tenant_id, agentKey);
              const isCritical = criticalByKey[criticalKey] ?? false;
              const editable = canEdit(asset.tenant_id);
              return <tr key={key}>
                <td><code>{visibleText(asset.agent_id)}</code></td>
                <td><strong>{visibleText(asset.agent_name)}</strong></td>
                <td>{visibleText(asset.ip_address || "Não informado")}</td>
                <td>{visibleText(asset.host_os || "Não informado")}</td>
                <td>{asset.agent_groups.length ? <div className="asset-groups">{asset.agent_groups.map((item) => <span key={item}>{visibleText(item)}</span>)}</div> : "Sem grupo"}</td>
                <td>{date(asset.registered_at)}</td>
                <td>{date(asset.last_keep_alive_at)}</td>
                <td><span className={`asset-status asset-status-${asset.status}`}>{statusLabels[asset.status] ?? statusLabels.unknown}</span></td>
                <td>{editable ? <label className="asset-critical-control">
                  <input type="checkbox" checked={isCritical} disabled={Boolean(savingCriticalKey)} aria-label={`${isCritical ? "Remover classificação de ativo crítico" : "Marcar como ativo crítico"}: ${visibleText(asset.agent_name)}`} onChange={(event) => void setCritical(asset, event.target.checked)} />
                  <span>{savingCriticalKey === criticalKey ? "Salvando..." : isCritical ? "Sim" : "Não"}</span>
                </label> : <span className={isCritical ? "asset-critical-yes" : "asset-critical-no"}>{isCritical ? "Sim" : "Não"}</span>}</td>
              </tr>;
            }) : <tr><td className="assets-table-message" colSpan={9}>
              <div className="assets-empty"><strong>{total === 0 && !hasFilters ? "Nenhum ativo chegou ainda" : "Nenhum ativo corresponde aos filtros"}</strong>
                <span>{total === 0 && !hasFilters ? "Confira as credenciais da API de gerenciamento e se a coleta terminou." : "Altere a busca, o estado ou o grupo para ver outros ativos."}</span>
                {hasFilters && <button className="assets-clear" type="button" onClick={clearFilters}>Limpar filtros</button>}
              </div>
            </td></tr>}
        </tbody>
      </table>
    </div>

    <div className="table-footer assets-footer">
      <span>{filteredCount ? `${rangeStart.toLocaleString("pt-BR")}–${rangeEnd.toLocaleString("pt-BR")} de ${filteredCount.toLocaleString("pt-BR")}` : "Nenhum resultado"}</span>
      <div className="pagination">
        <button className="button button-secondary" type="button" disabled={page === 0 || loading} onClick={() => setPage((value) => value - 1)}>Anterior</button>
        <span>Página {filteredCount ? page + 1 : 0}{filteredCount ? ` de ${totalPages}` : ""}</span>
        <button className="button button-secondary" type="button" disabled={(page + 1) * pageSize >= filteredCount || loading} onClick={() => setPage((value) => value + 1)}>Próxima</button>
      </div>
    </div>
    <p className="assets-data-note">Os campos de identificação, sistema, grupo e conectividade vêm da API de gerenciamento. A contagem de vulnerabilidades por ativo não está disponível nesta coleta.</p>
  </section>;
}
