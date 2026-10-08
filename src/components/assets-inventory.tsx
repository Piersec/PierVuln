"use client";

import { Button, Checkbox, Table } from "@heroui/react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { visibleText } from "@/src/lib/visible-text";

type Asset = {
  tenant_id: string; connection_id: string; agent_key: string; agent_id: string | null;
  agent_name: string | null; host_os: string | null; first_detected_at: string;
  last_seen_at: string; active_vulnerabilities: number;
};
const pageSize = 50;
const date = (value: string | null) => value ? new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo" }).format(new Date(value)) : "—";
const assetKey = (asset: Asset) => `${asset.tenant_id}:${asset.connection_id}:${asset.agent_key}`;

export function AssetsInventory({ client, companyId, revision }: { client: SupabaseClient; companyId: string; revision: number }) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [sort, setSort] = useState<{ field: "agent_id" | "agent_name" | "last_seen_at"; ascending: boolean }>({ field: "agent_id", ascending: true });

  const load = useCallback(async (signal: AbortSignal) => {
    setLoading(true); setError("");
    const term = search.trim().replace(/[^\p{L}\p{N}_ -]/gu, "").slice(0, 80);
    let request = client.from("asset_inventory").select("tenant_id,connection_id,agent_key,agent_id,agent_name,host_os,first_detected_at,last_seen_at,active_vulnerabilities", { count: "exact" });
    if (companyId) request = request.eq("tenant_id", companyId);
    if (term) request = request.or(`agent_id.ilike.%${term}%,agent_name.ilike.%${term}%,host_os.ilike.%${term}%`);
    const { data, count, error: queryError } = await request.order(sort.field, { ascending: sort.ascending }).range(page * pageSize, (page + 1) * pageSize - 1).abortSignal(signal);
    if (signal.aborted) return;
    if (queryError) { setError("Não foi possível carregar os ativos. Tente atualizar a página."); setLoading(false); return; }
    setAssets((data ?? []) as Asset[]); setTotal(count ?? 0); setSelected(new Set()); setLoading(false);
  }, [client, companyId, page, search, sort]);

  useEffect(() => { const controller = new AbortController(); void load(controller.signal); return () => controller.abort(); }, [load, revision]);

  const allSelected = assets.length > 0 && assets.every((asset) => selected.has(assetKey(asset)));
  const selectedCount = useMemo(() => assets.filter((asset) => selected.has(assetKey(asset))).length, [assets, selected]);
  function selectOne(key: string, checked: boolean) {
    setSelected((current) => { const next = new Set(current); if (checked) next.add(key); else next.delete(key); return next; });
  }
  function toggleSort(field: typeof sort.field) {
    setSort((current) => ({ field, ascending: current.field === field ? !current.ascending : true })); setPage(0);
  }

  return <section className="assets-page" aria-busy={loading}>
    <div className="page-heading"><div><span className="page-kicker">INVENTÁRIO / ATIVOS</span><h1>Ativos</h1><p>Agentes identificados nos dados de vulnerabilidade publicados.</p></div><span className="result-count">{total.toLocaleString("pt-BR")} ativos</span></div>
    <div className="assets-toolbar"><label className="sr-only" htmlFor="asset-search">Buscar ativos</label><input id="asset-search" type="search" placeholder="Buscar ID, nome ou sistema operacional" value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} /><span>{selectedCount ? `${selectedCount} selecionado${selectedCount === 1 ? "" : "s"}` : "Selecione ativos na tabela"}</span><Button variant="secondary" onPress={() => void load(new AbortController().signal)}>Atualizar</Button></div>
    {error && <p className="inline-alert" role="alert">{error}</p>}
    <Table className="assets-table" variant="secondary"><Table.ScrollContainer className="table-scroll"><Table.Content aria-label="Ativos identificados">
      <Table.Header><Table.Column><Checkbox variant="secondary" aria-label="Selecionar todos os ativos nesta página" isSelected={allSelected} onChange={(checked) => setSelected(checked ? new Set(assets.map(assetKey)) : new Set())}><Checkbox.Content><Checkbox.Control><Checkbox.Indicator /></Checkbox.Control></Checkbox.Content></Checkbox></Table.Column><Table.Column isRowHeader><button className="case-sort" onClick={() => toggleSort("agent_id")}>ID {sort.field === "agent_id" ? sort.ascending ? "↑" : "↓" : "↕"}</button></Table.Column><Table.Column><button className="case-sort" onClick={() => toggleSort("agent_name")}>Nome {sort.field === "agent_name" ? sort.ascending ? "↑" : "↓" : "↕"}</button></Table.Column><Table.Column>IP</Table.Column><Table.Column>Sistema operacional</Table.Column><Table.Column>Primeira detecção</Table.Column><Table.Column><button className="case-sort" onClick={() => toggleSort("last_seen_at")}>Última leitura {sort.field === "last_seen_at" ? sort.ascending ? "↑" : "↓" : "↕"}</button></Table.Column><Table.Column>Status</Table.Column><Table.Column>Vulnerabilidades ativas</Table.Column></Table.Header>
      <Table.Body>{loading && !assets.length ? <Table.Row id="loading"><Table.Cell> </Table.Cell><Table.Cell>Carregando…</Table.Cell>{Array.from({ length: 7 }, (_, index) => <Table.Cell key={index}> </Table.Cell>)}</Table.Row> : assets.length ? assets.map((asset) => <Table.Row key={assetKey(asset)} id={assetKey(asset)}><Table.Cell><Checkbox variant="secondary" aria-label={`Selecionar ${visibleText(asset.agent_name || asset.agent_id || asset.agent_key)}`} isSelected={selected.has(assetKey(asset))} onChange={(checked) => selectOne(assetKey(asset), checked)}><Checkbox.Content><Checkbox.Control><Checkbox.Indicator /></Checkbox.Control></Checkbox.Content></Checkbox></Table.Cell><Table.Cell>{visibleText(asset.agent_id || "—")}</Table.Cell><Table.Cell><strong>{visibleText(asset.agent_name || asset.agent_key)}</strong></Table.Cell><Table.Cell><span className="asset-unavailable" title="O índice de vulnerabilidades não fornece o IP do agente">Não disponível</span></Table.Cell><Table.Cell>{visibleText(asset.host_os || "Não informado")}</Table.Cell><Table.Cell>{date(asset.first_detected_at)}</Table.Cell><Table.Cell>{date(asset.last_seen_at)}</Table.Cell><Table.Cell><span className="asset-unavailable" title="O índice de vulnerabilidades não informa o status de conexão do agente">Não disponível</span></Table.Cell><Table.Cell>{Number(asset.active_vulnerabilities).toLocaleString("pt-BR")}</Table.Cell></Table.Row>) : <Table.Row id="empty"><Table.Cell> </Table.Cell><Table.Cell>Nenhum ativo encontrado.</Table.Cell>{Array.from({ length: 7 }, (_, index) => <Table.Cell key={index}> </Table.Cell>)}</Table.Row>}</Table.Body>
    </Table.Content></Table.ScrollContainer></Table>
    <div className="table-footer"><span>{total ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, total)} de ${total}` : "Nenhum ativo"}</span><div className="pagination"><Button variant="secondary" isDisabled={page === 0 || loading} onPress={() => setPage((value) => value - 1)}>Anterior</Button><Button variant="secondary" isDisabled={(page + 1) * pageSize >= total || loading} onPress={() => setPage((value) => value + 1)}>Próxima</Button></div></div>
    <p className="assets-data-note">Esta lista vem das vulnerabilidades já publicadas. IP, registro e estado de conexão do agente dependem de uma futura coleta do inventário de agentes do Wazuh.</p>
  </section>;
}
