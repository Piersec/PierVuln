"use client";

import { useCallback, useEffect, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { visibleText } from "@/src/lib/visible-text";

type Slice = { name: string; count: number; detail?: string };
type Summary = { statuses: Slice[]; systems: Slice[]; critical_assets: Slice[] };
const palette = ["#55b49c", "#649bc4", "#9373bb", "#d25d89", "#ffcf73"];
const statusPalette = ["#00877e", "#d13b2c", "#ffcc00", "#8a919c"];
const statusLabels: Record<string, string> = { active: "Ativo", disconnected: "Desconectado", pending: "Pendente", never_connected: "Nunca conectado", unknown: "Desconhecido" };

function DonutCard({ title, note, slices, loading, colors = palette }: { title: string; note: string; slices: Slice[]; loading: boolean; colors?: string[] }) {
  const total = slices.reduce((sum, slice) => sum + slice.count, 0);
  let offset = 0;
  return <section className="asset-chart-card" aria-label={title}>
    <h2>{title}</h2>
    <div className="asset-chart-body">
      <svg viewBox="0 0 120 120" className="asset-chart-ring" role="img" aria-label={`${title}: ${loading ? "carregando" : total.toLocaleString("pt-BR") + " ativos"}`}>
        <circle cx="60" cy="60" r="46" fill="none" stroke="var(--line)" strokeWidth="13" />
        {slices.map((slice, index) => {
          const size = total ? slice.count / total * 100 : 0;
          const start = offset;
          offset += size;
          return size > 0 && <circle key={`${slice.name}:${index}`} cx="60" cy="60" r="46" fill="none" stroke={colors[index % colors.length]} strokeWidth="13" pathLength="100" strokeDasharray={`${size} ${100 - size}`} strokeDashoffset={-start} transform="rotate(-90 60 60)"><title>{visibleText(slice.name)}: {slice.count}</title></circle>;
        })}
        <text x="60" y="59" textAnchor="middle" className="asset-chart-total">{loading ? "…" : total.toLocaleString("pt-BR")}</text>
        <text x="60" y="73" textAnchor="middle" className="asset-chart-unit">ativos</text>
      </svg>
      <ul>{slices.map((slice, index) => <li key={`${slice.name}:${index}`}><i style={{ background: colors[index % colors.length] }} aria-hidden="true" /><span>{visibleText(slice.name)}{slice.detail && <small>{slice.detail}</small>}</span><strong>{slice.count.toLocaleString("pt-BR")}</strong></li>)}</ul>
      {!loading && !slices.length && <p className="asset-chart-empty">Nenhum ativo nesta seleção.</p>}
    </div>
    <p>{note}</p>
  </section>;
}

export function AssetSummaryCharts({ client, companyId, revision }: { client: SupabaseClient; companyId: string; revision: number }) {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const refresh = useCallback(async (signal: AbortSignal) => {
    try {
      const result = await client.rpc("get_asset_inventory_charts", { p_company_id: companyId || null }).abortSignal(signal);
      if (signal.aborted) return;
      if (result.error) throw result.error;
      setError(false);
      setSummary(result.data as Summary);
    } catch {
      if (!signal.aborted) setError(true);
    }
  }, [client, companyId]);
  useEffect(() => { setSummary(null); }, [companyId]);
  useEffect(() => {
    setError(false);
    const controller = new AbortController();
    const update = () => { if (document.visibilityState === "visible") void refresh(controller.signal); };
    update();
    const interval = window.setInterval(update, 30_000);
    return () => { controller.abort(); window.clearInterval(interval); };
  }, [refresh, revision, retry]);
  return <>
    <div className="asset-chart-grid" aria-busy={!summary && !error}>
      <DonutCard colors={statusPalette} title="Ativos por status" note="Todo o inventário da empresa selecionada." slices={summary ? Object.entries(statusLabels).filter(([key]) => key !== "unknown").map(([key, name]) => ({ name, count: summary.statuses.find((item) => item.name === key)?.count ?? 0 })) : []} loading={!summary && !error} />
      <DonutCard title="Top 5 sistemas operacionais" note="Sistemas com mais ativos no inventário." slices={summary?.systems ?? []} loading={!summary && !error} />
      <DonutCard title="Top 5 ativos críticos" note="Marcados como críticos · sem conexão e maior tempo sem sinal primeiro." slices={(summary?.critical_assets ?? []).map((item) => ({ ...item, detail: statusLabels[item.detail ?? ""] ?? item.detail }))} loading={!summary && !error} />
    </div>
    {error && <p className="inline-alert" role="alert">Não foi possível atualizar os gráficos. <button className="button button-secondary" onClick={() => setRetry((value) => value + 1)}>Tentar novamente</button></p>}
  </>;
}
