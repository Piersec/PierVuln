"use client";

import { useMemo, useState } from "react";
import { useReducedMotion } from "framer-motion";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Search, Swords } from "lucide-react";
import { adminDate } from "@/src/lib/admin";
import { visibleText } from "@/src/lib/visible-text";
import { AnimatedCounter } from "@/src/components/ui/animated-counter";

export type BattleCompany = {
  id: string; name: string; slug: string; case_count: number; critical_high_count: number;
  in_progress_count: number; corrected_30: number; refreshed_at: string | null; stale: boolean;
};

type ChartMode = "exposure" | "response";
const number = (value: number) => value.toLocaleString("pt-BR");
const score = (company: BattleCompany) => company.case_count ? Math.max(0, 100 * (1 - company.critical_high_count / company.case_count)) : -1;

export function BattleDashboard({ companies, error, onRetry }: { companies: BattleCompany[] | null; error: string; onRetry: () => void }) {
  const reducedMotion = useReducedMotion();
  const [mode, setMode] = useState<ChartMode>("exposure");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const ranked = useMemo(() => [...(companies ?? [])].sort((a, b) => score(b) - score(a) || a.critical_high_count - b.critical_high_count || a.name.localeCompare(b.name, "pt-BR")), [companies]);
  const filtered = ranked.filter((company) => `${visibleText(company.name)} ${company.slug}`.toLocaleLowerCase("pt-BR").includes(query.trim().toLocaleLowerCase("pt-BR")));
  const selected = ranked.find((company) => company.id === selectedId) ?? ranked.find((company) => company.case_count > 0) ?? ranked[0];
  const published = ranked.filter((company) => company.case_count > 0);
  const totalCases = published.reduce((sum, company) => sum + company.case_count, 0);
  const highCases = published.reduce((sum, company) => sum + company.critical_high_count, 0);
  const inProgress = published.reduce((sum, company) => sum + company.in_progress_count, 0);
  const corrected = published.reduce((sum, company) => sum + company.corrected_30, 0);
  const aggregateScore = totalCases ? Math.round(100 * (1 - highCases / totalCases)) : null;
  const chartData = filtered.filter((company) => company.case_count > 0).slice(0, 12).map((company) => ({
    name: visibleText(company.name),
    shortName: visibleText(company.name).length > 18 ? `${visibleText(company.name).slice(0, 17)}…` : visibleText(company.name),
    high: company.critical_high_count,
    other: Math.max(0, company.case_count - company.critical_high_count),
    progress: company.in_progress_count,
    corrected: company.corrected_30,
  }));
  const latest = ranked.reduce<string | null>((value, company) => !company.refreshed_at || (value && value > company.refreshed_at) ? value : company.refreshed_at, null);

  if (error && !companies) return <section className="battle-state panel" role="alert"><Swords size={28} aria-hidden="true" /><h2>Não foi possível carregar a Batalha</h2><p>{error}</p><button className="button button-secondary" onClick={onRetry}>Tentar novamente</button></section>;
  if (!companies) return <section className="battle-state panel" role="status"><span className="battle-loader" aria-hidden="true" /><h2>Carregando Batalha</h2><p>Buscando os resumos publicados das empresas.</p></section>;
  if (!ranked.length) return <section className="battle-state panel"><Swords size={28} aria-hidden="true" /><h2>A classificação ainda está vazia</h2><p>As empresas aparecem aqui após a publicação dos primeiros dados.</p></section>;

  return <div className="battle-dashboard">
    {error && <div className="inline-alert" role="alert">{error} <button className="button button-secondary" onClick={onRetry}>Tentar novamente</button></div>}
    <section className="battle-overview" aria-labelledby="battle-overview-title">
      <div className="battle-overview-main">
        <div className="battle-overview-title"><Swords size={20} aria-hidden="true" /><h2 id="battle-overview-title">Panorama da Batalha</h2></div>
        <div className="battle-score-line"><strong>{aggregateScore === null ? "—" : <AnimatedCounter value={aggregateScore} suffix="%" />}</strong><span>dos casos ativos sem severidade crítica ou alta</span></div>
        <div className="battle-score-track" role="meter" aria-label="Índice consolidado" aria-valuemin={0} aria-valuemax={100} aria-valuenow={aggregateScore ?? undefined} aria-valuetext={aggregateScore === null ? "Sem dados publicados" : undefined}><span style={{ width: `${aggregateScore ?? 0}%` }} /></div>
        <p>Índice calculado pelo volume de casos, não pela média das empresas. {published.length} {published.length === 1 ? "empresa classificada" : "empresas classificadas"}.</p>
      </div>
      <div className="battle-overview-stats" aria-label="Resumo dos casos">
        <div><span>Casos ativos</span><strong><AnimatedCounter value={totalCases} /></strong></div>
        <div><span>Críticos ou altos</span><strong className="battle-danger"><AnimatedCounter value={highCases} /></strong></div>
        <div><span>Em tratamento</span><strong><AnimatedCounter value={inProgress} /></strong></div>
        <div><span>Corrigidos em 30 dias</span><strong className="battle-positive"><AnimatedCounter value={corrected} /></strong></div>
      </div>
    </section>

    <div className="battle-content-grid">
      <section className="battle-chart-panel panel" aria-labelledby="battle-chart-title">
        <div className="battle-panel-head"><div><h2 id="battle-chart-title">Comparação entre empresas</h2><p>{mode === "exposure" ? "Distribuição dos casos ativos por severidade." : "Casos em tratamento e correções nos últimos 30 dias."}</p></div>
          <div className="battle-segmented" role="group" aria-label="Métrica do gráfico"><button type="button" aria-pressed={mode === "exposure"} onClick={() => setMode("exposure")}>Exposição</button><button type="button" aria-pressed={mode === "response"} onClick={() => setMode("response")}>Resposta</button></div>
        </div>
        {chartData.length ? <>
          <div className="battle-chart-legend"><span><i className={mode === "exposure" ? "battle-key-danger" : "battle-key-cyan"} />{mode === "exposure" ? "Críticos ou altos" : "Em tratamento"}</span><span><i className={mode === "exposure" ? "battle-key-muted" : "battle-key-positive"} />{mode === "exposure" ? "Demais severidades" : "Corrigidos em 30 dias"}</span></div>
          <div className="battle-chart" role="img" aria-label={mode === "exposure" ? "Gráfico de casos críticos ou altos e demais casos ativos por empresa" : "Gráfico de casos em tratamento e corrigidos em 30 dias por empresa"} style={{ height: Math.max(240, chartData.length * 58 + 46) }}>
            <ResponsiveContainer width="100%" height="100%"><BarChart data={chartData} layout="vertical" margin={{ top: 8, right: 18, bottom: 4, left: 4 }} barCategoryGap="28%">
              <CartesianGrid stroke="var(--line)" horizontal={false} strokeDasharray="3 5" />
              <XAxis type="number" allowDecimals={false} tick={{ fill: "var(--muted-strong)", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="shortName" width={116} tick={{ fill: "var(--muted-strong)", fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: "var(--surface-raised)", opacity: .55 }} contentStyle={{ background: "var(--surface-raised)", border: "1px solid var(--line-strong)", borderRadius: 10, color: "var(--ink)" }} labelFormatter={(_, payload) => payload?.[0]?.payload?.name ?? ""} formatter={(value, name) => [number(Number(value)), name === "high" ? "Críticos ou altos" : name === "other" ? "Demais severidades" : name === "progress" ? "Em tratamento" : "Corrigidos em 30 dias"]} />
              {mode === "exposure" ? <><Bar dataKey="high" stackId="active" fill="var(--danger)" radius={[0, 0, 0, 0]} isAnimationActive={!reducedMotion} animationDuration={450} /><Bar dataKey="other" stackId="active" fill="var(--accent)" radius={[0, 5, 5, 0]} isAnimationActive={!reducedMotion} animationDuration={450} /></> : <><Bar dataKey="progress" fill="var(--accent)" radius={[0, 5, 5, 0]} isAnimationActive={!reducedMotion} animationDuration={450} /><Bar dataKey="corrected" fill="var(--positive)" radius={[0, 5, 5, 0]} isAnimationActive={!reducedMotion} animationDuration={450} /></>}
            </BarChart></ResponsiveContainer>
          </div>
          {filtered.length > 12 && <p className="battle-chart-note">O gráfico mostra as 12 primeiras empresas da busca. A lista abaixo inclui todas.</p>}
        </> : <p className="battle-chart-empty">Nenhuma empresa com casos publicados corresponde à busca.</p>}
      </section>

      <section className="battle-focus panel" aria-labelledby="battle-focus-title">
        <div className="battle-panel-head"><div><h2 id="battle-focus-title">Em foco</h2><p>Selecione uma empresa na classificação.</p></div></div>
        {selected && <div key={selected.id} className="battle-focus-body">
          <div className="battle-focus-rank">{selected.case_count ? `${ranked.findIndex((company) => company.id === selected.id) + 1}º lugar` : "Sem classificação"}</div>
          <h3>{visibleText(selected.name)}</h3><p className="battle-focus-slug">{selected.slug}</p>
          <div className="battle-focus-score"><strong>{selected.case_count ? <AnimatedCounter value={Math.round(score(selected))} suffix="%" /> : "—"}</strong><span>índice da empresa</span></div>
          <dl><div><dt>Casos ativos</dt><dd><AnimatedCounter value={selected.case_count} /></dd></div><div><dt>Críticos ou altos</dt><dd><AnimatedCounter value={selected.critical_high_count} /></dd></div><div><dt>Em tratamento</dt><dd><AnimatedCounter value={selected.in_progress_count} /></dd></div><div><dt>Corrigidos em 30 dias</dt><dd><AnimatedCounter value={selected.corrected_30} /></dd></div></dl>
          <p className="battle-data-time">{selected.refreshed_at ? `Publicado em ${adminDate(selected.refreshed_at)}` : "Aguardando publicação"}{selected.stale && <span>Atualização pendente</span>}</p>
        </div>}
      </section>
    </div>

    <section className="battle-ranking panel" aria-labelledby="battle-ranking-title"><div className="battle-panel-head"><div><h2 id="battle-ranking-title">Classificação atual</h2><p>Empresas sem casos publicados ficam fora das posições. A posição não mede evolução histórica.</p></div><span className="battle-last-update">{latest ? `Última publicação: ${adminDate(latest)}` : "Sem publicação"}</span></div>
      <div className="battle-ranking-tools"><label className="battle-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Buscar empresa</span><input type="search" placeholder="Buscar empresa" value={query} onChange={(event) => setQuery(event.target.value)} /></label><span>{filtered.length} {filtered.length === 1 ? "empresa" : "empresas"}</span></div>
      <div className="battle-table-scroll"><table className="battle-table"><thead><tr><th scope="col">Posição</th><th scope="col">Empresa</th><th scope="col">Índice</th><th scope="col">Casos ativos</th><th scope="col">Críticos ou altos</th><th scope="col">Em tratamento</th><th scope="col">Corrigidos 30 dias</th><th scope="col">Dados</th></tr></thead><tbody>
        {filtered.map((company) => <tr key={company.id} className={selected?.id === company.id ? "is-selected" : ""}><td>{company.case_count ? `${ranked.findIndex((item) => item.id === company.id) + 1}º` : "—"}</td><td><button className="battle-company-button" type="button" aria-pressed={selected?.id === company.id} onClick={() => setSelectedId(company.id)}><strong>{visibleText(company.name)}</strong><small>{company.slug}</small></button></td><td><strong>{company.case_count ? `${Math.round(score(company))}%` : "Sem dados"}</strong></td><td>{number(company.case_count)}</td><td>{number(company.critical_high_count)}</td><td>{number(company.in_progress_count)}</td><td>{number(company.corrected_30)}</td><td>{company.refreshed_at ? adminDate(company.refreshed_at) : "Aguardando publicação"}{company.stale && <small>Atualização pendente</small>}</td></tr>)}
      </tbody></table>{!filtered.length && <p className="battle-table-empty">Nenhuma empresa encontrada. Tente outro nome.</p>}</div>
    </section>
  </div>;
}
