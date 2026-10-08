"use client";

import Link from "next/link";
import { CompanyPicker } from "@/src/components/company-picker";
import { SpotlightCard } from "@/src/components/ui/spotlight-card";
import { AnimatedCounter } from "@/src/components/ui/animated-counter";
import { useLiveData } from "@/src/lib/use-live-data";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSiteNotifications } from "@/src/components/site-notifications";
import { useErrorNotice } from "@/src/lib/use-filter-notice";
import type { Session, SupabaseClient } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import { ProfileMenu } from "@/src/components/profile-menu";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { withConsistentInventoryRead } from "@/src/lib/consistent-inventory";
import { snapshotFreshness } from "@/src/lib/snapshot-freshness";
import { BentoCard, BentoGrid } from "@/src/components/ui/bento-grid";
import { NavSymbol } from "@/src/components/ui/nav-symbol";
import { visibleText } from "@/src/lib/visible-text";

type Company = { id: string; name: string; slug: string; role: string };
type SeverityDatum = { name: string; count: number; color: string };
type AgeDatum = { name: string; count: number };
type MonthDatum = { month: string; count: number; key: string };
type TopVulnerability = {
  id: string;
  hosts: number;
  count: number;
  firstDetected: string;
};
type BookMetrics = {
  total: number;
  uniqueCves: number;
  affectedHosts: number;
  criticalHigh: number;
  otherSeverity: number;
  prolonged: number;
  severity: SeverityDatum[];
  ages: AgeDatum[];
  months: MonthDatum[];
  top: TopVulnerability[];
  currentMonth: number;
  previousMonth: number;
};
type BookMetricsRow = {
  total: number;
  unique_cves: number;
  affected_hosts: number;
  critical_high: number;
  other_severity: number;
  prolonged: number;
  severity: Record<string, number>;
  ages: { over90: number; days61to90: number; days31to60: number; days0to30: number };
  months: Record<string, number>;
  top: TopVulnerability[];
};
type SyncSummary = { finishedAt: string | null; connections: number; missingSnapshots: number };

const severityColors: Record<string, string> = {
  Critical: "#a90839",
  High: "#ef3438",
  Medium: "#f28b25",
  Low: "#e5bf21",
};
const severityOrder = ["Critical", "High", "Medium", "Low"];

export function CustomerBook() {
  const supabase = getSupabaseBrowserClient();
  const { notify } = useSiteNotifications();
  const [session, setSession] = useState<Session | null>(null);
  const userId = session?.user.id;
  const [authReady, setAuthReady] = useState(false);
  const [contextReady, setContextReady] = useState(false);
  const [contextError, setContextError] = useState("");
  const [companies, setCompanies] = useState<Company[]>([]);
  const [selectedCompany, setSelectedCompany] = useState("");
  const [isInternal, setIsInternal] = useState(false);
  const [metrics, setMetrics] = useState<BookMetrics>(() => buildMetrics());
  const [latestSync, setLatestSync] = useState<SyncSummary>({ finishedAt: null, connections: 0, missingSnapshots: 0 });
  const [loadedAt, setLoadedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const refreshRequested = useRef(false);
  const loadedScopeRef = useRef<string | null>(null);
  const live = useLiveData(supabase, contextReady ? session?.user.id : undefined, loading);
  useErrorNotice(error || contextError, "book-feedback");

  function refresh() {
    refreshRequested.current = true;
    notify({ title: "Atualizando relatório…", key: "book-feedback" });
    setRefreshKey((value) => value + 1);
  }

  useEffect(() => {
    if (!supabase) {
      setAuthReady(true);
      setLoading(false);
      return;
    }
    let mounted = true;
    const { data: authListener } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      if (mounted) {
        setSession(nextSession);
        setAuthReady(true);
      }
    });
    void supabase.auth.getSession().then(({ data }) => {
      if (!mounted) return;
      setSession(data.session);
      setAuthReady(true);
    }).catch(() => {
      if (mounted) setAuthReady(true);
    });
    return () => {
      mounted = false;
      authListener.subscription.unsubscribe();
    };
  }, [supabase]);

  useEffect(() => {
    if (!supabase || !userId) {
      setContextReady(false);
      return;
    }
    let active = true;
    setContextReady(false);
    setContextError("");
    void (async () => {
      try {
        const { data, error: contextQueryError } = await supabase.rpc("current_user_context");
        if (contextQueryError) throw contextQueryError;
        const context = data as { is_internal_admin?: boolean; companies?: Company[] };
        const internal = Boolean(context.is_internal_admin);
        let availableCompanies = context.companies ?? [];
        if (internal) {
          const { data: companyRows, error: companyQueryError } = await supabase
            .from("companies")
            .select("id,name,slug")
            .eq("is_active", true)
            .order("name");
          if (companyQueryError) throw companyQueryError;
          availableCompanies = (companyRows ?? []).map((company) => ({ ...company, role: "internal" }));
        }
        if (!active) return;
        setIsInternal(internal);
        setCompanies(availableCompanies);
        setSelectedCompany(internal ? "" : availableCompanies[0]?.id ?? "");
        if (!internal && availableCompanies.length === 0) {
          setContextError("Sua conta ainda não tem uma empresa vinculada. Peça à equipe para revisar o convite.");
        }
        setContextReady(true);
      } catch {
        if (!active) return;
        setContextError("Não foi possível carregar as empresas permitidas para esta conta.");
        setContextReady(true);
      }
    })();
    return () => { active = false; };
  }, [userId, supabase]);

  const loadMetrics = useCallback(async (client: SupabaseClient, companyId: string) => {
    const { data, error: queryError } = await client.rpc("get_customer_book_metrics", { p_company_id: companyId || null });
    if (queryError) throw queryError;
    if (!data || typeof data !== "object" || typeof (data as BookMetricsRow).total !== "number") {
      throw new Error("O relatório não retornou os indicadores esperados.");
    }
    return buildMetrics(data as BookMetricsRow);
  }, []);

  const loadSyncSummary = useCallback(async (client: SupabaseClient, companyId: string, internal: boolean): Promise<SyncSummary> => {
    const { data: connectionRows, error: connectionError } = await client
      .from("wazuh_connections")
      .select("id,tenant_id,mode,published_sync_run_id")
      .eq("is_active", true);
    if (connectionError) throw connectionError;
    let connections = connectionRows ?? [];
    if (companyId && internal) {
      const { data: mappingRows, error: mappingError } = await client
        .from("wazuh_agent_mappings")
        .select("connection_id")
        .eq("tenant_id", companyId)
        .eq("is_active", true);
      if (mappingError) throw mappingError;
      const mappedIds = new Set((mappingRows ?? []).map((row) => row.connection_id));
      connections = connections.filter((connection) =>
        connection.tenant_id === companyId || (connection.mode === "shared" && mappedIds.has(connection.id))
      );
    }
    const ids = connections.map((connection) => connection.id);
    if (!ids.length) return { finishedAt: null, connections: 0, missingSnapshots: 0 };
    const publishedRunIds = connections
      .map((connection) => connection.published_sync_run_id)
      .filter((runId): runId is string => Boolean(runId));
    if (!publishedRunIds.length) {
      return { finishedAt: null, connections: ids.length, missingSnapshots: ids.length };
    }
    const { data: runs, error: runError } = await client
      .from("sync_runs")
      .select("id,connection_id,finished_at,status,full_snapshot")
      .in("id", publishedRunIds)
      .eq("status", "succeeded")
      .eq("full_snapshot", true);
    if (runError) throw runError;
    const publishedByConnection = new Map((runs ?? [])
      .filter((run) => run.finished_at)
      .map((run) => [run.connection_id, run.finished_at!]));
    const completedAt = ids.map((id) => publishedByConnection.get(id)).filter((value): value is string => Boolean(value));
    completedAt.sort((left, right) => Date.parse(left) - Date.parse(right));
    return {
      finishedAt: completedAt[0] ?? null,
      connections: ids.length,
      missingSnapshots: ids.length - completedAt.length,
    };
  }, []);

  useEffect(() => {
    if (!supabase || !userId || !contextReady || contextError || (!isInternal && !selectedCompany)) return;
    let active = true;
    const scope = `${userId}:${selectedCompany}:${isInternal}`;
    if (loadedScopeRef.current !== scope || refreshRequested.current) setLoading(true);
    setError("");
    void withConsistentInventoryRead(supabase, () => Promise.all([
      loadMetrics(supabase, selectedCompany),
      loadSyncSummary(supabase, selectedCompany, isInternal),
    ])).then(([nextMetrics, nextSync]) => {
      if (!active) return;
      loadedScopeRef.current = scope;
      setMetrics(nextMetrics);
      setLatestSync(nextSync);
      setLoadedAt(new Date().toISOString());
      if (refreshRequested.current) {
        notify({ title: "Relatório atualizado.", detail: `${nextMetrics.total.toLocaleString("pt-BR")} vulnerabilidades ativas consultadas.`, key: "book-feedback" });
        refreshRequested.current = false;
      }
    }).catch((loadError: unknown) => {
      if (!active) return;
      refreshRequested.current = false;
      setError(loadError instanceof Error
        ? loadError.message
        : "Não foi possível carregar os dados completos deste relatório.");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [contextError, contextReady, isInternal, live.revision, loadMetrics, loadSyncSummary, notify, refreshKey, selectedCompany, userId, supabase]);

  const selectedCompanyName = companies.find((company) => company.id === selectedCompany)?.name;
  const freshness = snapshotFreshness(latestSync.finishedAt, live.now);
  const isStale = latestSync.missingSnapshots > 0 || freshness === "stale";
  const isAging = !isStale && freshness === "aging";
  const displayCount = (value: number) => value.toLocaleString("pt-BR");

  async function signOut() {
    if (!supabase) return;
    const { error } = await supabase.auth.signOut();
    if (error) notify({ title: "Não foi possível encerrar a sessão.", error: true, key: "auth-session" });
  }

  if (!supabase) return <BookConfigurationRequired />;
  if (!authReady || (session && !contextReady)) return <main className="loading-screen"><Brand href="/dashboard" /><div className="spinner"/><p>Preparando o Book dos Clientes…</p></main>;
  if (!session) return <main className="welcome-shell"><div className="welcome-card"><Brand href="/dashboard" /><span className="eyebrow">BOOK DOS CLIENTES</span><h1>Entre para consultar o relatório.</h1><p>O acesso ao Book respeita os vínculos e as permissões da sua empresa.</p><Link className="button button-primary" href="/login">Entrar com convite</Link></div><aside className="welcome-art"><BentoGrid className="welcome-bento" aria-label="Conteúdo do Book"><BentoCard className="welcome-feature welcome-feature-main"><span>Relatório por empresa</span><strong>Exposição atual</strong><small>Uma leitura vinculada aos dados do cliente.</small></BentoCard><BentoCard className="welcome-feature"><span>Criticidade</span><strong>Severidade</strong><small>Distribuição das vulnerabilidades ativas.</small></BentoCard><BentoCard className="welcome-feature"><span>Prioridade</span><strong>Tempo de exposição</strong><small>Foco nos casos que persistem.</small></BentoCard></BentoGrid></aside></main>;

  return (
    <main className="app-shell book-shell">
      <a className="skip-link" href="#book-overview">Pular para o conteúdo</a>
      <aside className="sidebar">
        <Brand href="/dashboard" />
        <nav className="workspace-nav" aria-label="Navegação principal">
          <div className="nav-caption">WORKSPACE</div>
          <Link className="nav-link" href="/dashboard" aria-label="Vulnerabilidades" title="Vulnerabilidades"><NavSymbol kind="vulnerabilities" /><span className="nav-label">Vulnerabilidades</span></Link>
          <Link className="nav-link" href="/cases" aria-label="Casos" title="Casos de vulnerabilidade"><NavSymbol kind="cases" /><span className="nav-label">Casos</span></Link>
          <Link className="nav-link" href="/assets" aria-label="Ativos" title="Ativos"><NavSymbol kind="assets" /><span className="nav-label">Ativos</span></Link>
          <Link className="nav-link active" href="/book" aria-current="page" aria-label="Book dos Clientes" title="Book dos Clientes"><NavSymbol kind="book" /><span className="nav-label">Book dos Clientes</span></Link>
          {isInternal && <Link className="nav-link" href="/battle" aria-label="Batalha" title="Batalha"><NavSymbol kind="battle" /><span className="nav-label">Batalha</span></Link>}
        </nav>
        <div className="sidebar-bottom"><ProfileMenu userId={session.user.id} fallback={session.user.email ?? "U"} isInternal={isInternal} /><div className="user-info"><strong>{session.user.email}</strong><span>{isInternal ? "Equipe Pier" : selectedCompanyName ?? "Cliente"}</span></div><button className="book-signout" onClick={() => void signOut()}>Sair</button></div>
      </aside>

      <section className="main-column book-main-column">
        <header className="topbar">
          <div className="breadcrumb">PierVuln <span>/</span> <strong>Book dos Clientes</strong></div>
          <div className="topbar-actions">
            {isInternal ? <CompanyPicker client={supabase} companies={companies} value={selectedCompany} isInternal={isInternal} onChange={setSelectedCompany} /> : <span className="company-chip">{visibleText(selectedCompanyName ?? "Minha empresa")}</span>}
            <button className="button button-secondary refresh-button" onClick={refresh} disabled={loading}>{loading ? "Atualizando…" : "Atualizar"}</button>
          </div>
        </header>

        <div className="book-content" id="book-overview" tabIndex={-1}>
          <div className="book-heading">
            <div><h1>Book dos Clientes</h1><p>Exposição atual, criticidade e tempo de permanência das vulnerabilidades.</p></div>
            <div className={`book-source-state ${isStale ? "book-source-stale" : isAging ? "book-source-aging" : "book-source-fresh"}`}><span/>{latestSync.finishedAt ? (isStale ? "Coleta atrasada" : isAging ? "Atualização recomendada" : "Leitura atualizada") : "Aguardando leitura"}<small>{latestSync.finishedAt ? `Snapshot mais antigo: ${formatDate(latestSync.finishedAt)}${latestSync.missingSnapshots ? ` · ${latestSync.missingSnapshots} fonte(s) sem snapshot` : ""}` : "Nenhum snapshot completo disponível"} · recomendada após 1h; atrasada após 2h · {live.connected ? "Relatório ao vivo" : "Atualização automática"}</small></div>
          </div>

          {contextError && <div className="book-alert" role="alert">{contextError}</div>}
          {error && <div className="book-alert" role="alert"><span>{error}</span><button onClick={refresh}>Tentar novamente</button></div>}

          {!contextError && <>
            <BentoGrid className="book-overview" aria-label="Indicadores de exposição">
              <BentoCard className="book-total"><span>Vulnerabilidades ativas</span><strong><AnimatedCounter value={metrics.total} /></strong><small>{selectedCompanyName ?? (selectedCompany ? "Empresa selecionada" : "Visão consolidada")}</small></BentoCard>
              <BentoCard className="book-highlight-stat"><span className="book-section-tag">Críticas e altas</span><strong><AnimatedCounter value={metrics.criticalHigh} /></strong><p>{metrics.total ? `${Math.round(metrics.criticalHigh / metrics.total * 100)}%` : "0%"} do total ativo.</p></BentoCard>
              <BentoCard className="book-highlight-stat"><span className="book-section-tag">Exposição prolongada</span><strong><AnimatedCounter value={metrics.prolonged} /></strong><p>Vulnerabilidades ativas há mais de 90 dias.</p></BentoCard>
            </BentoGrid>

            <BentoGrid className="book-chart-grid" aria-label="Distribuição e evolução das vulnerabilidades">
              <SpotlightCard className="book-chart-section">
                <div className="book-section-heading"><div><span className="book-section-tag">DISTRIBUIÇÃO POR SEVERIDADE</span><h2>Criticidade das vulnerabilidades</h2></div><small>{displayCount(metrics.total)} ativas</small></div>
                <div className="book-chart" role="img" aria-label={`Distribuição por severidade: ${metrics.severity.map((item) => `${item.name} ${displayCount(item.count)}`).join(", ")}`}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={metrics.severity} margin={{ top: 26, right: 12, bottom: 2, left: -16 }}>
                      <CartesianGrid vertical={false} stroke="rgba(255, 255, 255, .09)" />
                      <XAxis dataKey="name" axisLine={{ stroke: "rgba(255, 255, 255, .12)" }} tickLine={false} tick={{ fill: "#a4a8ae", fontSize: 12 }} />
                      <YAxis allowDecimals={false} width={54} axisLine={false} tickLine={false} tick={{ fill: "#a4a8ae", fontSize: 12 }} tickFormatter={shortCount} />
                      <Tooltip cursor={{ fill: "rgba(72, 233, 255, .07)" }} contentStyle={tooltipStyle} labelStyle={{ color: "#f6f7f7" }} formatter={(value) => [displayCount(Number(value)), "Vulnerabilidades"]} />
                      <Bar dataKey="count" name="Vulnerabilidades" radius={[5, 5, 0, 0]} isAnimationActive={false}>
                        {metrics.severity.map((item) => <Cell key={item.name} fill={item.color} />)}
                        <LabelList dataKey="count" position="top" fill="#f6f7f7" fontSize={12} formatter={(value: unknown) => shortCount(Number(value))} />
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                {metrics.otherSeverity > 0 && <p className="book-chart-note">{displayCount(metrics.otherSeverity)} informativas ou sem severidade classificada também entram no total.</p>}
              </SpotlightCard>
              <SpotlightCard className="book-chart-section">
                <div className="book-section-heading"><div><span className="book-section-tag">EVOLUÇÃO TEMPORAL</span><h2>Primeira detecção</h2></div><small>Últimos 6 meses</small></div>
                <div className="book-chart" role="img" aria-label="Vulnerabilidades ainda ativas, agrupadas pelo mês de primeira detecção nos últimos seis meses">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={metrics.months} margin={{ top: 26, right: 12, bottom: 2, left: -16 }}>
                      <CartesianGrid vertical={false} stroke="rgba(255, 255, 255, .09)" />
                      <XAxis dataKey="month" axisLine={{ stroke: "rgba(255, 255, 255, .12)" }} tickLine={false} tick={{ fill: "#a4a8ae", fontSize: 12 }} />
                      <YAxis allowDecimals={false} width={54} axisLine={false} tickLine={false} tick={{ fill: "#a4a8ae", fontSize: 12 }} tickFormatter={shortCount} />
                      <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "#f6f7f7" }} formatter={(value) => [displayCount(Number(value)), "Vulnerabilidades ativas"]} />
                      <Line type="monotone" dataKey="count" name="Vulnerabilidades ativas" stroke="#48e9ff" strokeWidth={3} dot={{ r: 3, fill: "#48e9ff", stroke: "#191a1c", strokeWidth: 2 }} activeDot={{ r: 5, fill: "#191a1c", stroke: "#78f1ff", strokeWidth: 2 }} isAnimationActive={false}>
                        <LabelList dataKey="count" position="top" fill="#f6f7f7" fontSize={11} formatter={(value: unknown) => shortCount(Number(value))} />
                      </Line>
                    </LineChart>
                  </ResponsiveContainer>
                </div>
                <p className="book-chart-note">Vulnerabilidades atualmente ativos agrupados pela data de primeira detecção — não é um snapshot mensal histórico.</p>
              </SpotlightCard>
            </BentoGrid>

            <BentoGrid className="book-highlights" aria-label="Contexto do relatório">
              <BentoCard className="book-month-highlight"><span className="book-section-tag">Vulnerabilidades ativas por detecção</span><div className="book-month-comparison"><div><small>Mês anterior</small><strong><AnimatedCounter value={metrics.previousMonth} /></strong></div><div><small>Mês vigente</small><strong><AnimatedCounter value={metrics.currentMonth} /></strong></div><div><small>Variação</small><strong className={monthVariation(metrics.currentMonth, metrics.previousMonth).className}>{monthVariation(metrics.currentMonth, metrics.previousMonth).label}</strong></div></div><p>Contagem atual agrupada pela data da primeira detecção.</p></BentoCard>
            </BentoGrid>

            <BentoGrid className="book-detail-grid" aria-label="Tempo de exposição e concentração por CVE">
              <SpotlightCard className="book-chart-section book-age-section">
                <div className="book-section-heading"><div><span className="book-section-tag">FAIXA DE TEMPO DA EXPOSIÇÃO</span><h2>Há quanto tempo continuam ativas</h2></div></div>
                <div className="book-age-chart" role="img" aria-label={`Faixas de exposição: ${metrics.ages.map((item) => `${item.name} ${displayCount(item.count)}`).join(", ")}`}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={metrics.ages} layout="vertical" margin={{ top: 8, right: 40, bottom: 4, left: 10 }}>
                      <CartesianGrid horizontal={false} stroke="rgba(255, 255, 255, .09)" />
                      <XAxis type="number" allowDecimals={false} axisLine={{ stroke: "rgba(255, 255, 255, .12)" }} tickLine={false} tick={{ fill: "#a4a8ae", fontSize: 12 }} tickFormatter={shortCount} />
                      <YAxis type="category" dataKey="name" width={88} axisLine={false} tickLine={false} tick={{ fill: "#d4d7da", fontSize: 12 }} />
                      <Tooltip cursor={{ fill: "rgba(72, 233, 255, .07)" }} contentStyle={tooltipStyle} labelStyle={{ color: "#f6f7f7" }} formatter={(value) => [displayCount(Number(value)), "Vulnerabilidades"]} />
                      <Bar dataKey="count" name="Vulnerabilidades" radius={[0, 5, 5, 0]} isAnimationActive={false}>
                        {metrics.ages.map((item, index) => <Cell key={item.name} fill={["#48e9ff", "#3abdd0", "#2c91a1", "#206973"][index]} />)}
                        <LabelList dataKey="count" position="right" fill="#f6f7f7" fontSize={12} formatter={(value: unknown) => shortCount(Number(value))} />
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </SpotlightCard>
              <SpotlightCard className="book-top-table" id="concentracao">
                <div className="book-section-heading"><div><span className="book-section-tag">CONCENTRAÇÃO POR VULNERABILIDADE</span><h2>Top 3 por ativos afetados</h2></div></div>
                <div className="book-table-scroll"><table><thead><tr><th>CVE</th><th>DETECÇÃO INICIAL</th><th>VOLUME</th></tr></thead><tbody>
                  {metrics.top.length ? metrics.top.map((item) => <tr key={item.id}><td><strong>{item.id}</strong></td><td>{formatMonth(item.firstDetected)}</td><td><strong>{displayCount(item.hosts)}</strong><span>{item.hosts === 1 ? "host afetado" : "hosts afetados"}</span></td></tr>) : <tr><td colSpan={3} className="book-table-empty">Nenhuma vulnerabilidade ativa nesta seleção.</td></tr>}
                </tbody></table></div>
                <p className="book-table-note">Ordenado pelo número de hosts distintos afetados; o total conta apenas as vulnerabilidades ativas.</p>
              </SpotlightCard>
            </BentoGrid>

            <BentoGrid className="book-footer-row" aria-label="Ativos e inventário técnico">
              <div className="book-foot-stat"><span>HOSTS AFETADOS</span><strong><AnimatedCounter value={metrics.affectedHosts} /></strong><small>Agentes distintos com vulnerabilidades ativas</small></div>
              <div className="book-foot-stat"><span>CVEs ÚNICOS</span><strong><AnimatedCounter value={metrics.uniqueCves} /></strong><small>Identificadores diferentes no total ativo</small></div>
               <div className="book-inventory-cta"><span>APROFUNDAMENTO TÉCNICO</span><p>Abra o inventário completo para consultar ativos, pacotes e o fluxo de tratamento de cada caso.</p><Link href="/cases">Explorar inventário técnico</Link></div>
            </BentoGrid>
          </>}
          <footer className="book-footer"><span>PierVuln</span><span>{latestSync.finishedAt ? `Último snapshot completo: ${formatDate(latestSync.finishedAt)}` : "Sem snapshot completo registrado"}</span><span>{latestSync.connections} {latestSync.connections === 1 ? "fonte ativa" : "fontes de dados"}</span></footer>
        </div>
      </section>
      <nav className={`book-mobile-nav${isInternal ? " has-admin" : ""}`} aria-label="Navegação principal"><Link href="/dashboard">Vulnerabilidades</Link><Link href="/cases">Casos</Link><Link href="/assets">Ativos</Link><Link href="/book" aria-current="page">Book dos Clientes</Link>{isInternal && <Link href="/battle">Batalha</Link>}</nav>
    </main>
  );
}

function buildMetrics(row?: BookMetricsRow): BookMetrics {
  const now = new Date();
  const monthStarts = Array.from({ length: 6 }, (_, index) => new Date(now.getFullYear(), now.getMonth() - (5 - index), 1));
  const months: MonthDatum[] = monthStarts.map((date) => ({
    key: monthKey(date),
    month: new Intl.DateTimeFormat("pt-BR", { month: "short" }).format(date).replace(".", ""),
    count: row?.months[monthKey(date)] ?? 0,
  }));
  const currentKey = monthKey(now);
  const previousKey = monthKey(new Date(now.getFullYear(), now.getMonth() - 1, 1));
  return {
    total: row?.total ?? 0,
    uniqueCves: row?.unique_cves ?? 0,
    affectedHosts: row?.affected_hosts ?? 0,
    criticalHigh: row?.critical_high ?? 0,
    otherSeverity: row?.other_severity ?? 0,
    prolonged: row?.prolonged ?? 0,
    severity: severityOrder.map((name) => ({ name, count: row?.severity[name] ?? 0, color: severityColors[name] })),
    ages: [
      { name: ">90 dias", count: row?.ages.over90 ?? 0 },
      { name: "61–90 dias", count: row?.ages.days61to90 ?? 0 },
      { name: "31–60 dias", count: row?.ages.days31to60 ?? 0 },
      { name: "Até 30 dias", count: row?.ages.days0to30 ?? 0 },
    ],
    months,
    top: row?.top ?? [],
    currentMonth: row?.months[currentKey] ?? 0,
    previousMonth: row?.months[previousKey] ?? 0,
  };
}

function monthKey(date: Date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
}

function monthVariation(current: number, previous: number) {
  if (previous === 0 && current === 0) return { label: "0%", className: "book-variation-flat" };
  if (previous === 0) return { label: "Novo", className: "book-variation-up" };
  const delta = Math.round(((current - previous) / previous) * 100);
  if (delta === 0) return { label: "0%", className: "book-variation-flat" };
  return { label: `${delta > 0 ? "Aumento" : "Redução"} de ${Math.abs(delta)}%`, className: delta > 0 ? "book-variation-up" : "book-variation-down" };
}

function shortCount(value: number) {
  return value.toLocaleString("pt-BR", { notation: "compact", maximumFractionDigits: 1 });
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : new Intl.DateTimeFormat("pt-BR", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function formatMonth(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : new Intl.DateTimeFormat("pt-BR", { month: "short", year: "numeric" }).format(date).replace(".", "");
}

const tooltipStyle = {
  border: "0",
  borderRadius: 12,
  backgroundColor: "#252628",
  color: "#f6f7f7",
  fontSize: 13,
};

function BookConfigurationRequired() {
  return <main className="welcome-shell"><div className="auth-card"><Brand href="/dashboard"/><div className="eyebrow">CONFIGURAÇÃO NECESSÁRIA</div><h1>Conecte o projeto Supabase</h1><p>Configure a URL e a chave publicável do projeto PierGV para consultar o relatório.</p></div></main>;
}
