"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import type { Session } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import { WorkspaceNav } from "@/src/components/workspace-nav";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import type { VulnerabilityOverview } from "@/src/lib/vulnerability-overview";

type Access = "checking" | "allowed" | "denied" | "error";
type Company = { id: string; name: string };

// Mesma fonte da visão de vulnerabilidades: o banco aplica o isolamento por empresa.
export function BookSocOverview() {
  const client = getSupabaseBrowserClient();
  const [session, setSession] = useState<Session | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [access, setAccess] = useState<Access>("checking");
  const [companies, setCompanies] = useState<Company[]>([]);
  const [companyId, setCompanyId] = useState("");
  const [overview, setOverview] = useState<VulnerabilityOverview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!client) return;
    let mounted = true;
    void client.auth.getSession().then(({ data }) => { if (mounted) { setSession(data.session); setAuthReady(true); } });
    const { data: listener } = client.auth.onAuthStateChange((_event, next) => { if (mounted) { setSession(next); setAuthReady(true); } });
    return () => { mounted = false; listener.subscription.unsubscribe(); };
  }, [client]);

  useEffect(() => {
    if (!client || !session) return;
    let mounted = true;
    void client.rpc("current_user_context").then(({ data, error: rpcError }) => {
      if (mounted) setAccess(rpcError ? "error" : (data as { is_internal_admin?: boolean } | null)?.is_internal_admin === true ? "allowed" : "denied");
    });
    return () => { mounted = false; };
  }, [client, session]);

  useEffect(() => {
    if (!client || access !== "allowed") return;
    let mounted = true;
    void client.from("companies").select("id, name").eq("is_active", true).order("name").then(({ data }) => {
      if (mounted && data) setCompanies(data as Company[]);
    });
    return () => { mounted = false; };
  }, [client, access]);

  useEffect(() => {
    if (!client || access !== "allowed" || !companyId) { setOverview(null); return; }
    let mounted = true;
    setLoading(true); setError("");
    void client.rpc("get_vulnerability_overview", { p_company_id: companyId, p_agent_name_prefix: null }).then(({ data, error: rpcError }) => {
      if (!mounted) return;
      setLoading(false);
      const result = (Array.isArray(data) ? data[0] : data) as VulnerabilityOverview | undefined;
      if (rpcError || !result) { setOverview(null); setError("Não foi possível carregar os indicadores desta empresa."); return; }
      setOverview(result);
    });
    return () => { mounted = false; };
  }, [client, access, companyId]);

  const shell = (content: ReactNode) => (
    <main className="app-shell">
      <a className="skip-link" href="#book-soc-content">Pular para o conteúdo</a>
      <aside className="sidebar"><Brand /><WorkspaceNav isInternal={access === "allowed"} /></aside>
      <section className="main-column book-main-column">
        <header className="topbar"><div className="breadcrumb">Relatórios <span>/</span><strong>Book SOC</strong></div></header>
        <div className="content-wrap" id="book-soc-content" tabIndex={-1}>{content}</div>
      </section>
    </main>
  );

  if (!client) return shell(<p className="inline-alert" role="alert">Configure a conexão pública com o Supabase para abrir esta página.</p>);
  if (!authReady) return shell(<div className="admin-loading" role="status"><div className="spinner" />Verificando sessão…</div>);
  if (!session) return shell(<section className="auth-card"><h1>Book SOC</h1><p>Entre com a conta da equipe para continuar.</p><Link className="button button-primary" href="/login">Entrar</Link></section>);
  if (access === "checking") return shell(<div className="admin-loading" role="status"><div className="spinner" />Verificando acesso…</div>);
  if (access !== "allowed") return shell(<section className="auth-card"><h1>{access === "error" ? "Não foi possível verificar o acesso" : "Acesso restrito"}</h1><p>Esta área é exclusiva da equipe Pier.</p></section>);

  return shell(
    <div className="bsoc-page">
      <header className="bsoc-head">
        <h1>Book SOC</h1>
        <p>Visão executiva · estado atual das vulnerabilidades</p>
      </header>

      <form className="bsoc-card bsoc-context" aria-label="Empresa" onSubmit={(event) => event.preventDefault()}>
        <label htmlFor="bsoc-company">Empresa</label>
        <select id="bsoc-company" value={companyId} onChange={(event) => setCompanyId(event.target.value)}>
          <option value="">Selecione uma empresa</option>
          {companies.map((company) => <option key={company.id} value={company.id}>{company.name}</option>)}
        </select>
      </form>

      {error && <div className="inline-alert" role="alert">{error}</div>}
      {loading && <div className="admin-loading" role="status"><div className="spinner" />Carregando indicadores…</div>}

      {overview && !loading && (
        <div className="bsoc-stack">
          <div className="bsoc-hero">
            <section className="bsoc-card bsoc-card--inset" aria-label="Destaque">
              <span className="bsoc-tag">Destaque da visão</span>
              <strong className="bsoc-big">{overview.activeCount.toLocaleString("pt-BR")}</strong>
              <p className="bsoc-caption">registros de vulnerabilidade ativos nesta empresa</p>
            </section>
            <section className="bsoc-card" aria-label="Situação atual">
              <SectionHead title="Situação atual" />
              <div className="bsoc-stats">
                <div><strong>{overview.criticalHighCount.toLocaleString("pt-BR")}</strong><span>críticas e altas</span></div>
                <div><strong>{overview.inProgressCount.toLocaleString("pt-BR")}</strong><span>em andamento</span></div>
                <div><strong>{overview.corrected30.toLocaleString("pt-BR")}</strong><span>corrigidas em 30 dias</span></div>
              </div>
              <p className="bsoc-note">Estado atual lido do banco do PierVuln; não representa o fechamento histórico do mês.</p>
            </section>
          </div>

          <div className="bsoc-trio">
            <section className="bsoc-card" aria-label="Distribuição por severidade">
              <SectionHead tag="Distribuição por severidade" title="Registros por severidade" />
              <BarList label="Registros por severidade" rows={sortedSeverities(overview).map(([label, count]) => ({ label, count: Number(count) }))} />
              <p className="bsoc-note">Total de registros ativos em cada severidade.</p>
            </section>
            <section className="bsoc-card" aria-label="Tempo de exposição">
              <SectionHead tag="Faixa de tempo da exposição" title="Há quanto tempo continuam ativas" />
              <BarList label="Vulnerabilidades ativas por faixa de idade" rows={ageBands(overview)} />
              <p className="bsoc-note">Idade contada a partir da primeira detecção registrada na fonte.</p>
            </section>
            <section className="bsoc-card" aria-label="Evolução por primeira detecção">
              <SectionHead tag="Evolução temporal" title="Primeira detecção" side="Últimos 6 meses" />
              <BarList label="Vulnerabilidades ativas por mês de primeira detecção" rows={lastMonths(overview)} />
              <p className="bsoc-note">Agrupa os achados atuais pela data de primeira detecção. Não é o total histórico da fonte.</p>
            </section>
          </div>

          <section className="bsoc-card" aria-label="Concentração por vulnerabilidade">
            <SectionHead tag="Concentração por vulnerabilidade" title="Principais CVEs por ativos afetados" />
            <div className="bsoc-table-wrap">
              <table className="bsoc-table">
                <thead>
                  <tr><th scope="col">CVE</th><th scope="col">Severidade</th><th scope="col" className="is-num">CVSS</th><th scope="col" className="is-num hide-narrow">Registros</th><th scope="col" className="is-num">Hosts</th></tr>
                </thead>
                <tbody>
                  {topCves(overview).map((item) => (
                    <tr key={item.cve}>
                      <td><strong>{item.cve}</strong></td>
                      <td>{item.severity}</td>
                      <td className="is-num">{Number.isFinite(item.cvss) ? item.cvss.toFixed(1) : "—"}</td>
                      <td className="is-num hide-narrow">{item.cases.toLocaleString("pt-BR")}</td>
                      <td className="is-num">{item.hosts.toLocaleString("pt-BR")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="bsoc-note">Ordenado pelo número de hosts distintos afetados. Para ativos, pacotes e tratamento de cada caso, abra o <Link href="/cases">inventário</Link>.</p>
          </section>
        </div>
      )}
    </div>,
  );
}

function SectionHead({ tag, title, side }: { tag?: string; title: string; side?: string }) {
  return (
    <div className="bsoc-section-head">
      <div>{tag && <span className="bsoc-tag">{tag}</span>}<h2>{title}</h2></div>
      {side && <small>{side}</small>}
    </div>
  );
}

const AGE_LABELS = ["Até 7 dias", "8–30 dias", "31–90 dias", "Mais de 90 dias"];
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"];

function ageBands(overview: VulnerabilityOverview) {
  const totals = AGE_LABELS.map(() => 0);
  for (const entry of overview.ageCounts) if (entry.band >= 0 && entry.band < totals.length) totals[entry.band] += entry.count;
  return AGE_LABELS.map((label, index) => ({ label, count: totals[index] }));
}

function lastMonths(overview: VulnerabilityOverview, size = 6) {
  const byMonth = new Map<string, number>();
  for (const entry of overview.monthCounts) byMonth.set(entry.month, (byMonth.get(entry.month) ?? 0) + entry.count);
  const now = new Date();
  return Array.from({ length: size }, (_, index) => {
    const date = new Date(now.getFullYear(), now.getMonth() - (size - 1 - index), 1);
    const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
    return { label: date.toLocaleDateString("pt-BR", { month: "short", year: "2-digit" }).replace(".", ""), count: byMonth.get(key) ?? 0 };
  });
}

function sortedSeverities(overview: VulnerabilityOverview): [string, number][] {
  const rank = (name: string) => { const index = SEVERITY_ORDER.indexOf(name); return index === -1 ? SEVERITY_ORDER.length : index; };
  return Object.entries(overview.severityCounts).sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b));
}

function topCves(overview: VulnerabilityOverview, size = 10) {
  const byCve = new Map<string, { cve: string; severity: string; cvss: number; cases: number; hosts: number }>();
  for (const group of overview.groups) {
    const current = byCve.get(group.cve) ?? { cve: group.cve, severity: group.severity, cvss: group.cvss, cases: 0, hosts: 0 };
    current.cases += group.caseCount; current.hosts += group.hostCount;
    byCve.set(group.cve, current);
  }
  return [...byCve.values()].sort((a, b) => b.hosts - a.hosts || b.cases - a.cases || a.cve.localeCompare(b.cve)).slice(0, size);
}

function BarList({ rows, label }: { rows: { label: string; count: number }[]; label: string }) {
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <ul className="bsoc-bars" aria-label={label}>
      {rows.map((row) => (
        <li key={row.label}>
          <span className="bsoc-bar-label">{row.label}</span>
          <span className="bsoc-bar-track" aria-hidden="true"><span className="bsoc-bar-fill" style={{ width: `${Math.round((row.count / max) * 100)}%` }} /></span>
          <strong className="bsoc-bar-value">{row.count.toLocaleString("pt-BR")}</strong>
        </li>
      ))}
    </ul>
  );
}
