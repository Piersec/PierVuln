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
    <>
      <header className="bsoc-head">
        <h1>Book SOC</h1>
        <p>Visão executiva · estado atual das vulnerabilidades</p>
      </header>

      <form className="bsoc-context" aria-label="Empresa" onSubmit={(event) => event.preventDefault()}>
        <label>Empresa
          <select value={companyId} onChange={(event) => setCompanyId(event.target.value)}>
            <option value="">Selecione uma empresa</option>
            {companies.map((company) => <option key={company.id} value={company.id}>{company.name}</option>)}
          </select>
        </label>
      </form>

      {error && <div className="inline-alert" role="alert">{error}</div>}
      {loading && <div className="admin-loading" role="status"><div className="spinner" />Carregando indicadores…</div>}

      {overview && !loading && (
        <>
          <div className="bsoc-hero">
            <section className="bsoc-highlight" aria-label="Destaque">
              <span className="bsoc-label">Destaque da visão</span>
              <strong className="bsoc-big">{overview.activeCount.toLocaleString("pt-BR")}</strong>
              <p className="bsoc-caption">registros de vulnerabilidade ativos nesta empresa</p>
            </section>
            <section className="bsoc-coverage" aria-label="Situação atual">
              <h2>Situação atual</h2>
              <div className="bsoc-stats">
                <div><strong>{overview.criticalHighCount.toLocaleString("pt-BR")}</strong><span>críticas e altas</span></div>
                <div><strong>{overview.inProgressCount.toLocaleString("pt-BR")}</strong><span>em andamento</span></div>
                <div><strong>{overview.corrected30.toLocaleString("pt-BR")}</strong><span>corrigidas em 30 dias</span></div>
              </div>
              <p className="bsoc-note">Estado atual lido do banco do PierVuln; não representa o fechamento histórico do mês.</p>
            </section>
          </div>
          <section className="book-chart-section">
            <div className="book-section-heading"><div><span className="book-section-tag">DISTRIBUIÇÃO POR SEVERIDADE</span><h2>Registros por severidade</h2></div></div>
            <div className="book-table-scroll">
              <table className="book-top-table">
                <thead><tr><th scope="col">Severidade</th><th scope="col">Registros</th></tr></thead>
                <tbody>{Object.entries(overview.severityCounts).map(([severity, count]) => <tr key={severity}><td>{severity}</td><td>{Number(count).toLocaleString("pt-BR")}</td></tr>)}</tbody>
              </table>
            </div>
            <p className="book-table-note">Estado atual lido do banco do PierVuln, com isolamento por empresa. Não representa o fechamento histórico do mês.</p>
          </section>
        </>
      )}
    </>,
  );
}
