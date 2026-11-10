"use client";

import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import Link from "next/link";
import type { Session } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import { WorkspaceNav } from "@/src/components/workspace-nav";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";

type Access = "checking" | "allowed" | "denied" | "error";
type Result = {
  total: number;
  porSeveridade: { severidade: string; registros: number }[];
  porCve: { cve: string; registros: number }[];
  porAgente: { agente: string; registros: number }[];
  consultadoEm: string;
};

export function BookSocOverview() {
  const client = getSupabaseBrowserClient();
  const [session, setSession] = useState<Session | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [access, setAccess] = useState<Access>("checking");
  const [companies, setCompanies] = useState<{ id: string; name: string }[]>([]);
  const [companyId, setCompanyId] = useState("");
  const [result, setResult] = useState<Result | null>(null);
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
      if (mounted && data) setCompanies(data as { id: string; name: string }[]);
    });
    return () => { mounted = false; };
  }, [client, access]);

  async function consult(event: FormEvent) {
    event.preventDefault();
    if (!session) return;
    setLoading(true); setError("");
    try {
      const response = await fetch("/api/book-soc/overview", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify(companyId ? { companyId } : {}),
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) throw new Error(body?.error ?? "Não foi possível concluir a consulta.");
      setResult(body as Result);
    } catch (caught) {
      setResult(null);
      setError(caught instanceof Error ? caught.message : "Não foi possível concluir a consulta.");
    } finally {
      setLoading(false);
    }
  }

  const shell = (content: ReactNode) => (
    <main className="app-shell">
      <a className="skip-link" href="#book-soc-content">Pular para o conteúdo</a>
      <aside className="sidebar"><Brand /><WorkspaceNav isInternal={access === "allowed"} /></aside>
      <section className="main-column">
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
      <header className="page-heading">
        <h1>Visão executiva · vulnerabilidades</h1>
        <p className="muted-copy">Estado atual das vulnerabilidades no Wazuh. Nenhum documento individual é exibido nesta tela.</p>
      </header>

      <form className="panel" onSubmit={consult} aria-label="Escopo da consulta">
        <label>Empresa
          <select value={companyId} onChange={(e) => setCompanyId(e.target.value)}>
            <option value="">Todas as conexões</option>
            {companies.map((company) => <option key={company.id} value={company.id}>{company.name}</option>)}
          </select>
        </label>
        <button className="button button-primary" disabled={loading}>{loading ? "Consultando…" : "Consultar Wazuh"}</button>
      </form>

      {error && <div className="inline-alert" role="alert">{error}</div>}

      {result && (
        <>
          <section className="panel" aria-label="Total">
            <p className="eyebrow">Registros de vulnerabilidade</p>
            <strong className="metric">{result.total.toLocaleString("pt-BR")}</strong>
            <p className="muted-copy">Consultado em {new Date(result.consultadoEm).toLocaleString("pt-BR")}</p>
          </section>
          <div className="book-soc-grid">
            <BreakdownTable title="Por severidade" label="Severidade" rows={result.porSeveridade.map((r) => ({ key: r.severidade, count: r.registros }))} />
            <BreakdownTable title="Principais CVEs" label="CVE" rows={result.porCve.map((r) => ({ key: r.cve, count: r.registros }))} />
            <BreakdownTable title="Principais agentes" label="Agente" rows={result.porAgente.map((r) => ({ key: r.agente, count: r.registros }))} />
          </div>
        </>
      )}
    </>,
  );
}

function BreakdownTable({ title, label, rows }: { title: string; label: string; rows: { key: string; count: number }[] }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {rows.length === 0 ? <p className="muted-copy">Nenhum registro encontrado.</p> : (
        <table>
          <thead><tr><th scope="col">{label}</th><th scope="col">Registros</th></tr></thead>
          <tbody>{rows.map((row) => <tr key={row.key}><td>{row.key}</td><td>{row.count.toLocaleString("pt-BR")}</td></tr>)}</tbody>
        </table>
      )}
    </section>
  );
}
