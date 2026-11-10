"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import type { Session } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import { WorkspaceNav } from "@/src/components/workspace-nav";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";

type Access = "checking" | "allowed" | "denied" | "error";
export type BookClient = { id: string; name: string; alerts: boolean };
export type FrameContext = { token: string; client: BookClient };
export type BookSection = "visao" | "alertas";

const TABS: { id: BookSection; label: string; path: string }[] = [
  { id: "visao", label: "Visão executiva", path: "/book-soc" },
  { id: "alertas", label: "Alertas", path: "/book-soc/alertas" },
];

// Casca comum das páginas do Book SOC: sessão, acesso interno, lista de clientes e navegação.
// O login do PierVuln só identifica a equipe interna; os dados do Book vêm direto do Wazuh pelo servidor.
export function BookSocFrame({ section, subtitle, children }: {
  section: BookSection; subtitle: string; children: (context: FrameContext) => ReactNode;
}) {
  const supabase = getSupabaseBrowserClient();
  const [session, setSession] = useState<Session | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [access, setAccess] = useState<Access>("checking");
  const [clients, setClients] = useState<BookClient[]>([]);
  const [clientId, setClientId] = useState("");
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    if (!supabase) return;
    let mounted = true;
    void supabase.auth.getSession().then(({ data }) => { if (mounted) { setSession(data.session); setAuthReady(true); } });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, next) => { if (mounted) { setSession(next); setAuthReady(true); } });
    return () => { mounted = false; listener.subscription.unsubscribe(); };
  }, [supabase]);

  useEffect(() => {
    if (!supabase || !session) return;
    let mounted = true;
    void supabase.rpc("current_user_context").then(({ data, error }) => {
      if (mounted) setAccess(error ? "error" : (data as { is_internal_admin?: boolean } | null)?.is_internal_admin === true ? "allowed" : "denied");
    });
    return () => { mounted = false; };
  }, [supabase, session]);

  const token = session?.access_token;

  useEffect(() => {
    if (access !== "allowed" || !token) return;
    let mounted = true;
    void fetch("/api/book-soc/clients", { headers: { authorization: `Bearer ${token}` } })
      .then((response) => (response.ok ? response.json() : null))
      .then((body: { clients?: BookClient[] } | null) => {
        if (!mounted) return;
        if (!body?.clients) { setLoadError("Não foi possível carregar a lista de clientes."); return; }
        setClients(body.clients);
        const wanted = new URLSearchParams(window.location.search).get("cliente");
        if (wanted && body.clients.some((item) => item.id === wanted)) setClientId(wanted);
      })
      .catch(() => { if (mounted) setLoadError("Não foi possível carregar a lista de clientes."); });
    return () => { mounted = false; };
  }, [access, token]);

  function choose(id: string) {
    setClientId(id);
    const url = new URL(window.location.href);
    if (id) url.searchParams.set("cliente", id); else url.searchParams.delete("cliente");
    window.history.replaceState(null, "", `${url.pathname}${url.search}`);
  }

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

  if (!supabase) return shell(<p className="inline-alert" role="alert">Configure a conexão pública com o Supabase para abrir esta página.</p>);
  if (!authReady) return shell(<div className="admin-loading" role="status"><div className="spinner" />Verificando sessão…</div>);
  if (!session) return shell(<section className="auth-card"><h1>Book SOC</h1><p>Entre com a conta da equipe para continuar.</p><Link className="button button-primary" href="/login">Entrar</Link></section>);
  if (access === "checking") return shell(<div className="admin-loading" role="status"><div className="spinner" />Verificando acesso…</div>);
  if (access !== "allowed") return shell(<section className="auth-card"><h1>{access === "error" ? "Não foi possível verificar o acesso" : "Acesso restrito"}</h1><p>Esta área é exclusiva da equipe Pier.</p></section>);

  const selected = clients.find((item) => item.id === clientId);
  const query = clientId ? `?cliente=${encodeURIComponent(clientId)}` : "";

  return shell(
    <div className="bsoc-page">
      <header className="bsoc-head">
        <h1>Book SOC</h1>
        <p>{subtitle}</p>
      </header>

      <nav className="bsoc-tabs" aria-label="Seções do Book SOC">
        {TABS.map((tab) => (
          <Link key={tab.id} href={`${tab.path}${query}`} aria-current={tab.id === section ? "page" : undefined} className={tab.id === section ? "active" : undefined}>{tab.label}</Link>
        ))}
      </nav>

      <form className="bsoc-card bsoc-context" aria-label="Cliente" onSubmit={(event) => event.preventDefault()}>
        <label htmlFor="bsoc-client">Cliente</label>
        <select id="bsoc-client" value={clientId} onChange={(event) => choose(event.target.value)}>
          <option value="">Selecione um cliente</option>
          {clients.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
        </select>
      </form>

      {loadError && <div className="inline-alert" role="alert">{loadError}</div>}
      {selected && token && children({ token, client: selected })}
    </div>,
  );
}
