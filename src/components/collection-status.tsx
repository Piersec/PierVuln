"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import type { User } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import { NavSymbol } from "@/src/components/ui/nav-symbol";
import { UserAvatar } from "@/src/components/user-avatar";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { visibleText } from "@/src/lib/visible-text";

type Connection = { id: string; name: string; is_active: boolean };
type SyncRun = {
  id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  documents_received: number;
  pages_received: number;
};
type Source = { connection: Connection; latest: SyncRun | null; lastSuccess: SyncRun | null };
type Health = "healthy" | "running" | "warning" | "paused" | "empty";

const staleAfterMs = 2 * 60 * 60 * 1000;
const runningAfterMs = 10 * 60 * 1000;

function sourceHealth(source: Source, now: number): Health {
  if (!source.connection.is_active) return "paused";
  if (source.latest?.status === "running") {
    if (now - Date.parse(source.latest.started_at) >= runningAfterMs) return "warning";
    if (!source.lastSuccess || now - Date.parse(source.lastSuccess.finished_at ?? source.lastSuccess.started_at) > staleAfterMs) return "warning";
    return "running";
  }
  if (source.latest && ["failed", "partial"].includes(source.latest.status)) return "warning";
  if (!source.lastSuccess) return "empty";
  return now - Date.parse(source.lastSuccess.finished_at ?? source.lastSuccess.started_at) > staleAfterMs
    ? "warning" : "healthy";
}

function healthLabel(health: Health): string {
  return ({ healthy: "Em dia", running: "Sincronizando", warning: "Atenção", paused: "Pausada", empty: "Sem leitura completa" })[health];
}

function runLabel(status: string): string {
  return ({ succeeded: "Concluída", running: "Em andamento", failed: "Falhou", partial: "Parcial" } as Record<string, string>)[status] ?? "Indefinido";
}

function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : new Intl.DateTimeFormat("pt-BR", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function CollectionStatus() {
  const client = getSupabaseBrowserClient();
  const requestId = useRef(0);
  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [isInternal, setIsInternal] = useState(false);
  const [sources, setSources] = useState<Source[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async (showRefresh = false) => {
    if (!client) return;
    const currentRequest = ++requestId.current;
    if (showRefresh) setRefreshing(true);
    setError("");

    const { data: connections, error: connectionsError } = await client.from("wazuh_connections")
      .select("id,name,is_active").order("name");
    if (currentRequest !== requestId.current) return;
    if (connectionsError) {
      setError("Não foi possível consultar as fontes. Tente atualizar a página.");
      setLoading(false);
      setRefreshing(false);
      return;
    }

    const results = await Promise.all((connections ?? []).map(async (connection) => {
      const [latest, lastSuccess] = await Promise.all([
        client.from("sync_runs").select("id,status,started_at,finished_at,documents_received,pages_received")
          .eq("connection_id", connection.id).order("started_at", { ascending: false }).limit(1).maybeSingle(),
        client.from("sync_runs").select("id,status,started_at,finished_at,documents_received,pages_received")
          .eq("connection_id", connection.id).eq("status", "succeeded").eq("full_snapshot", true)
          .order("started_at", { ascending: false }).limit(1).maybeSingle(),
      ]);
      if (latest.error || lastSuccess.error) throw new Error("sync_runs");
      return { connection, latest: latest.data, lastSuccess: lastSuccess.data } as Source;
    }));
    if (currentRequest !== requestId.current) return;
    setSources(results);
    setCheckedAt(new Date().toISOString());
    setNow(Date.now());
    setLoading(false);
    setRefreshing(false);
  }, [client]);

  useEffect(() => {
    if (!client) { setAuthReady(true); setLoading(false); return; }
    let active = true;
    void client.auth.getUser().then(async ({ data, error: authError }) => {
      if (!active) return;
      setUser(authError ? null : data.user);
      setAuthReady(true);
      if (data.user && !authError) {
        const context = await client.rpc("current_user_context");
        if (active && !context.error) setIsInternal(context.data?.is_internal_admin === true);
      }
    });
    const { data: listener } = client.auth.onAuthStateChange((event, session) => {
      if (!active) return;
      if (event === "SIGNED_OUT") { setUser(null); setIsInternal(false); }
      if (event === "SIGNED_IN" && session) setUser(session.user);
    });
    return () => { active = false; requestId.current += 1; listener.subscription.unsubscribe(); };
  }, [client]);

  useEffect(() => {
    if (!user) return;
    void load().catch(() => { setError("Não foi possível consultar as sincronizações. Tente novamente."); setLoading(false); setRefreshing(false); });
    const timer = window.setInterval(() => { if (!document.hidden) void load().catch(() => setError("Não foi possível atualizar o status.")); }, 60_000);
    const onVisibility = () => { if (!document.hidden) void load().catch(() => setError("Não foi possível atualizar o status.")); };
    document.addEventListener("visibilitychange", onVisibility);
    return () => { requestId.current += 1; window.clearInterval(timer); document.removeEventListener("visibilitychange", onVisibility); };
  }, [load, user]);

  const healthyCount = sources.filter((source) => ["healthy", "running"].includes(sourceHealth(source, now))).length;
  const allHealthy = sources.length > 0 && healthyCount === sources.length;
  const overall = sources.length === 0 ? "Sem conexões" : allHealthy ? "Todas as conexões saudáveis" : "Conexões requerem atenção";
  const overallTone = sources.length === 0 ? "empty" : allHealthy ? "healthy" : "warning";
  const latestComplete = sources.map((source) => source.lastSuccess).filter((run): run is SyncRun => Boolean(run))
    .sort((a, b) => Date.parse(b.finished_at ?? b.started_at) - Date.parse(a.finished_at ?? a.started_at))[0];

  if (!client) return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Configuração necessária</h1><p>O projeto Supabase não está configurado neste ambiente.</p></section></main>;
  if (!authReady) return <main className="loading-screen"><Brand /><div className="spinner" /><p>Verificando acesso…</p></main>;
  if (!user) return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Entre para ver o status</h1><p>O estado da coleta está disponível para usuários autorizados.</p><Link className="button button-primary" href="/login">Entrar</Link></section></main>;

  return <main className="app-shell">
    <a className="skip-link" href="#status-content">Pular para o conteúdo</a>
    <aside className={`sidebar${isInternal ? " has-admin" : ""}`}>
      <Brand />
      <nav className="workspace-nav" aria-label="Navegação principal">
        <Link className="nav-link" href="/" aria-label="Vulnerabilidades" title="Vulnerabilidades"><NavSymbol kind="vulnerabilities" /><span className="nav-label">Vulnerabilidades</span></Link>
        <Link className="nav-link" href="/book" aria-label="Book dos Clientes" title="Book dos Clientes"><NavSymbol kind="book" /><span className="nav-label">Book dos Clientes</span></Link>
        <Link className="nav-link active" href="/status" aria-current="page" aria-label="Status" title="Status"><NavSymbol kind="status" /><span className="nav-label">Status</span></Link>
        {isInternal && <Link className="nav-link" href="/admin" aria-label="Administração" title="Administração"><NavSymbol kind="admin" /><span className="nav-label">Administração</span></Link>}
        <Link className="nav-link" href="/settings" aria-label="Configurações" title="Configurações"><NavSymbol kind="settings" /><span className="nav-label">Configurações</span></Link>
      </nav>
      <div className="sidebar-bottom"><UserAvatar userId={user.id} fallback={user.email ?? "U"} /><div className="user-info"><strong>{visibleText(user.email)}</strong><span>{isInternal ? "Equipe Pier" : "Cliente"}</span></div><button className="sidebar-signout" onClick={() => void client.auth.signOut()}>Sair</button></div>
    </aside>
    <section className="main-column" id="status-content" tabIndex={-1}>
      <header className="topbar"><div className="breadcrumb">PierVuln <span>/</span> <strong>Status</strong></div><div className="topbar-actions"><span className="status-checked">Consultado: {formatDate(checkedAt)}</span><button className="button button-secondary refresh-button" disabled={refreshing} onClick={() => void load(true).catch(() => { setError("Não foi possível atualizar o status."); setRefreshing(false); })}>{refreshing ? "Atualizando…" : "Atualizar"}</button></div></header>
      <div className="content-wrap status-page">
        <div className="page-heading"><div><span className="page-kicker">FONTE DE DADOS / WAZUH</span><h1>Status da coleta</h1><p>Acompanhe as leituras completas que alimentam o PierVuln.</p></div></div>
        {error && <p className="status-error" role="alert">{error}</p>}
        {loading ? <div className="admin-loading" role="status"><div className="spinner" />Consultando sincronizações…</div> : <>
          <section className={`status-overview status-${overallTone}`} aria-label="Resumo da coleta">
            <div><span className="status-overview-kicker">ESTADO GERAL</span><div className="status-overview-title"><span className="status-overview-dot" aria-hidden="true" /><h2>{overall}</h2></div><p>Baseado nas sincronizações registradas. Não representa um teste instantâneo da VPN.</p></div>
            <div className="status-overview-facts"><div><span>Conexões saudáveis</span><strong>{healthyCount} / {sources.length}</strong></div><div><span>Última leitura completa</span><strong>{formatDate(latestComplete?.finished_at)}</strong></div></div>
          </section>
          <div className="status-section-heading"><h2>Fontes</h2><span>{sources.length} {sources.length === 1 ? "fonte visível" : "fontes visíveis"}</span></div>
          {sources.length === 0 ? <section className="status-empty"><h3>Nenhuma fonte disponível</h3><p>Não há uma conexão do Wazuh vinculada à sua conta.</p></section> : <div className="status-source-list">{sources.map((source) => {
            const health = sourceHealth(source, now);
            const complete = source.lastSuccess;
            return <article className="status-source" key={source.connection.id}>
              <div className="status-source-heading"><div><span className="status-source-kicker">WAZUH INDEXER</span><h3>{visibleText(source.connection.name)}</h3></div><span className={`status-pill status-${health}`}><span aria-hidden="true" />{healthLabel(health)}</span></div>
              <div className="status-source-facts"><div><span>Última leitura completa</span><strong>{formatDate(complete?.finished_at)}</strong></div><div><span>Documentos recebidos</span><strong>{complete ? complete.documents_received.toLocaleString("pt-BR") : "—"}</strong></div><div><span>Páginas recebidas</span><strong>{complete ? complete.pages_received.toLocaleString("pt-BR") : "—"}</strong></div><div><span>Última tentativa</span><strong>{source.latest ? `${runLabel(source.latest.status)} · ${formatDate(source.latest.finished_at ?? source.latest.started_at)}` : "—"}</strong></div></div>
            </article>;
          })}</div>}
          <p className="status-method">Uma fonte ativa aparece em dia quando a última leitura completa ocorreu nas últimas 2 horas. A página atualiza a cada minuto enquanto estiver aberta.</p>
        </>}
      </div>
    </section>
  </main>;
}
