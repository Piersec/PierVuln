"use client";
import { CertificateInput } from "@/src/components/certificate-input";

import Link from "next/link";
import { TriangleAlert } from "lucide-react";
import { Label, Meter, ProgressBar } from "@heroui/react";
import { trackSpotlight } from "@/src/components/ui/spotlight-card";
import { usePathname } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import type { Session, SupabaseClient } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import { NavSymbol } from "@/src/components/ui/nav-symbol";
import { AnimatedCounter } from "@/src/components/ui/animated-counter";
import { ProfileMenu } from "@/src/components/profile-menu";
import { useSiteNotifications } from "@/src/components/site-notifications";
import { useErrorNotice } from "@/src/lib/use-filter-notice";
import { type NoticeInput } from "@/src/lib/admin-notifications";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { AdminRequestError, adminDate, archiveLabels, formatStorageBytes, invokeAdmin, roleLabels, syncLabels, type AdminArchive, type AdminCompany, type AdminConnection, type AdminData, type AdminMapping, type AdminMembership, type CompanyStorageUsage } from "@/src/lib/admin";
import { visibleText } from "@/src/lib/visible-text";
import { CompanyDataDeletionDialog } from "@/src/components/company-data-deletion-dialog";
import { BattleDashboard, type BattleCompany } from "@/src/components/battle-dashboard";

type Section = "dashboard" | "tenants" | "battle" | "integrations" | "users" | "audit";
const DATABASE_LIMIT_BYTES = 500_000_000;
type SyncMeasurement = {
  id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  pages_received: number;
  documents_received: number;
  full_snapshot: boolean;
  error_summary: string | null;
};
const sections: { key: Section; label: string; href: string }[] = [
  { key: "dashboard", label: "Visão geral", href: "/admin" },
  { key: "tenants", label: "Empresas", href: "/admin/tenants" },
  { key: "integrations", label: "Integrações", href: "/admin/integrations" },
  { key: "users", label: "Usuários", href: "/admin/users" },
  { key: "audit", label: "Auditoria", href: "/admin/audit" },
];
type Notice = NoticeInput;
type Context = {
  client: SupabaseClient; data: AdminData | null; loading: boolean; busy: boolean; loadError: string;
  query: { search: string; scope: string; page: number }; setQuery: (query: Context["query"]) => void;
  reload: () => Promise<void>; notify: (notice: Notice) => void;
  setIslandHost: (host: HTMLElement | null) => void;
  run: (payload: Record<string, unknown>, title: string) => Promise<Record<string, unknown> | null>;
};
const AdminContext = createContext<Context | null>(null);
function useAdmin() { const value = useContext(AdminContext); if (!value) throw new Error("Admin workspace required"); return value; }

export function AdminWorkspace({ children }: { children: ReactNode }) {
  const client = getSupabaseBrowserClient();
  const pathname = usePathname();
  const battlePage = pathname === "/battle";
  const [session, setSession] = useState<Session | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [access, setAccess] = useState<"checking" | "allowed" | "denied" | "error">("checking");
  const [data, setData] = useState<AdminData | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState("");
  const { notify, clear, setIslandHost, beginMutation, endMutation, revision } = useSiteNotifications();
  useErrorNotice(loadError, "admin-feedback");
  const [query, setQuery] = useState({ search: "", scope: "", page: 0 });
  const requestId = useRef(0);
  const mutationLock = useRef(false);
  const currentUser = useRef<string | null>(null);
  const reloadRef = useRef<() => Promise<void>>(async () => {});

  useEffect(() => {
    if (!client) return;
    let mounted = true;
    void client.auth.getSession().then(({ data: auth }) => { if (mounted) { setSession(auth.session); setAuthReady(true); } });
    const { data: listener } = client.auth.onAuthStateChange((event, next) => {
      if (event === "PASSWORD_RECOVERY") { window.location.replace("/reset-password?mode=update"); return; }
      if (mounted) { setSession(next); setAuthReady(true); }
    });
    return () => { mounted = false; listener.subscription.unsubscribe(); };
  }, [client]);

  useEffect(() => {
    currentUser.current = session?.user.id ?? null;
    setData(null); setAccess("checking"); requestId.current += 1;
    if (!client || !session?.user.id) return;
    let mounted = true;
    void client.rpc("current_user_context").then(({ data: context, error }) => {
      if (mounted) setAccess(error ? "error" : context?.is_internal_admin === true ? "allowed" : "denied");
    });
    return () => { mounted = false; };
  }, [client, session?.user.id]);

  const reload = useCallback(async (manual = false) => {
    if (!client || access !== "allowed") return;
    const id = ++requestId.current;
    setLoading(true); setLoadError("");
    if (manual) notify({ title: "Atualizando administração…", key: "admin-feedback" });
    try {
      const next = await invokeAdmin<AdminData>(client, { action: "panel_data", ...query });
      if (id === requestId.current) { setData(next); if (manual) notify({ title: "Dados administrativos atualizados.", key: "admin-feedback" }); }
    } catch (error) {
      if (id === requestId.current) {
        setLoadError((error as Error).message);
        if (error instanceof AdminRequestError && (error.status === 401 || error.status === 403)) { setAccess("denied"); setData(null); clear(); }
      }
    }
    finally { if (id === requestId.current) setLoading(false); }
  }, [access, clear, client, notify, query]);
  reloadRef.current = reload;

  useEffect(() => { const timer = setTimeout(() => void reload(), 250); return () => clearTimeout(timer); }, [reload]);

  useEffect(() => {
    const timer = setTimeout(() => void reloadRef.current(), 400);
    return () => clearTimeout(timer);
  }, [revision]);

  async function run(payload: Record<string, unknown>, title: string) {
    if (!client || mutationLock.current || access !== "allowed") return null;
    mutationLock.current = true; beginMutation(); setBusy(true);
    const actor = currentUser.current;
    try {
      const result = await invokeAdmin(client, payload);
      if (actor !== currentUser.current) return null;
      const entityId = result.entityId ?? result.id ?? result.connectionId ?? result.mappingId ?? payload.id ?? payload.mappingId;
      endMutation(typeof entityId === "string" ? entityId : undefined);
      notify({ title, secret: typeof result.ingestToken === "string" ? result.ingestToken : undefined });
      await reload(); return result;
    } catch (error) {
      if (actor === currentUser.current) {
        if (error instanceof AdminRequestError && (error.status === 401 || error.status === 403)) { setAccess("denied"); setData(null); clear(); }
        else notify({ title: (error as Error).message, error: true });
      }
      return null;
    }
    finally { mutationLock.current = false; endMutation(); setBusy(false); }
  }

  async function signOut() {
    if (!client) return;
    const { error } = await client.auth.signOut();
    if (error) notify({ title: "Não foi possível encerrar a sessão.", error: true, key: "auth-session" });
    else { setData(null); setAccess("checking"); }
  }

  if (!client) return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Configuração necessária</h1><p>Configure a conexão pública com o Supabase para abrir o painel.</p></section></main>;
  if (!authReady || (session && access === "checking")) return <main className="loading-screen"><Brand /><div className="spinner" /><p>Verificando acesso administrativo…</p></main>;
  if (!session) return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Administração Pier</h1><p>Entre com a conta da equipe para continuar.</p><Link className="button button-primary" href="/login">Entrar</Link></section></main>;
  if (access !== "allowed") return <main className="auth-shell"><section className="auth-card"><Brand /><h1>{access === "error" ? "Não foi possível verificar o acesso" : "Acesso restrito"}</h1><p>Esta área é exclusiva da equipe Pier.</p><Link className="button button-secondary" href="/dashboard">Voltar ao painel</Link>{access === "error" && <button className="button button-secondary" onClick={() => window.location.reload()}>Tentar novamente</button>}</section></main>;

  return <AdminContext.Provider value={{ client, data, loading, busy, loadError, query, setQuery, reload, notify, run, setIslandHost }}>
    <main className={`app-shell${battlePage ? "" : " admin-shell"}`}>
      <a className="skip-link" href="#admin-content">Pular para o conteúdo</a>
      <aside className="sidebar has-admin"><Brand /><nav className="workspace-nav" aria-label="Navegação principal">
        <Link className="nav-link" href="/dashboard" aria-label="Vulnerabilidades" title="Vulnerabilidades"><NavSymbol kind="vulnerabilities" /></Link>
        <Link className="nav-link" href="/cases" aria-label="Casos" title="Casos de vulnerabilidade"><NavSymbol kind="cases" /></Link>
        <Link className="nav-link" href="/assets" aria-label="Ativos" title="Ativos"><NavSymbol kind="assets" /></Link>
        <Link className="nav-link" href="/book" aria-label="Book dos Clientes" title="Book dos Clientes"><NavSymbol kind="book" /></Link>
        <Link className={`nav-link${battlePage ? " active" : ""}`} href="/battle" aria-current={battlePage ? "page" : undefined} aria-label="Batalha" title="Batalha"><NavSymbol kind="battle" /><span className="nav-label">Batalha</span></Link>
      </nav><div className="sidebar-bottom"><ProfileMenu userId={session.user.id} fallback={session.user.email ?? "U"} isInternal={true} /><button className="sidebar-signout" onClick={() => void signOut()}>Sair</button></div></aside>
      <section className="main-column"><header className="topbar"><div className="breadcrumb">{battlePage ? "PierVuln" : "ADMIN"} <span>/</span><strong>{battlePage ? "Batalha" : sections.find((s) => s.href === pathname)?.label ?? "Administração"}</strong></div><button className="button button-secondary" disabled={loading} onClick={() => void reload(true)}>{loading ? "Atualizando…" : "Atualizar"}</button></header>
        <div className="content-wrap admin-content" id="admin-content" tabIndex={-1}>
          {!battlePage && <nav className="admin-tabs" aria-label="Administração">{sections.map((s) => <Link href={s.href} key={s.key} className={pathname === s.href ? "active" : ""} aria-current={pathname === s.href ? "page" : undefined}>{s.label}</Link>)}</nav>}
          {loadError && <div className="inline-alert" role="alert">{loadError}<button className="button button-secondary" onClick={() => void reload(true)}>Tentar novamente</button></div>}
          {loading && !data ? <div className="admin-loading" role="status"><div className="spinner" />Carregando dados administrativos…</div> : data && children}
        </div>
      </section>
    </main>
  </AdminContext.Provider>;
}

type Editor = { kind: "company"; company?: AdminCompany } | { kind: "delete-company"; company: AdminCompany } | { kind: "connection"; connection?: AdminConnection } | { kind: "delete-connection"; connection: AdminConnection } | { kind: "connection-credentials"; connection: AdminConnection; nextCompany?: AdminCompany } | { kind: "connection-ca"; connection: AdminConnection } | { kind: "asset-api-endpoint"; connection: AdminConnection; nextCompany?: AdminCompany } | { kind: "asset-api"; connection: AdminConnection; company: AdminCompany } | { kind: "invite" } | { kind: "mapping"; connectionId: string; mapping?: AdminMapping } | { kind: "delete-mapping"; mapping: AdminMapping } | { kind: "shared-company"; connectionId: string } | { kind: "membership"; membership: AdminMembership; email: string } | { kind: "toggle"; entity: "company" | "connection"; id: string; name: string; active: boolean };

export function AdminSection({ section }: { section: Section }) {
  const { data, client, busy, query, setQuery, run, notify, reload } = useAdmin();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [companyFilter, setCompanyFilter] = useState("");
  const [editor, setEditor] = useState<Editor | null>(null);
  const [archiveLink, setArchiveLink] = useState<{ id: string; url: string } | null>(null);
  const [downloadBusy, setDownloadBusy] = useState<string | null>(null);
  const [syncHistory, setSyncHistory] = useState<Record<string, SyncMeasurement[]>>({});
  const [syncNow, setSyncNow] = useState(() => Date.now());
  const [storageUsage, setStorageUsage] = useState<CompanyStorageUsage | null>(null);
  const [storageError, setStorageError] = useState(false);
  const [storageNow, setStorageNow] = useState(() => Date.now());
  const [deleteCompany, setDeleteCompany] = useState<AdminCompany | null>(null);
  const [battle, setBattle] = useState<BattleCompany[] | null>(null);
  const [battleError, setBattleError] = useState("");
  const [battleRetry, setBattleRetry] = useState(0);
  const connectionIds = data?.connections.map((connection) => connection.id).sort().join(",") ?? "";

  useEffect(() => {
    if (section !== "battle") return;
    let active = true;
    void invokeAdmin<{ companies: BattleCompany[] }>(client, { action: "battle_data" })
      .then((result) => { if (active) { setBattle(result.companies); setBattleError(""); } })
      .catch((error) => { if (active) setBattleError((error as Error).message); });
    return () => { active = false; };
  }, [client, data, section, battleRetry]);

  useEffect(() => {
    if (section !== "tenants") return;
    let active = true;
    let pending = false;
    let controller: AbortController | undefined;
    async function loadStorage() {
      if (pending || document.visibilityState === "hidden") return;
      pending = true;
      controller = new AbortController();
      const timeout = setTimeout(() => controller?.abort(), 10_000);
      try {
        const { data: result, error } = await client.rpc("get_company_storage_usage").abortSignal(controller.signal);
        if (!active) return;
        setStorageError(Boolean(error));
        if (!error && result) setStorageUsage(result as CompanyStorageUsage);
        setStorageNow(Date.now());
      } catch {
        if (active) setStorageError(true);
      } finally {
        clearTimeout(timeout);
        pending = false;
      }
    }
    void loadStorage();
    const timer = setInterval(() => void loadStorage(), 15_000);
    const onVisibility = () => { if (document.visibilityState === "visible") void loadStorage(); };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      active = false;
      controller?.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [client, data, section]);

  useEffect(() => {
    if ((section !== "dashboard" && section !== "integrations") || !connectionIds) {
      setSyncHistory({});
      return;
    }
    const ids = connectionIds.split(",");
    let active = true;
    let debounce: ReturnType<typeof setTimeout> | undefined;
    async function loadHistory() {
      const columns = "id,connection_id,status,started_at,finished_at,pages_received,documents_received,full_snapshot,error_summary";
      const [attempts, completions] = await Promise.all([
        client.from("sync_runs").select(columns).in("connection_id", ids)
          .order("started_at", { ascending: false }).limit(Math.min(ids.length * 16, 200)),
        client.from("sync_runs").select(columns).in("connection_id", ids)
          .eq("status", "succeeded").eq("full_snapshot", true)
          .order("started_at", { ascending: false }).limit(Math.min(ids.length * 5, 200)),
      ]);
      if (!active || attempts.error || completions.error) return;
      const grouped: Record<string, SyncMeasurement[]> = {};
      const uniqueRows = new Map<string, (typeof attempts.data)[number]>();
      for (const row of [...(attempts.data ?? []), ...(completions.data ?? [])]) uniqueRows.set(row.id, row);
      for (const row of uniqueRows.values()) {
        const run = row as typeof row & { connection_id: string };
        (grouped[run.connection_id] ??= []).push(run as unknown as SyncMeasurement);
      }
      for (const runs of Object.values(grouped)) runs.sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at));
      setSyncHistory(grouped);
      setSyncNow(Date.now());
    }
    const request = () => {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(() => void loadHistory(), 500);
    };
    void loadHistory();
    const channel = client.channel(`sync-metrics-${ids.join("-")}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "sync_runs" }, request)
      .subscribe();
    const clock = setInterval(() => setSyncNow(Date.now()), 15_000);
    const fallback = setInterval(request, 30_000);
    return () => {
      active = false;
      if (debounce) clearTimeout(debounce);
      clearInterval(clock);
      clearInterval(fallback);
      void client.removeChannel(channel);
    };
  }, [client, connectionIds, section]);
  if (!data) return null;
  const companyName = (id: string | null) => visibleText(data.companies.find((c) => c.id === id)?.name ?? "Compartilhada");
  const matches = (value: string) => value.toLocaleLowerCase("pt-BR").includes(search.toLocaleLowerCase("pt-BR"));
  const companies = data.companies.filter((c) => matches(`${visibleText(c.name)} ${c.slug}`) && (!status || String(c.is_active) === status));
  const connections = data.connections.filter((c) => matches(`${visibleText(c.name)} ${visibleText(c.endpoint_url)} ${companyName(c.tenant_id)} ${data.mappings.filter((m) => m.connection_id === c.id).map((m) => `${companyName(m.tenant_id)} ${m.match_value}`).join(" ")}`) && (!status || String(c.is_active) === status)
    && (!companyFilter || c.tenant_id === companyFilter || data.mappings.some((m) => m.connection_id === c.id && m.tenant_id === companyFilter)));

  async function download(archive: AdminArchive) {
    setDownloadBusy(archive.id); setArchiveLink(null);
    try {
      const { data: link, error } = await client.storage.from(archive.bucket_name).createSignedUrl(archive.object_path, 300, { download: `${archive.id}.json.gz` });
      if (error || !link?.signedUrl) throw new Error("Não foi possível preparar o download do arquivo.");
      setArchiveLink({ id: archive.id, url: link.signedUrl }); notify({ title: "Download preparado. O link vale por cinco minutos.", key: "archive-download" });
    } catch (error) { notify({ title: (error as Error).message, error: true }); }
    finally { setDownloadBusy(null); }
  }

  return <>
    <div className="page-heading"><div><h1>{section === "battle" ? "Batalha" : sections.find((s) => s.key === section)?.label}</h1><p>{({ dashboard: "Clientes, acessos e status das fontes de dados.", tenants: "Gerencie empresas e preserve o histórico de cada cliente.", battle: "Ranking interno dos clientes com dados publicados.", integrations: "Cadastre o IP do ambiente e os acessos de cada empresa. Compartilhado: mesmo IP, usuários e senhas próprios. Dedicado: IP exclusivo da empresa.", users: "Equipe Pier e acessos dos clientes por empresa.", audit: "Arquivos de retenção, integridade e validade dos downloads." })[section]}</p></div>
      {section === "tenants" && <button className="button button-primary" onClick={() => setEditor({ kind: "company" })}>Nova empresa</button>}
      {section === "integrations" && <button className="button button-primary" onClick={() => setEditor({ kind: "connection" })}>Nova integração</button>}
      {section === "users" && <button className="button button-primary" onClick={() => setEditor({ kind: "invite" })}>Convidar usuário</button>}
    </div>
    {section === "dashboard" && <>
      <div className="admin-metrics">
        <Link className="admin-metric spotlight-card" onMouseMove={(event) => trackSpotlight(event)} href="/admin/tenants"><span>Empresas</span><strong><AnimatedCounter value={data.stats.active_companies + data.stats.inactive_companies} /></strong><small>{data.stats.active_companies} ativas · {data.stats.inactive_companies} inativas</small></Link>
        <Link className="admin-metric spotlight-card" onMouseMove={(event) => trackSpotlight(event)} href="/admin/users"><span>Usuários vinculados</span><strong><AnimatedCounter value={data.stats.users} /></strong><small>Equipe Pier e clientes</small></Link>
        <Link className="admin-metric spotlight-card" onMouseMove={(event) => trackSpotlight(event)} href="/admin/integrations"><span>Fontes de vulnerabilidades</span><strong><AnimatedCounter value={data.stats.connections} /></strong><small>{data.stats.active_connections} ativas · {data.stats.connections - data.stats.active_connections} inativas</small></Link>
      </div>
      <section className="panel admin-list-panel"><div className="panel-heading"><div><h2>Última sincronização por conexão</h2><p>A média usa até cinco leituras completas; a previsão considera o ritmo da execução atual.</p></div><Link className="button button-secondary" href="/admin/integrations">Gerenciar integrações</Link></div>
        <DataTable headings={["Conexão", "Empresa", "Estado", "Última execução", "Documentos", "Ritmo de sincronização"]} empty={!data.connections.length}>
          {data.connections.map((c) => <tr key={c.id}><td>{visibleText(c.name)}<small>{c.is_active ? "Ativa" : "Inativa"}</small></td><td>{companyName(c.tenant_id)}</td><td><SyncStatus connection={c} /></td><td>{adminDate(c.latest_sync?.finished_at ?? c.latest_sync?.started_at)}</td><td>{c.latest_sync ? c.latest_sync.documents_received.toLocaleString("pt-BR") : "Sem execução"}</td><td><SyncTiming runs={syncHistory[c.id] ?? []} now={syncNow} /></td></tr>)}
        </DataTable>
      </section>
    </>}
    {section === "battle" && <BattleDashboard companies={battle} error={battleError} onRetry={() => { setBattleError(""); setBattleRetry((value) => value + 1); }} />}
    {(section === "tenants" || section === "integrations") && <div className="admin-filters"><label><span className="sr-only">Buscar {section === "tenants" ? "empresa" : "integração"}</span><input type="search" placeholder={section === "tenants" ? "Buscar empresa…" : "Buscar empresa, integração ou vínculo…"} value={search} onChange={(e) => setSearch(e.target.value)} /></label><label><span className="sr-only">Filtrar por status</span><select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Todos os status</option><option value="true">Ativas</option><option value="false">Inativas</option></select></label>{section === "integrations" && <label><span className="sr-only">Filtrar por empresa</span><select value={companyFilter} onChange={(e) => setCompanyFilter(e.target.value)}><option value="">Todas as empresas</option>{data.companies.map((c) => <option key={c.id} value={c.id}>{visibleText(c.name)}</option>)}</select></label>}</div>}
    {section === "tenants" && <section className="panel admin-list-panel">
      {storageUsage && <Meter className="database-storage-meter" value={Math.min(storageUsage.database_bytes, DATABASE_LIMIT_BYTES)} maxValue={DATABASE_LIMIT_BYTES}
        color={storageUsage.database_bytes > DATABASE_LIMIT_BYTES ? "danger" : storageUsage.database_bytes >= DATABASE_LIMIT_BYTES * .8 ? "warning" : "accent"}
        valueLabel={`${formatStorageBytes(storageUsage.database_bytes)} de 500 MB · ${Math.round(storageUsage.database_bytes / DATABASE_LIMIT_BYTES * 100)}%`}>
        <Label>Armazenamento do banco</Label><Meter.Output />
        <Meter.Track><Meter.Fill /></Meter.Track>
      </Meter>}
      {storageUsage && storageUsage.database_bytes > DATABASE_LIMIT_BYTES && <div className="database-capacity-warning" role="status">
        <TriangleAlert size={22} aria-hidden="true" />
        <div><strong>Limite de armazenamento ultrapassado</strong><p>O banco está usando {formatStorageBytes(storageUsage.database_bytes)} de 500 MB ({Math.round(storageUsage.database_bytes / DATABASE_LIMIT_BYTES * 100)}%). Excedente: {formatStorageBytes(storageUsage.database_bytes - DATABASE_LIMIT_BYTES)}.</p><small>Com base na medição de {adminDate(storageUsage.measured_at)}. Atualização a cada 5 minutos.</small></div>
      </div>}
      <div className="panel-heading"><div><p>Tamanho medido dos registros de cada empresa: vulnerabilidades, casos, histórico e comentários. Índices e espaço livre das tabelas compartilhadas aparecem somente no total do banco.</p><small className="muted-copy" role="status">
        {storageUsage ? `Banco: ${formatStorageBytes(storageUsage.database_bytes)} · Medição: ${adminDate(storageUsage.measured_at)} · Atualização a cada 5 minutos` : storageError ? "Não foi possível consultar os tamanhos. Nova tentativa automática em um minuto." : "Carregando a medição de armazenamento…"}
        {storageUsage && (storageError || storageNow - Date.parse(storageUsage.measured_at) > storageUsage.refresh_seconds * 2000) && " · Última medição mantida; aguardando atualização."}
      </small></div></div>
      <DataTable headings={["Empresa", "Usuários ativos", "Conexões", "Tamanho dos dados", "Status", "Ações"]} empty={!companies.length}>
      {companies.map((c) => {
        const usage = storageUsage?.companies.find((item) => item.tenant_id === c.id);
        const deletion = storageUsage?.deletions?.find((item) => item.tenant_id === c.id);
        const removing = deletion?.status === "queued" || deletion?.status === "running";
        const compacting = deletion?.storage_status === "queued" || deletion?.storage_status === "running";
        const deleting = removing || compacting;
        return <tr key={c.id}>
          <td><div className="admin-company-identity">{c.logo_dark_path && <img src={client.storage.from("company-logos").getPublicUrl(c.logo_dark_path).data.publicUrl} alt="" />}<span><strong>{visibleText(c.name)}</strong><small>{visibleText(c.slug)}</small></span></div>
            {deletion && <small role="status">{removing ? `Limpeza ${deletion.status === "queued" ? "na fila" : "em andamento"} · ${deletion.findings_deleted.toLocaleString("pt-BR")} vulnerabilidades removidas` : compacting ? `Dados apagados · compactação ${deletion.storage_status === "queued" ? "na fila" : "em andamento"} · ${deletion.storage_tables_done ?? 0}/4 tabelas` : deletion.status === "failed" ? deletion.error_message : deletion.storage_status === "failed" ? deletion.storage_error : deletion.storage_status === "succeeded" ? `Limpeza concluída · ${formatStorageBytes(deletion.storage_reclaimed_bytes ?? 0)} recuperados nas tabelas compartilhadas` : "Última limpeza concluída"}</small>}
            {deletion && deletion.status !== "failed" && deletion.storage_status !== "failed" && <ProgressBar className="company-cleanup-progress" aria-label={`${compacting ? "Compactação" : "Limpeza"} de ${visibleText(c.name)}`}
              isIndeterminate={removing} value={compacting ? (deletion.storage_tables_done ?? 0) / 4 * 100 : deletion.status === "succeeded" ? 100 : 0} color={deleting ? "accent" : "success"} size="sm">
              {compacting && <ProgressBar.Output />}
              <ProgressBar.Track><ProgressBar.Fill /></ProgressBar.Track>
            </ProgressBar>}
          </td>
          <td>{c.user_count}</td><td>{c.connection_count}</td>
          <td title="Soma do tamanho dos registros da empresa, medida com pg_column_size. Não inclui rateio de índices nem espaço livre compartilhado.">{usage ? <strong>{formatStorageBytes(usage.data_bytes)}</strong> : <span className="muted-copy">{storageError ? "Indisponível" : "Aguardando medição"}</span>}</td>
          <td><ActiveStatus active={c.is_active} /></td>
          <td><div className="admin-row-actions">
            <button className="button button-secondary" disabled={busy || deleting} onClick={() => setEditor({ kind: "company", company: c })}>Editar</button>
            <button className="button button-secondary" disabled={busy || deleting} onClick={() => setEditor({ kind: "toggle", entity: "company", id: c.id, name: visibleText(c.name), active: c.is_active })}>{c.is_active ? "Desativar" : "Reativar"}</button>
            <button className="button button-secondary button-destructive" disabled={busy || deleting || c.user_count > 0 || c.connection_count > 0 || (usage?.finding_count ?? 0) > 0} title="Exclua apenas empresas sem usuários, conexões ou vulnerabilidades" onClick={() => setEditor({ kind: "delete-company", company: c })}>Excluir empresa</button>
            <button className="button button-secondary button-destructive" disabled={busy || deleting} onClick={() => setDeleteCompany(c)}>{compacting ? "Compactando…" : removing ? "Apagando…" : "Apagar dados"}</button>
          </div></td>
        </tr>;
      })}
    </DataTable></section>}
    {section === "integrations" && <div className="admin-integrations">
      <SocWebhookPanel companies={data.companies} client={client} />
      {!connections.length && <div className="panel admin-empty">Nenhuma integração encontrada. Ajuste os filtros ou cadastre uma nova integração.</div>}
      {connections.map((connection) => <IntegrationPanel key={connection.id} connection={connection} data={data} companyFilter={companyFilter} search={search} runs={syncHistory[connection.id] ?? []} now={syncNow} setEditor={setEditor} />)}
    </div>}
    {section === "users" && <>
      <div className="admin-filters"><label><span className="sr-only">Buscar usuário</span><input type="search" placeholder="Buscar nome ou e-mail…" value={query.search} onChange={(e) => setQuery({ ...query, search: e.target.value, page: 0 })} /></label><label><span className="sr-only">Filtrar usuários por equipe ou empresa</span><select value={query.scope} onChange={(e) => setQuery({ ...query, scope: e.target.value, page: 0 })}><option value="">Todos os usuários</option><option value="pier">Equipe Pier</option>{data.companies.map((c) => <option key={c.id} value={c.id}>{visibleText(c.name)}</option>)}</select></label></div>
      <section className="panel admin-list-panel"><DataTable headings={["Nome / e-mail", "Acesso", "Empresas e perfis", "Cadastro", "Ações"]} empty={!data.users.length}>
        {data.users.map((u) => <tr key={u.id}><td><strong>{visibleText(u.display_name)}</strong><small>{visibleText(u.email)}</small></td><td>{u.is_internal ? <span className="admin-status positive">Admin · Equipe Pier</span> : "Cliente"}</td><td>{u.memberships.length ? u.memberships.map((m) => <div className="admin-membership" key={m.id}><span>{companyName(m.company_id)}<small>{roleLabels[m.role]} · {m.is_active ? "Ativo" : "Inativo"}</small></span><button className="button button-secondary" onClick={() => setEditor({ kind: "membership", membership: m, email: visibleText(u.email) })}>Editar vínculo</button></div>) : <span className="muted-copy">{u.is_internal ? "Acesso administrativo a todas as empresas" : "Sem empresa vinculada"}</span>}</td><td><span>{u.email_confirmed_at ? "Cadastro concluído" : u.invited_at ? "Convite pendente" : "Não confirmado"}</span><small>Último acesso: {adminDate(u.last_sign_in_at)}</small></td><td>{u.invited_at && !u.email_confirmed_at ? <button className="button button-secondary" disabled={busy} onClick={() => void run({ action: "resend_invite", id: u.id }, "Convite reenviado.")}>Reenviar convite</button> : "Cadastro concluído"}</td></tr>)}
      </DataTable><div className="admin-pagination"><span>{data.user_count} usuários · página {query.page + 1} de {Math.max(1, Math.ceil(data.user_count / 50))}</span><div><button className="button button-secondary" disabled={!query.page} onClick={() => setQuery({ ...query, page: query.page - 1 })}>Anterior</button><button className="button button-secondary" disabled={(query.page + 1) * 50 >= data.user_count} onClick={() => setQuery({ ...query, page: query.page + 1 })}>Próxima</button></div></div></section>
    </>}
    {section === "audit" && <>
      <div className="admin-filters"><label><span className="sr-only">Buscar arquivo</span><input type="search" placeholder="Buscar identificador ou caminho…" value={search} onChange={(e) => setSearch(e.target.value)} /></label><label><span className="sr-only">Filtrar arquivos por status</span><select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Todos os status</option>{Object.entries(archiveLabels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label><span className="muted-copy">Últimos 50 arquivos</span></div>
      <section className="panel admin-list-panel"><DataTable headings={["Arquivo / SHA-256", "Registros", "Arquivado em", "Validade", "Status", "Download"]} empty={!data.archives.some((a) => matches(`${a.id} ${a.object_path}`) && (!status || a.status === status))}>
        {data.archives.filter((a) => matches(`${a.id} ${a.object_path}`) && (!status || a.status === status)).map((a) => <tr key={a.id}><td className="admin-file"><strong>{a.object_path}</strong><small>{a.id}</small><code>{a.checksum_sha256}</code></td><td>{a.record_count.toLocaleString("pt-BR")}</td><td>{adminDate(a.archived_at)}</td><td>{adminDate(a.expires_at)}</td><td>{archiveLabels[a.status] ?? a.status}</td><td>{archiveLink?.id === a.id ? <a className="button button-primary" href={archiveLink.url} download rel="noreferrer">Baixar arquivo</a> : <button className="button button-secondary" disabled={a.status === "expired" || Date.parse(a.expires_at) <= Date.now() || downloadBusy !== null} onClick={() => void download(a)}>{downloadBusy === a.id ? "Preparando…" : "Preparar download"}</button>}</td></tr>)}
      </DataTable></section>
    </>}
    {editor && <AdminEditor key={editor.kind} editor={editor} close={() => setEditor(null)} setEditor={(next) => setEditor(next)} />}
    {deleteCompany && <CompanyDataDeletionDialog company={deleteCompany} client={client} close={() => setDeleteCompany(null)} onQueued={() => {
      setDeleteCompany(null);
      notify({ title: "Limpeza iniciada. A empresa foi desativada e a coleta desligada." });
      void reload();
    }} />}
  </>;
}

type SocCredential = {
  id: string; tenant_id: string; name: string; token_prefix: string; created_at: string; revoked_at: string | null;
  last_received_at: string | null; last_batch_events: number; last_inserted: number; last_duplicates: number; last_error: string | null;
};

async function invokeSocIngestAdmin<T>(client: SupabaseClient, body: Record<string, unknown>): Promise<T> {
  const { data, error } = await client.functions.invoke("soc-ingest-admin", { body });
  if (error) {
    const detail = error.context instanceof Response ? await error.context.json().catch(() => null) : null;
    throw new AdminRequestError(detail?.error || "Não foi possível concluir a operação. Tente novamente.", error.context instanceof Response ? error.context.status : undefined);
  }
  if (!data || data.error) throw new Error(data?.error || "Resposta administrativa inválida.");
  return data as T;
}

function SocWebhookPanel({ companies, client }: { companies: AdminCompany[]; client: SupabaseClient }) {
  const [credentials, setCredentials] = useState<SocCredential[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [name, setName] = useState("n8n");
  const [token, setToken] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const endpoint = `${process.env.NEXT_PUBLIC_SUPABASE_URL}/functions/v1/soc-alert-ingest`;
  const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ?? "";

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const result = await invokeSocIngestAdmin<{ credentials: SocCredential[] }>(client, { action: "list" });
      setCredentials(result.credentials);
      setError("");
    } catch (cause) {
      setError((cause as Error).message || "Não foi possível carregar as chaves.");
    } finally { setLoading(false); }
  }, [client]);

  useEffect(() => { void reload(); }, [reload]);

  async function createCredential(event: FormEvent) {
    event.preventDefault();
    if (!tenantId || busy) return;
    setBusy(true); setError(""); setMessage(""); setToken("");
    try {
      const result = await invokeSocIngestAdmin<{ credential: SocCredential; token: string }>(client, {
        action: "create", tenantId, name,
      });
      setToken(result.token);
      setMessage("Chave criada. Copie agora: ela não será exibida novamente.");
      await reload();
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }

  async function revoke(credential: SocCredential) {
    if (busy || credential.revoked_at) return;
    setBusy(true); setError(""); setMessage("");
    try {
      await invokeSocIngestAdmin(client, { action: "revoke", id: credential.id });
      setMessage(`Chave ${credential.token_prefix} revogada.`);
      await reload();
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }

  async function copy(value: string, label: string) {
    try { await navigator.clipboard.writeText(value); setMessage(`${label} copiado.`); }
    catch { setError("Não foi possível copiar. Selecione e copie o texto manualmente."); }
  }

  const companyName = (id: string) => visibleText(companies.find((company) => company.id === id)?.name ?? "Empresa removida");

  return <section className="panel soc-ingest-panel" aria-labelledby="soc-ingest-title">
    <div className="soc-ingest-heading"><div><span className="eyebrow">RECEBIMENTO SOC</span><h2 id="soc-ingest-title">Alertas do n8n</h2><p>Gere uma chave por empresa e envie eventos normalizados em lotes de até 100.</p></div>
      <span className="soc-ingest-retention">Detalhes: 30 dias · Totais diários: mantidos</span></div>

    <form className="soc-ingest-create" onSubmit={createCredential}>
      <label>Empresa<select required value={tenantId} onChange={(event) => setTenantId(event.target.value)}><option value="">Selecione a empresa</option>{companies.map((company) => <option key={company.id} value={company.id} disabled={!company.is_active}>{visibleText(company.name)}{company.is_active ? "" : " · inativa"}</option>)}</select></label>
      <label>Nome da chave<input required maxLength={80} value={name} onChange={(event) => setName(visibleText(event.target.value))} placeholder="n8n produção" /></label>
      <button className="button button-primary" disabled={busy || !tenantId}>{busy ? "Salvando…" : "Gerar chave"}</button>
    </form>

    {token && <div className="soc-token-reveal" role="status"><div><strong>Copie a chave agora</strong><p>O banco guarda só o hash. Feche ou atualize a página e ela não poderá ser recuperada.</p></div><code>{token}</code><button type="button" className="button button-secondary" onClick={() => void copy(token, "Chave")}>Copiar chave</button></div>}
    {message && <p className="soc-ingest-message" role="status">{visibleText(message)}</p>}
    {error && <p className="inline-alert" role="alert">{visibleText(error)}</p>}

    <details className="soc-ingest-guide"><summary>Configuração do webhook no n8n</summary>
      <div className="soc-ingest-guide-grid"><div><span>URL</span><code>{endpoint}</code><button type="button" className="button button-secondary" onClick={() => void copy(endpoint, "URL")}>Copiar URL</button></div>
        <div><span>Método e cabeçalhos</span><pre>{`POST\nContent-Type: application/json\nAuthorization: Bearer SUA_CHAVE_PIER\napikey: ${publishableKey || "CHAVE_PUBLICA_SUPABASE"}`}</pre><small>A chave pública do projeto pode ficar na configuração do n8n. Nunca coloque a chave de ingestão em query string ou logs.</small></div>
        <div><span>Formato do corpo</span><pre>{`{\n  "events": [{\n    "source_id": "firewall-filial-01",\n    "source_name": "Firewall Filial 01",\n    "source_event_id": "ID_ESTAVEL_DA_ORIGEM",\n    "occurred_at": "2026-10-30T14:30:00Z",\n    "severity": "high",\n    "title": "Bloqueio de conexão",\n    "message": "Descrição do evento",\n    "rule_id": "regra-42",\n    "src_ip": "203.0.113.10",\n    "dst_ip": "192.0.2.15",\n    "mitre_ids": []\n  }]\n}`}</pre><button type="button" className="button button-secondary" onClick={() => void copy(`{\n  "events": [{\n    "source_id": "firewall-filial-01",\n    "source_name": "Firewall Filial 01",\n    "source_event_id": "ID_ESTAVEL_DA_ORIGEM",\n    "occurred_at": "2026-10-30T14:30:00Z",\n    "severity": "high",\n    "title": "Bloqueio de conexão",\n    "message": "Descrição do evento",\n    "rule_id": "regra-42",\n    "src_ip": "203.0.113.10",\n    "dst_ip": "192.0.2.15",\n    "mitre_ids": []\n  }]\n}`, "Exemplo de JSON")}>Copiar exemplo</button></div>
        <p className="soc-ingest-response">Resposta 200: `accepted`, `inserted` e `duplicates`. Reenvie em caso de falha: `source_id` + `source_event_id` impedem contagem duplicada. Severidade aceita: critical, high, medium, low, informational ou unknown.</p>
      </div>
    </details>

    <div className="soc-ingest-keys"><h3>Chaves por empresa</h3>{loading ? <p className="muted-copy">Carregando chaves…</p> : !credentials.length ? <p className="muted-copy">Nenhuma chave criada.</p> : credentials.map((credential) => <div className="soc-ingest-key" key={credential.id}>
      <div><strong>{companyName(credential.tenant_id)} · {visibleText(credential.name)}</strong><code>{visibleText(credential.token_prefix)}…</code><small>{credential.revoked_at ? `Revogada em ${adminDate(credential.revoked_at)}` : `Ativa · criada ${adminDate(credential.created_at)}`}</small></div>
      <div><strong>{credential.last_received_at ? `Último lote ${adminDate(credential.last_received_at)}` : "Sem eventos recebidos"}</strong>{credential.last_received_at && <small>{credential.last_inserted.toLocaleString("pt-BR")} novos · {credential.last_duplicates.toLocaleString("pt-BR")} duplicados</small>}{credential.last_error && <small className="soc-ingest-error">{visibleText(credential.last_error)}</small>}</div>
      {!credential.revoked_at && <button type="button" className="button button-secondary button-destructive" disabled={busy} onClick={() => void revoke(credential)}>Revogar</button>}
    </div>)}</div>
  </section>;
}

function IntegrationPanel({ connection, data, companyFilter, search, runs, now, setEditor }: {
  connection: AdminConnection; data: AdminData; companyFilter: string; search: string;
  runs: SyncMeasurement[]; now: number; setEditor: (editor: Editor) => void;
}) {
  const { busy, run } = useAdmin();
  const mappings = data.mappings.filter((mapping) => mapping.connection_id === connection.id);
  const tenantIds = new Set(mappings.map((mapping) => mapping.tenant_id));
  if (connection.tenant_id) tenantIds.add(connection.tenant_id);
  const configuredTenantIds = new Set(connection.asset_api_configured_tenant_ids ?? []);
  const configuredApiCount = [...tenantIds].filter((tenantId) => configuredTenantIds.has(tenantId)).length;
  const activeMappingCount = mappings.filter((mapping) => mapping.is_active).length;
  const inactiveMappingCount = mappings.length - activeMappingCount;
  const normalizedSearch = search.trim().toLocaleLowerCase("pt-BR");
  const connectionMatches = `${visibleText(connection.name)} ${visibleText(connection.endpoint_url)}`.toLocaleLowerCase("pt-BR").includes(normalizedSearch);
  const companies = data.companies.filter((company) => tenantIds.has(company.id) && (!companyFilter || company.id === companyFilter)
    && (connectionMatches || `${visibleText(company.name)} ${mappings.filter((mapping) => mapping.tenant_id === company.id).map((mapping) => mapping.match_value).join(" ")}`.toLocaleLowerCase("pt-BR").includes(normalizedSearch)))
    .sort((a, b) => a.name.localeCompare(b.name, "pt-BR"));
  function mappingRows(rows: typeof mappings) {
    return rows.map((mapping) => <div className="admin-mapping-row" key={mapping.id}>
      <span><strong>{mapping.match_type === "group" ? "Grupo" : mapping.match_type === "agent_name_prefix" ? "Prefixo" : "Agente"}</strong><code>{visibleText(mapping.match_value)}</code><small>{mapping.is_active ? "Ativo" : "Inativo"}</small></span>
      <button className="button button-secondary" disabled={busy} onClick={() => setEditor({ kind: "mapping", connectionId: connection.id, mapping })}>Editar</button>
      <button className="button button-secondary" disabled={busy} aria-label={`${mapping.is_active ? "Desativar" : "Ativar"} ${visibleText(mapping.match_value)}`} onClick={() => void run(mapping.is_active
        ? { action: "disable_agent_mapping", mappingId: mapping.id }
        : { action: "set_agent_mapping", connectionId: mapping.connection_id, tenantId: mapping.tenant_id, matchType: mapping.match_type, matchValue: mapping.match_value }, mapping.is_active ? "Regra desativada." : connection.is_active ? "Regra ativada." : "Regra ativada. Ative também a integração para iniciar a coleta.")}>{mapping.is_active ? "Desativar" : "Ativar"}</button>
    </div>);
  }
  return <section className="panel admin-integration-panel" aria-labelledby={`connection-${connection.id}`}>
    <header className="admin-integration-header">
      <div><h2 id={`connection-${connection.id}`}>{visibleText(connection.name)}</h2><p>{connection.mode === "shared" ? "Ambiente compartilhado" : "Ambiente dedicado"} · {tenantIds.size} {tenantIds.size === 1 ? "empresa vinculada" : "empresas vinculadas"}</p></div>
      <div className="admin-integration-actions"><ActiveStatus active={connection.is_active} /><button className="button button-secondary" disabled={busy} onClick={() => setEditor({ kind: "toggle", entity: "connection", id: connection.id, name: visibleText(connection.name), active: connection.is_active })}>{connection.is_active ? "Desativar integração" : "Ativar integração"}</button>{connection.mode === "shared" && <button className="button button-primary" disabled={!connection.is_active || busy} title={!connection.is_active ? "Ative a integração antes de adicionar uma empresa." : undefined} onClick={() => setEditor({ kind: "shared-company", connectionId: connection.id })}>Adicionar empresa</button>}</div>
    </header>
    {connection.mode === "shared" && !connection.is_active && <p className="admin-integration-paused-note">Integração inativa. Ative-a para adicionar empresas. Regras existentes podem ser editadas sem iniciar a coleta.</p>}
    <div className="admin-integration-checklist" aria-label="Resumo da configuração">
      <div><strong>Endpoint do Indexer</strong><span>{connection.endpoint_url ? "Configurado" : "Pendente"}</span></div>
      <div><strong>Acessos ao Indexer</strong><span>{connection.mode === "shared" ? `${connection.indexer_configured_tenant_ids?.length ?? 0}/${tenantIds.size} empresas` : connection.indexer_credentials_configured ? "Cadastrado" : "Pendente"}</span></div>
      <div><strong>API do Manager</strong><span>{connection.asset_api_url ? "Endereço configurado" : "Endereço pendente"}</span></div>
      <div><strong>Acesso ao Manager</strong><span>{tenantIds.size ? `${configuredApiCount}/${tenantIds.size} empresas configuradas` : "Sem empresas vinculadas"}</span></div>
      {connection.mode === "shared" && <div><strong>Regras de roteamento</strong><span>{activeMappingCount}/{mappings.length} ativas</span></div>}
    </div>
    {connection.mode === "shared" && mappings.some((mapping) => mapping.is_active && data.companies.some((company) => company.id === mapping.tenant_id && company.is_active) && !connection.indexer_configured_tenant_ids?.includes(mapping.tenant_id)) && <p className="admin-integration-paused-note" role="status">Configure o acesso ao Indexer de cada empresa ativa para liberar a coleta compartilhada. Os dados anteriores permanecem disponíveis.</p>}
    <div className="admin-integration-sync"><SyncStatus connection={connection} /><span>Última execução: {adminDate(connection.latest_sync?.finished_at ?? connection.latest_sync?.started_at)}</span></div>
    <details className="admin-connection-details"><summary>Configuração e sincronização</summary>
      <div className="admin-connection-body"><div className="admin-connection-facts"><div><span className="muted-copy">Endpoint do Indexer</span><p className="admin-endpoint">{visibleText(connection.endpoint_url)}</p></div><div><span className="muted-copy">Endpoint comum da API do Manager</span><p className="admin-endpoint">{connection.asset_api_url ? visibleText(connection.asset_api_url) : "Não configurado"}</p></div><SyncTiming runs={runs} now={now} />{connection.latest_asset_sync && <p className="muted-copy">Última coleta: {adminDate(connection.latest_asset_sync.finished_at)} · {connection.latest_asset_sync.status === "succeeded" ? `${connection.latest_asset_sync.agents_stored.toLocaleString("pt-BR")} ativos` : connection.latest_asset_sync.status === "failed" ? "Falhou" : "Em andamento"}</p>}</div>
        <div className="admin-connection-controls"><h3>Configuração</h3><div className="admin-integration-actions"><button className="button button-secondary" disabled={busy} onClick={() => setEditor({ kind: "connection", connection })}>Editar ambiente</button><button className="button button-secondary" disabled={busy} onClick={() => setEditor({ kind: "connection-ca", connection })}>Editar certificado CA</button>{connection.mode === "shared" && <button className="button button-secondary" disabled={busy} onClick={() => setEditor({ kind: "mapping", connectionId: connection.id })}>Adicionar regra manual</button>}<button className="button button-secondary button-destructive" disabled={connection.is_active || Boolean(connection.latest_sync || connection.latest_asset_sync) || busy} title={connection.is_active ? "Desative a integração antes de excluir." : connection.latest_sync || connection.latest_asset_sync ? "Há histórico de coleta. Desative a integração para preservá-lo." : undefined} onClick={() => setEditor({ kind: "delete-connection", connection })}>Excluir integração</button></div><p className="muted-copy">Excluir só funciona sem histórico nem dados. Se já houve coleta, desative para preservar os registros.</p></div>
      </div>
    </details>
    {!companies.length && <p className="admin-integration-empty">Nenhuma empresa vinculada nesta seleção.{connection.mode === "shared" ? " Use Adicionar empresa para configurar o primeiro cliente." : " Edite a integração para selecionar uma empresa."}</p>}
    <div className="admin-company-grid">{companies.map((company) => {
      const companyMappings = mappings.filter((mapping) => mapping.tenant_id === company.id);
      const rules = companyMappings.filter((mapping) => mapping.match_type !== "agent_id");
      const agents = companyMappings.filter((mapping) => mapping.match_type === "agent_id");
      const activeCompanyRules = companyMappings.filter((mapping) => mapping.is_active).length;
      const inactiveCompanyRules = companyMappings.length - activeCompanyRules;
      const mappingSummary = (matchType: string) => {
        const values = rules.filter((mapping) => mapping.match_type === matchType);
        return values.length ? <span className="admin-route-values">{values.map((mapping) => <span className="admin-route-value" key={mapping.id}><code>{visibleText(mapping.match_value)}</code><small className={mapping.is_active ? "positive-copy" : "muted-copy"}>{mapping.is_active ? "Ativo" : "Inativo"}</small></span>)}</span> : "Não configurado";
      };
      return <article className="admin-integration-company" key={company.id}>
        <header><h3>{visibleText(company.name)}</h3><ActiveStatus active={company.is_active} /></header>
        {connection.mode === "shared" ? <>
          <dl className="admin-company-routing"><div><dt>Prefixo</dt><dd>{mappingSummary("agent_name_prefix")}</dd></div><div><dt>Grupo</dt><dd>{mappingSummary("group")}</dd></div></dl>
          <details className="admin-company-details" name={`company-rules-${connection.id}`}><summary>Regras de roteamento <span>{activeCompanyRules}/{companyMappings.length} ativas</span></summary>
            {rules.length > 0 && <div className="admin-mapping-list" role="region" aria-label={`Regras de ${visibleText(company.name)}`} tabIndex={0}>{mappingRows(rules)}</div>}
            {agents.length > 0 && <details className="admin-agent-details"><summary>Agentes individuais ({agents.length})</summary><div className="admin-mapping-list" role="region" aria-label={`Agentes de ${visibleText(company.name)}`} tabIndex={0}>{mappingRows(agents)}</div></details>}
            {!companyMappings.length && <p className="muted-copy">Nenhum vínculo configurado para esta empresa.</p>}
          </details>
          <div className="admin-company-actions"><span className="muted-copy">{inactiveCompanyRules ? `${inactiveCompanyRules} regra${inactiveCompanyRules === 1 ? "" : "s"} desligada${inactiveCompanyRules === 1 ? "" : "s"}` : "Todas as regras estão ativas"}</span>{inactiveCompanyRules > 0 && <button className="button button-secondary" disabled={!company.is_active || busy} title={!company.is_active ? "Reative a empresa antes de ativar as regras." : undefined} onClick={() => void run({ action: "activate_company_mappings", connectionId: connection.id, tenantId: company.id }, connection.is_active ? `Regras de ${visibleText(company.name)} ativadas.` : `Regras de ${visibleText(company.name)} ativadas. Ative também a integração para iniciar a coleta.`)}>Ativar regras</button>}</div>
        </> : <p className="muted-copy">Os dados desta integração são destinados a esta empresa.</p>}
        <p className="muted-copy">Indexer: {connection.mode === "dedicated" ? connection.indexer_credentials_configured ? "cadastrado" : "pendente" : connection.indexer_configured_tenant_ids?.includes(company.id) ? "configurado" : "pendente"}</p><div className="admin-integration-actions"><span className="muted-copy">{configuredTenantIds.has(company.id) ? "Acesso ao Manager configurado" : "Acesso ao Manager pendente"}</span><button className={`button ${configuredTenantIds.has(company.id) ? "button-secondary" : "button-primary"}`} disabled={busy} onClick={() => setEditor({ kind: "asset-api", connection, company })}>{configuredTenantIds.has(company.id) ? "Editar acessos" : "Configurar acessos"}</button></div>
        {(() => { const run = connection.latest_asset_sync_by_tenant?.[company.id]; return run ? <p className="muted-copy">Última coleta desta empresa: {run.finished_at ? adminDate(run.finished_at) : "em andamento"} · {run.status === "succeeded" ? `${run.agents_stored.toLocaleString("pt-BR")} ativos` : run.status === "failed" ? "falhou" : "em andamento"}</p> : null; })()}
      </article>;
    })}</div>
  </section>;
}

function ActiveStatus({ active }: { active: boolean }) { return <span className={`admin-status${active ? " positive" : ""}`}>{active ? "Ativa" : "Inativa"}</span>; }
function SyncTiming({ runs, now }: { runs: SyncMeasurement[]; now: number }) {
  const current = runs.find((run) => run.status === "running");
  const completed = runs.filter((run) => run.status === "succeeded" && run.full_snapshot && run.finished_at)
    .slice(0, 5)
    .map((run) => ({
      seconds: (Date.parse(run.finished_at!) - Date.parse(run.started_at)) / 1000,
      documents: run.documents_received,
    }))
    .filter((run) => Number.isFinite(run.seconds) && run.seconds > 0 && run.documents >= 0);
  const avgSeconds = completed.length ? completed.reduce((sum, run) => sum + run.seconds, 0) / completed.length : null;
  const totalSeconds = completed.reduce((sum, run) => sum + run.seconds, 0);
  const totalDocuments = completed.reduce((sum, run) => sum + run.documents, 0);
  const documentsPerSecond = totalSeconds > 0 ? totalDocuments / totalSeconds : null;
  const basisDocuments = completed[0]?.documents ?? 0;
  const elapsed = current ? Math.max(0, (now - Date.parse(current.started_at)) / 1000) : 0;
  const liveRate = current && elapsed >= 5 && current.documents_received > 0 ? current.documents_received / elapsed : null;
  const progress = current && basisDocuments > 0 ? Math.min(99, current.documents_received / basisDocuments * 100) : null;
  const remaining = current && progress != null && progress < 99 && liveRate
    ? Math.ceil(Math.max(0, basisDocuments - current.documents_received) / liveRate)
    : null;
  const latest = runs[0];

  if (current) {
    return <span className="sync-timing"><strong>Em andamento</strong><small>{remaining != null && progress != null
      ? `~${Math.round(progress)}% · ~${formatSyncDuration(remaining)} restantes`
      : current.documents_received > 0 ? `${current.documents_received.toLocaleString("pt-BR")} documentos lidos · calculando estimativa`
        : "Aguardando a fonte enviar dados"}</small></span>;
  }
  if (!completed.length) return <span className="sync-timing"><strong>Sem leitura completa recente</strong><small>{latest?.status === "failed" ? visibleText(latest.error_summary) || "Última tentativa falhou" : "Aguardando uma leitura completa"}</small></span>;
  return <span className="sync-timing"><strong>Média: {formatSyncDuration(avgSeconds!)}</strong><small>{documentsPerSecond!.toLocaleString("pt-BR", { maximumFractionDigits: 1 })} documentos/s · {completed.length} leituras completas</small></span>;
}

function formatSyncDuration(seconds: number) {
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${Math.round(seconds % 60)} s`;
}

function SyncStatus({ connection }: { connection: AdminConnection }) {
  const status = connection.latest_sync?.status;
  return <span className={`admin-status${status === "failed" || status === "partial" ? " caution" : status === "succeeded" ? " positive" : ""}`}>{status ? visibleText(syncLabels[status] ?? status) : "Sem execução"}{connection.latest_sync && !connection.latest_sync.full_snapshot ? " · Incremental" : ""}</span>;
}
function DataTable({ headings, empty, children }: { headings: string[]; empty: boolean; children: ReactNode }) {
  return <div className="admin-table-scroll" role="region" aria-label={headings[0]} tabIndex={0}><table className="admin-table"><thead><tr>{headings.map((h) => <th scope="col" key={h}>{h}</th>)}</tr></thead><tbody>{empty ? <tr><td colSpan={headings.length}><div className="admin-empty">Nenhum registro encontrado para esta seleção.</div></td></tr> : children}</tbody></table></div>;
}

function imageDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Não foi possível ler a logo."));
    reader.readAsDataURL(file);
  });
}

function AdminEditor({ editor, close, setEditor }: { editor: Editor; close: () => void; setEditor: (editor: Editor) => void }) {
  const { client, data, busy, run, notify, setIslandHost } = useAdmin();
  const dialog = useRef<HTMLDialogElement>(null);
  const [inviteKind, setInviteKind] = useState("client");
  const [sharedCompanyTarget, setSharedCompanyTarget] = useState("new");
  const [mode, setMode] = useState(editor.kind === "connection" ? editor.connection?.mode ?? "dedicated" : "dedicated");
  function cancel() {
    if (busy) return;
    close();
  }
  useEffect(() => {
    dialog.current?.showModal(); setIslandHost(dialog.current);
    return () => setIslandHost(null);
  }, [setIslandHost]);
  if (!data) return null;
  const editorData = data;
  const activeCompanies = data.companies.filter((c) => c.is_active);
  const title = editor.kind === "company" ? editor.company ? "Editar empresa" : "Nova empresa"
    : editor.kind === "delete-company" ? "Excluir empresa"
    : editor.kind === "connection" ? editor.connection ? "Editar integração" : "Nova integração"
    : editor.kind === "delete-connection" ? `Excluir integração · ${visibleText(editor.connection.name)}`
    : editor.kind === "delete-mapping" ? `Excluir regra · ${visibleText(editor.mapping.match_value)}`
    : editor.kind === "connection-credentials" ? `Credenciais do Indexer · ${visibleText(editor.connection.name)}`
    : editor.kind === "connection-ca" ? `Atualizar certificado CA · ${visibleText(editor.connection.name)}`
    : editor.kind === "asset-api-endpoint" ? `Endereço comum da API · ${visibleText(editor.connection.name)}`
    : editor.kind === "asset-api" ? `Acessos da empresa · ${visibleText(editor.company.name)}`
    : editor.kind === "invite" ? "Convidar usuário" : editor.kind === "mapping" ? editor.mapping ? "Editar regra de roteamento" : "Adicionar regra de roteamento"
    : editor.kind === "shared-company" ? "Adicionar empresa ao indexador compartilhado"
    : editor.kind === "membership" ? "Editar vínculo com empresa" : `${editor.active ? "Desativar" : "Reativar"} ${editor.name}`;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const field = (key: string) => String(form.get(key) ?? "").trim();
    const saveCompanyAccess = (connectionId: string, tenantId: string) => run({ action: "configure_tenant_access", connectionId, tenantId,
      indexerUsername: field("indexerUsername"), indexerPassword: String(form.get("indexerPassword") ?? ""),
      assetApiUsername: field("assetApiUsername"), assetApiPassword: String(form.get("assetApiPassword") ?? ""),
      caCertificate: field("caCertificate") || null, assetApiCaCertificate: field("assetApiCaCertificate") || null,
    }, "Empresa configurada. Os acessos foram salvos.");
    let payload: Record<string, unknown>; let message: string;
    if (editor.kind === "company") {
      for (const theme of ["dark", "light"] as const) {
        const file = form.get(`logo_${theme}`);
        if (file instanceof File && file.size > 0 && (file.size > 1_048_576 || !["image/png", "image/jpeg", "image/webp"].includes(file.type))) {
          notify({ title: "Use logos PNG, JPG ou WebP de até 1 MB.", error: true }); return;
        }
      }
      payload = { action: editor.company ? "update_company" : "create_company", id: editor.company?.id, name: field("name") };
      message = editor.company ? "Empresa atualizada." : "Empresa criada.";
    const result = await run(payload, message);
      if (!result) return;
      const companyId = editor.company?.id ?? String(result.id);
      for (const theme of ["dark", "light"] as const) {
        const file = form.get(`logo_${theme}`);
        const remove = !(file instanceof File && file.size > 0) && form.get(`remove_${theme}`) === "on";
        if (!(file instanceof File && file.size > 0) && !remove) continue;
        try {
          const image = remove ? null : await imageDataUrl(file as File);
          if (!await run({ action: "set_company_logo", id: companyId, theme, image }, `Logo para tema ${theme === "dark" ? "escuro" : "claro"} atualizada.`)) {
            close(); return;
          }
        } catch (error) { notify({ title: (error as Error).message, error: true }); close(); return; }
      }
      close(); return;
    }
    else if (editor.kind === "delete-company") { payload = { action: "delete_company", id: editor.company.id }; message = "Empresa excluída."; }
    else if (editor.kind === "delete-connection") { payload = { action: "delete_connection", id: editor.connection.id, confirmName: field("confirmName") }; message = "Integração excluída. Nenhum histórico foi removido."; }
    else if (editor.kind === "delete-mapping") { payload = { action: "delete_agent_mapping", mappingId: editor.mapping.id, confirmValue: field("confirmValue") }; message = `Regra ${visibleText(editor.mapping.match_value)} excluída.`; }
    else if (editor.kind === "connection") { payload = { action: editor.connection ? "update_connection" : "create_connection", id: editor.connection?.id, name: field("name"), endpointUrl: `https://${field("host")}:${field("indexerPort")}`, assetApiUrl: `https://${field("host")}:${field("managerPort")}`, mode, tenantId: mode === "dedicated" ? field("company") : null, ...(!editor.connection ? { indexerUsername: field("indexerUsername"), indexerPassword: String(form.get("indexerPassword") ?? ""), caCertificate: field("caCertificate") || null } : {}) }; message = editor.connection ? "Integração atualizada." : "Ambiente criado. Configure os acessos de cada empresa."; }
    else if (editor.kind === "connection-credentials") { payload = { action: "configure_connection", connectionId: editor.connection.id, indexerUsername: field("indexerUsername"), indexerPassword: String(form.get("indexerPassword") ?? ""), caCertificate: field("caCertificate") || null }; message = editor.connection.is_active ? "Credenciais do Indexer salvas. A próxima leitura usará o novo acesso." : "Credenciais do Indexer salvas. Reative a integração quando terminar a configuração."; }
    else if (editor.kind === "connection-ca") { payload = { action: "update_connection_ca", connectionId: editor.connection.id, caCertificate: field("caCertificate") }; message = `Certificado CA de ${visibleText(editor.connection.name)} atualizado. O conector receberá a alteração na próxima leitura de configuração.`; }
    else if (editor.kind === "asset-api-endpoint") { payload = { action: "configure_asset_api_endpoint", connectionId: editor.connection.id, assetApiUrl: field("assetApiUrl") }; message = "Endereço comum da API salvo para esta integração."; }
    else if (editor.kind === "asset-api") { payload = { action: "configure_tenant_access", connectionId: editor.connection.id, tenantId: editor.company.id, indexerUsername: field("indexerUsername"), indexerPassword: String(form.get("indexerPassword") ?? ""), caCertificate: field("caCertificate") || null, assetApiUsername: field("assetApiUsername"), assetApiPassword: String(form.get("assetApiPassword") ?? ""), assetApiCaCertificate: field("assetApiCaCertificate") || null }; message = `Acessos ao Indexer e ao Manager salvos para ${visibleText(editor.company.name)}. O coletor usará estas credenciais.`; }
    else if (editor.kind === "invite") { payload = inviteKind === "pier" ? { action: "invite_pier_user", fullName: field("name"), email: field("email") } : { action: "invite_user", email: field("email"), tenantId: field("company"), role: field("role") }; message = "Acesso liberado. Novos usuários recebem o convite por e-mail."; }
    else if (editor.kind === "membership") { payload = { action: "update_membership", id: editor.membership.id, role: field("role"), isActive: field("active") === "true" }; message = "Vínculo atualizado."; }
    else if (editor.kind === "mapping") { payload = editor.mapping
      ? { action: "update_agent_mapping", mappingId: editor.mapping.id, matchType: field("matchType"), matchValue: field("matchValue") }
      : { action: "set_agent_mapping", connectionId: editor.connectionId, tenantId: field("company"), matchType: field("matchType"), matchValue: field("matchValue") };
      message = editor.mapping ? "Regra atualizada." : "Regra adicionada."; }
    else if (editor.kind === "shared-company") { payload = { action: "create_shared_company", connectionId: editor.connectionId, tenantId: sharedCompanyTarget === "existing" ? field("company") : null, name: sharedCompanyTarget === "new" ? field("name") : null, agentNamePrefix: field("prefix"), group: field("group") }; message = "Empresa vinculada. Salvando acessos."; }
    else { payload = { action: editor.entity === "company" ? "update_company" : "update_connection", id: editor.id, isActive: !editor.active }; message = `${editor.name} ${editor.active ? "desativada" : "reativada"}.`; }
    const result = await run(payload, message);
    if (!result) return;
    if (editor.kind === "connection" && !editor.connection) {
      const connectionId = String(result.connectionId ?? result.id ?? "");
      const name = field("name");
      const tenantId = mode === "dedicated" ? field("company") : null;
      const company = tenantId ? editorData.companies.find((item) => item.id === tenantId) : undefined;
      const created: AdminConnection = { id: connectionId, name, mode, tenant_id: tenantId, endpoint_url: `https://${field("host")}:${field("indexerPort")}`, is_active: true, latest_sync: null, indexer_credentials_configured: false, asset_api_configured_tenant_ids: [] };
      if (connectionId && company && await saveCompanyAccess(connectionId, company.id)) { close(); return; }
      if (connectionId && company) setEditor({ kind: "asset-api", connection: { ...created, asset_api_url: `https://${field("host")}:${field("managerPort")}` }, company });
      else close();
      return;
    }
    if (editor.kind === "shared-company") {
      const tenantId = String(result.tenantId ?? result.entityId ?? (sharedCompanyTarget === "existing" ? field("company") : ""));
      const company = editorData.companies.find((item) => item.id === tenantId) ?? {
        id: tenantId, name: visibleText(typeof result.name === "string" ? result.name : field("name")),
        slug: typeof result.slug === "string" ? result.slug : "", is_active: true, user_count: 0,
        connection_count: 1, logo_dark_path: null, logo_light_path: null,
      };
      const connection = editorData.connections.find((item) => item.id === editor.connectionId);
      if (!connection || !tenantId) { close(); return; }
      if (connection.asset_api_url && await saveCompanyAccess(connection.id, tenantId)) { close(); return; }
      setEditor(connection.asset_api_url
        ? { kind: "asset-api", connection, company }
        : { kind: "asset-api-endpoint", connection, nextCompany: company });
      return;
    }
    if (editor.kind === "asset-api-endpoint" && editor.nextCompany) {
      setEditor({ kind: "asset-api", connection: { ...editor.connection, asset_api_url: field("assetApiUrl") }, company: editor.nextCompany });
      return;
    }
    if (editor.kind === "connection-credentials" && editor.nextCompany) {
      const connection = { ...editor.connection, indexer_credentials_configured: true };
      setEditor(connection.asset_api_url
        ? { kind: "asset-api", connection, company: editor.nextCompany }
        : { kind: "asset-api-endpoint", connection, nextCompany: editor.nextCompany });
      return;
    }
    close();
  }
  return <dialog className="admin-dialog" ref={dialog} onCancel={(e) => { if (busy) e.preventDefault(); else cancel(); }} onClick={(e) => { if (e.target === e.currentTarget && !busy) cancel(); }} aria-labelledby="admin-dialog-title">
    <div className="admin-dialog-header"><h2 id="admin-dialog-title">{title}</h2><button className="icon-button" aria-label="Fechar formulário" disabled={busy} onClick={cancel}>Fechar</button></div>
    <form onSubmit={(e) => void submit(e)} className="admin-editor-form"><fieldset disabled={busy}>
      {(editor.kind === "company" || editor.kind === "connection") && <label>Nome<input name="name" required minLength={2} maxLength={160} defaultValue={visibleText(editor.kind === "company" ? editor.company?.name : editor.connection?.name)} onInput={(e) => { e.currentTarget.value = visibleText(e.currentTarget.value); }} autoFocus /></label>}
      {editor.kind === "company" && <div className="company-logo-fields">{(["dark", "light"] as const).map((theme) => {
        const path = theme === "dark" ? editor.company?.logo_dark_path : editor.company?.logo_light_path;
        const url = path ? client.storage.from("company-logos").getPublicUrl(path).data.publicUrl : null;
        return <div className="company-logo-field" key={theme}>
          <label>Logo para tema {theme === "dark" ? "escuro" : "claro"}<input name={`logo_${theme}`} type="file" accept="image/png,image/jpeg,image/webp" /><small>PNG, JPG ou WebP · até 1 MB</small></label>
          {url && <div className={`company-logo-preview ${theme}`}><img src={url} alt={`Logo atual para tema ${theme === "dark" ? "escuro" : "claro"}`} /><label><input name={`remove_${theme}`} type="checkbox" /> Remover logo</label></div>}
        </div>;
      })}</div>}
      {editor.kind === "delete-company" && <p>Excluir {visibleText(editor.company.name)}? Esta ação é permanente e só funciona quando a empresa não possui vínculos nem dados.</p>}
      {editor.kind === "delete-connection" && <><p>Esta ação remove a integração e suas configurações. O sistema bloqueia a exclusão se encontrar qualquer leitura, ativo ou histórico.</p><p>Se a integração já foi usada, desative-a para preservar os dados.</p><label>Digite <strong>{visibleText(editor.connection.name)}</strong> para confirmar<input name="confirmName" required autoComplete="off" /></label></>}
      {editor.kind === "delete-mapping" && <><p>A regra deixará de existir. Isso não apaga achados já associados à empresa.</p><label>Digite <strong>{visibleText(editor.mapping.match_value)}</strong> para confirmar<input name="confirmValue" required autoComplete="off" /></label></>}
      {editor.kind === "connection" && <>
        <label>Tipo de ambiente<select value={mode} disabled={!!editor.connection} onChange={(e) => setMode(e.target.value)}><option value="shared">Compartilhado</option><option value="dedicated">Dedicado</option></select></label>
        <p className="muted-copy">{mode === "shared" ? "Um IP para todas as empresas. Cada empresa tem seus próprios acessos ao Indexer e ao Manager." : "Um IP exclusivo para esta empresa. Os acessos ao Indexer e ao Manager ficam no cadastro dela."}</p>
        <label>IP ou hostname<input name="host" required maxLength={253} placeholder="192.168.100.110" pattern="[A-Za-z0-9.-]+" defaultValue={editor.connection ? new URL(editor.connection.endpoint_url).hostname : ""} /></label>
        <label>Porta do Indexer<input name="indexerPort" type="number" required min={1} max={65535} defaultValue={editor.connection ? new URL(editor.connection.endpoint_url).port || "443" : "9200"} /></label>
        <label>Porta do Manager<input name="managerPort" type="number" required min={1} max={65535} defaultValue={editor.connection?.asset_api_url ? new URL(editor.connection.asset_api_url).port || "443" : "55000"} /></label>
        {mode === "dedicated" && !editor.connection && <CompanyAccessFields required />}
        {mode === "dedicated" && <label>Empresa<select name="company" required disabled={!!editor.connection} defaultValue={editor.connection?.tenant_id ?? ""}><option value="">Selecione uma empresa</option>{(editor.connection ? data.companies : activeCompanies).map((c) => <option key={c.id} value={c.id}>{visibleText(c.name)}</option>)}</select></label>}
      </>}
      {editor.kind === "connection-credentials" && <><p>{editor.connection.mode === "shared" ? "Estas credenciais dão acesso ao Indexer compartilhado. Usuário e senha da API do Manager continuam exclusivos de cada empresa." : "Estas credenciais dão acesso ao Indexer desta integração."}</p><label>Usuário do Indexer<input name="indexerUsername" required maxLength={256} autoComplete="off" /></label><label>Senha do Indexer<input name="indexerPassword" type="password" required maxLength={4096} autoComplete="new-password" /></label><CertificateInput name="caCertificate" label="Certificado do Indexer" /><p className="muted-copy">Salvar renova o token de ingestão. O coletor recebe o novo valor na próxima leitura de configuração.{!editor.connection.is_active ? " Esta integração está inativa; reative-a para iniciar a coleta." : ""}</p></>}
      {editor.kind === "connection-ca" && <><p>Substitui apenas o certificado CA desta conexão. Usuário, senha e token atual serão preservados.</p><CertificateInput name="caCertificate" label="Certificado do Indexer" required /><p className="muted-copy">Envie o arquivo do certificado. TXT com certificado também é aceito.</p></>}
      {editor.kind === "asset-api-endpoint" && <><p>Este endereço será usado por todas as empresas vinculadas. Cada empresa terá usuário e senha próprios.</p><label>Endereço HTTPS comum da API<input name="assetApiUrl" type="url" required maxLength={2048} defaultValue={editor.connection.asset_api_url ?? ""} placeholder="https://192.168.100.110:55000" pattern="https://.*" /></label><small>Informe o IP e a porta uma vez para esta integração compartilhada.</small>{editor.nextCompany && <p className="muted-copy">Depois de salvar, você vai configurar o acesso de {visibleText(editor.nextCompany.name)}.</p>}</>}
      {editor.kind === "asset-api" && <>
        <p>Empresa: <strong>{visibleText(editor.company.name)}</strong> · IP: {new URL(editor.connection.endpoint_url).hostname}</p>
        <p className="muted-copy">Preencha os acessos desta empresa. Ao editar, campos vazios mantêm os valores salvos.</p>
        <CompanyAccessFields certificates={editor.connection.tenant_certificates?.[editor.company.id]} />
        {!editor.connection.is_active && <p className="muted-copy">Ambiente pausado. Ative-o após configurar as empresas.</p>}
      </>}
      {editor.kind === "shared-company" && <><label>Empresa<select value={sharedCompanyTarget} onChange={(e) => setSharedCompanyTarget(e.target.value)}><option value="new">Cadastrar nova empresa</option><option value="existing">Vincular empresa já cadastrada</option></select></label>{sharedCompanyTarget === "new" ? <label>Nome da empresa<input name="name" required minLength={2} maxLength={160} placeholder="Yamam" autoFocus onInput={(e) => { e.currentTarget.value = visibleText(e.currentTarget.value); }} /></label> : <label>Empresa cadastrada<select name="company" required defaultValue=""><option value="">Selecione uma empresa</option>{activeCompanies.map((company) => <option key={company.id} value={company.id}>{visibleText(company.name)}</option>)}</select></label>}<label>Prefixo de agent.name<input name="prefix" required maxLength={80} pattern="[A-Za-z0-9._-]+" placeholder="100" /><small>Informe o começo do nome, sem o asterisco. Exemplo: 100.</small></label><label>Grupo da empresa<input name="group" required maxLength={160} pattern="[A-Za-z0-9._-]+" placeholder="yamam-tenant" /></label><p className="muted-copy">O grupo e o prefixo identificam os agentes desta empresa.</p><CompanyAccessFields required /></>}
      {editor.kind === "invite" && <><label>Tipo de acesso<select value={inviteKind} onChange={(e) => setInviteKind(e.target.value)}><option value="client">Cliente</option><option value="pier">Equipe Pier (admin interno)</option></select></label>{inviteKind === "pier" && <><label>Nome completo<input name="name" required maxLength={160} autoComplete="name" /></label><p className="muted-copy">Todos os membros da equipe Pier têm acesso administrativo interno.</p></>}<label>E-mail<input name="email" type="email" required maxLength={320} autoComplete="email" /></label></>}
      {editor.kind === "mapping" && editor.mapping && <p className="muted-copy">Empresa: {visibleText(editorData.companies.find((company) => company.id === editor.mapping?.tenant_id)?.name ?? "Compartilhada")} · estado: {editor.mapping.is_active ? "ativa" : "inativa"}</p>}
      {(editor.kind === "mapping" && !editor.mapping || (editor.kind === "invite" && inviteKind === "client")) && <label>Empresa<select name="company" required defaultValue=""><option value="">Selecione uma empresa</option>{activeCompanies.map((c) => <option key={c.id} value={c.id}>{visibleText(c.name)}</option>)}</select></label>}
      {(editor.kind === "membership" || (editor.kind === "invite" && inviteKind === "client")) && <label>Perfil<select name="role" defaultValue={editor.kind === "membership" ? editor.membership.role : "analyst"}>{Object.entries(roleLabels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>}
      {editor.kind === "membership" && <><p className="muted-copy">{editor.email}</p><label>Estado do vínculo<select name="active" defaultValue={String(editor.membership.is_active)}><option value="true">Ativo</option><option value="false">Inativo</option></select></label><p className="muted-copy">Desativar impede o acesso pela empresa e preserva os casos e comentários.</p></>}
      {editor.kind === "mapping" && <><label>Tipo de vínculo<select name="matchType" defaultValue={editor.mapping?.match_type ?? "agent_id"}><option value="agent_id">ID do agente</option><option value="group">Grupo</option><option value="agent_name_prefix">Prefixo de agent.name</option></select></label><label>Valor<input name="matchValue" required maxLength={256} defaultValue={editor.mapping?.match_value} placeholder="200*" onInput={(e) => { e.currentTarget.value = visibleText(e.currentTarget.value); }} /></label></>}
      {editor.kind === "toggle" && <p>{editor.entity === "connection"
        ? editor.active ? "A coleta desta integração será interrompida. Empresas, regras, credenciais e histórico serão preservados."
          : "A integração ficará disponível para coleta na próxima execução. Só serão usados os vínculos ativos; regras desligadas continuam desligadas."
        : editor.active ? "O acesso da empresa será interrompido. Vínculos e histórico serão preservados para reativação."
          : "O acesso da empresa será restaurado com os mesmos vínculos e histórico."}</p>}
    </fieldset><div className="admin-dialog-footer"><button className="button button-secondary" type="button" disabled={busy} onClick={cancel}>Cancelar</button>{editor.kind === "asset-api" && editor.connection.asset_api_configured_tenant_ids?.includes(editor.company.id) && <button className="button button-secondary button-destructive" type="button" disabled={busy} onClick={() => void run({ action: "disable_asset_api", connectionId: editor.connection.id, tenantId: editor.company.id }, `Acesso da API desligado para ${visibleText(editor.company.name)}.`).then((ok) => { if (ok) close(); })}>Desligar Manager desta empresa</button>}{editor.kind === "mapping" && editor.mapping && <button className="button button-secondary button-destructive" type="button" disabled={busy} onClick={() => setEditor({ kind: "delete-mapping", mapping: editor.mapping! })}>Excluir regra</button>}<button className={`button ${editor.kind === "delete-company" || editor.kind === "delete-connection" || editor.kind === "delete-mapping" ? "button-secondary button-destructive" : "button-primary"}`} disabled={busy || (editor.kind === "asset-api" && !editor.connection.asset_api_url)}>{busy ? "Salvando…" : editor.kind === "delete-company" || editor.kind === "delete-connection" || editor.kind === "delete-mapping" ? "Excluir permanentemente" : editor.kind === "toggle" ? editor.active ? "Desativar" : "Reativar" : editor.kind === "invite" ? "Liberar acesso" : editor.kind === "shared-company" ? "Salvar empresa e acessos" : editor.kind === "connection-credentials" ? "Salvar credenciais" : editor.kind === "connection-ca" ? "Salvar certificado" : "Salvar"}</button></div></form>
  </dialog>;
}

function CompanyAccessFields({ required = false, certificates }: { required?: boolean; certificates?: { indexer: boolean; manager: boolean } }) { return <>
        <h3>Indexer · vulnerabilidades</h3>
        <label>Usuário do Indexer<input name="indexerUsername" required={required} maxLength={256} autoComplete="off" /></label>
        <label>Senha do Indexer<input name="indexerPassword" type="password" required={required} maxLength={4096} autoComplete="new-password" /></label>
        <h3>Manager · ativos</h3>
        <label>Usuário do Manager<input name="assetApiUsername" required={required} maxLength={256} autoComplete="off" /></label>
        <label>Senha do Manager<input name="assetApiPassword" type="password" required={required} maxLength={4096} autoComplete="new-password" /></label>
        <CertificateInput name="caCertificate" label="Certificado do Indexer" saved={certificates?.indexer} /><CertificateInput name="assetApiCaCertificate" label="Certificado do Manager" saved={certificates?.manager} />

</>; }
