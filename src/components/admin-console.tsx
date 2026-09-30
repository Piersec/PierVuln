"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import type { Session, SupabaseClient } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import { NavSymbol } from "@/src/components/ui/nav-symbol";
import { useSiteNotifications } from "@/src/components/site-notifications";
import { type NoticeInput } from "@/src/lib/admin-notifications";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { AdminRequestError, adminDate, archiveLabels, invokeAdmin, roleLabels, syncLabels, type AdminArchive, type AdminCompany, type AdminConnection, type AdminData, type AdminMembership } from "@/src/lib/admin";

type Section = "dashboard" | "tenants" | "integrations" | "users" | "audit";
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
  const [session, setSession] = useState<Session | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [access, setAccess] = useState<"checking" | "allowed" | "denied" | "error">("checking");
  const [data, setData] = useState<AdminData | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState("");
  const { notify, clear, setIslandHost, beginMutation, endMutation, revision } = useSiteNotifications();
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

  const reload = useCallback(async () => {
    if (!client || access !== "allowed") return;
    const id = ++requestId.current;
    setLoading(true); setLoadError("");
    try {
      const next = await invokeAdmin<AdminData>(client, { action: "panel_data", ...query });
      if (id === requestId.current) setData(next);
    } catch (error) {
      if (id === requestId.current) {
        setLoadError((error as Error).message);
        if (error instanceof AdminRequestError && (error.status === 401 || error.status === 403)) { setAccess("denied"); setData(null); clear(); }
      }
    }
    finally { if (id === requestId.current) setLoading(false); }
  }, [access, client, query]);
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

  if (!client) return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Configuração necessária</h1><p>Configure a conexão pública com o Supabase para abrir o painel.</p></section></main>;
  if (!authReady || (session && access === "checking")) return <main className="loading-screen"><Brand /><div className="spinner" /><p>Verificando acesso administrativo…</p></main>;
  if (!session) return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Administração Pier</h1><p>Entre com a conta da equipe para continuar.</p><Link className="button button-primary" href="/login">Entrar</Link></section></main>;
  if (access !== "allowed") return <main className="auth-shell"><section className="auth-card"><Brand /><h1>{access === "error" ? "Não foi possível verificar o acesso" : "Acesso restrito"}</h1><p>Esta área é exclusiva da equipe Pier.</p><Link className="button button-secondary" href="/">Voltar ao painel</Link>{access === "error" && <button className="button button-secondary" onClick={() => window.location.reload()}>Tentar novamente</button>}</section></main>;

  return <AdminContext.Provider value={{ client, data, loading, busy, loadError, query, setQuery, reload, notify, run, setIslandHost }}>
    <main className="app-shell admin-shell">
      <a className="skip-link" href="#admin-content">Pular para o conteúdo</a>
      <aside className="sidebar has-admin"><Brand /><nav className="workspace-nav" aria-label="Navegação principal">
        <Link className="nav-link" href="/" aria-label="Vulnerabilidades" title="Vulnerabilidades"><NavSymbol kind="vulnerabilities" /></Link>
        <Link className="nav-link" href="/book" aria-label="Book dos Clientes" title="Book dos Clientes"><NavSymbol kind="book" /></Link>
        <Link className="nav-link active" href="/admin" aria-label="Administração" title="Administração"><NavSymbol kind="admin" /></Link>
      </nav><div className="sidebar-bottom"><div className="avatar" aria-hidden="true">{session.user.email?.slice(0, 1).toUpperCase()}</div><button className="sidebar-signout" onClick={() => { setData(null); clear(); setAccess("checking"); void client.auth.signOut(); }}>Sair</button></div></aside>
      <section className="main-column"><header className="topbar"><div className="breadcrumb">ADMIN <span>/</span><strong>{sections.find((s) => s.href === pathname)?.label ?? "Administração"}</strong></div><button className="button button-secondary" disabled={loading} onClick={() => void reload()}>{loading ? "Atualizando…" : "Atualizar"}</button></header>
        <div className="content-wrap admin-content" id="admin-content" tabIndex={-1}>
          <nav className="admin-tabs" aria-label="Administração">{sections.map((s) => <Link href={s.href} key={s.key} className={pathname === s.href ? "active" : ""} aria-current={pathname === s.href ? "page" : undefined}>{s.label}</Link>)}</nav>
          {loadError && <div className="inline-alert" role="alert">{loadError}<button className="button button-secondary" onClick={() => void reload()}>Tentar novamente</button></div>}
          {loading && !data ? <div className="admin-loading" role="status"><div className="spinner" />Carregando dados administrativos…</div> : data && children}
        </div>
      </section>
    </main>
  </AdminContext.Provider>;
}

type Editor = { kind: "company"; company?: AdminCompany } | { kind: "connection"; connection?: AdminConnection } | { kind: "invite" } | { kind: "mapping"; connectionId: string } | { kind: "membership"; membership: AdminMembership; email: string } | { kind: "toggle"; entity: "company" | "connection"; id: string; name: string; active: boolean };

export function AdminSection({ section }: { section: Section }) {
  const { data, client, busy, query, setQuery, run, notify } = useAdmin();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [companyFilter, setCompanyFilter] = useState("");
  const [editor, setEditor] = useState<Editor | null>(null);
  const [archiveLink, setArchiveLink] = useState<{ id: string; url: string } | null>(null);
  const [downloadBusy, setDownloadBusy] = useState<string | null>(null);
  if (!data) return null;
  const companyName = (id: string | null) => data.companies.find((c) => c.id === id)?.name ?? "Compartilhada";
  const matches = (value: string) => value.toLocaleLowerCase("pt-BR").includes(search.toLocaleLowerCase("pt-BR"));
  const companies = data.companies.filter((c) => matches(`${c.name} ${c.slug}`) && (!status || String(c.is_active) === status));
  const connections = data.connections.filter((c) => matches(`${c.name} ${c.endpoint_url}`) && (!status || String(c.is_active) === status)
    && (!companyFilter || c.tenant_id === companyFilter || data.mappings.some((m) => m.connection_id === c.id && m.tenant_id === companyFilter && m.is_active)));

  async function download(archive: AdminArchive) {
    setDownloadBusy(archive.id); setArchiveLink(null);
    try {
      const { data: link, error } = await client.storage.from(archive.bucket_name).createSignedUrl(archive.object_path, 300, { download: `${archive.id}.json.gz` });
      if (error || !link?.signedUrl) throw new Error("Não foi possível preparar o download do arquivo.");
      setArchiveLink({ id: archive.id, url: link.signedUrl }); notify({ title: "Download preparado. O link vale por cinco minutos." });
    } catch (error) { notify({ title: (error as Error).message, error: true }); }
    finally { setDownloadBusy(null); }
  }

  return <>
    <div className="page-heading"><div><h1>{sections.find((s) => s.key === section)?.label}</h1><p>{({ dashboard: "Clientes, acessos e estado das fontes Wazuh.", tenants: "Gerencie empresas e preserve o histórico de cada cliente.", integrations: "Conexões Wazuh e vínculos de agentes e grupos.", users: "Equipe Pier e acessos dos clientes por empresa.", audit: "Arquivos de retenção, integridade e validade dos downloads." })[section]}</p></div>
      {section === "tenants" && <button className="button button-primary" onClick={() => setEditor({ kind: "company" })}>Nova empresa</button>}
      {section === "integrations" && <button className="button button-primary" onClick={() => setEditor({ kind: "connection" })}>Nova integração</button>}
      {section === "users" && <button className="button button-primary" onClick={() => setEditor({ kind: "invite" })}>Convidar usuário</button>}
    </div>
    {section === "dashboard" && <>
      <div className="admin-metrics">
        <Link className="admin-metric" href="/admin/tenants"><span>Empresas</span><strong>{data.stats.active_companies + data.stats.inactive_companies}</strong><small>{data.stats.active_companies} ativas · {data.stats.inactive_companies} inativas</small></Link>
        <Link className="admin-metric" href="/admin/users"><span>Usuários vinculados</span><strong>{data.stats.users}</strong><small>Equipe Pier e clientes</small></Link>
        <Link className="admin-metric" href="/admin/integrations"><span>Conexões Wazuh</span><strong>{data.stats.connections}</strong><small>{data.stats.active_connections} ativas · {data.stats.connections - data.stats.active_connections} inativas</small></Link>
      </div>
      <section className="panel admin-list-panel"><div className="panel-heading"><h2>Última sincronização por conexão</h2><Link className="button button-secondary" href="/admin/integrations">Gerenciar integrações</Link></div>
        <DataTable headings={["Conexão", "Empresa", "Estado", "Última execução", "Documentos"]} empty={!data.connections.length}>
          {data.connections.map((c) => <tr key={c.id}><td>{c.name}<small>{c.is_active ? "Ativa" : "Inativa"}</small></td><td>{companyName(c.tenant_id)}</td><td><SyncStatus connection={c} /></td><td>{adminDate(c.latest_sync?.finished_at ?? c.latest_sync?.started_at)}</td><td>{c.latest_sync ? c.latest_sync.documents_received.toLocaleString("pt-BR") : "Sem execução"}</td></tr>)}
        </DataTable>
      </section>
    </>}
    {(section === "tenants" || section === "integrations") && <div className="admin-filters"><label><span className="sr-only">Buscar {section === "tenants" ? "empresa" : "integração"}</span><input type="search" placeholder={section === "tenants" ? "Buscar empresa…" : "Buscar integração…"} value={search} onChange={(e) => setSearch(e.target.value)} /></label><label><span className="sr-only">Filtrar por status</span><select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Todos os status</option><option value="true">Ativas</option><option value="false">Inativas</option></select></label>{section === "integrations" && <label><span className="sr-only">Filtrar por empresa</span><select value={companyFilter} onChange={(e) => setCompanyFilter(e.target.value)}><option value="">Todas as empresas</option>{data.companies.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>}</div>}
    {section === "tenants" && <section className="panel admin-list-panel"><DataTable headings={["Empresa", "Usuários ativos", "Conexões", "Status", "Ações"]} empty={!companies.length}>
      {companies.map((c) => <tr key={c.id}><td><strong>{c.name}</strong><small>{c.slug}</small></td><td>{c.user_count}</td><td>{c.connection_count}</td><td><ActiveStatus active={c.is_active} /></td><td><div className="admin-row-actions"><button className="button button-secondary" onClick={() => setEditor({ kind: "company", company: c })}>Editar</button><button className="button button-secondary" onClick={() => setEditor({ kind: "toggle", entity: "company", id: c.id, name: c.name, active: c.is_active })}>{c.is_active ? "Desativar" : "Reativar"}</button></div></td></tr>)}
    </DataTable></section>}
    {section === "integrations" && <section className="panel admin-list-panel"><DataTable headings={["Conexão / vínculos", "Empresa", "Endpoint", "Sincronização", "Status", "Ações"]} empty={!connections.length}>
      {connections.map((c) => <tr key={c.id}><td><strong>{c.name}</strong><small>{c.mode === "shared" ? "Compartilhada" : "Dedicada"}</small>{c.mode === "shared" && <details className="admin-mappings"><summary>Vínculos de agentes e grupos ({data.mappings.filter((m) => m.connection_id === c.id).length})</summary>{data.mappings.filter((m) => m.connection_id === c.id).map((m) => <div key={m.id}><span>{m.match_type === "group" ? "Grupo" : "Agente"}: {m.match_value}<small>{companyName(m.tenant_id)} · {m.is_active ? "Ativo" : "Inativo"}</small></span>{m.is_active && <button className="button button-secondary" disabled={busy} onClick={() => void run({ action: "disable_agent_mapping", mappingId: m.id }, "Vínculo desativado.")}>Desativar</button>}</div>)}<button className="button button-secondary" disabled={!c.is_active} onClick={() => setEditor({ kind: "mapping", connectionId: c.id })}>Adicionar ou reativar vínculo</button></details>}</td><td>{companyName(c.tenant_id)}</td><td className="admin-endpoint">{c.endpoint_url}</td><td><SyncStatus connection={c} /><small>{adminDate(c.latest_sync?.finished_at ?? c.latest_sync?.started_at)}</small></td><td><ActiveStatus active={c.is_active} /></td><td><div className="admin-row-actions"><button className="button button-secondary" onClick={() => setEditor({ kind: "connection", connection: c })}>Editar</button><button className="button button-secondary" onClick={() => setEditor({ kind: "toggle", entity: "connection", id: c.id, name: c.name, active: c.is_active })}>{c.is_active ? "Desativar" : "Reativar"}</button></div></td></tr>)}
    </DataTable></section>}
    {section === "users" && <>
      <div className="admin-filters"><label><span className="sr-only">Buscar usuário</span><input type="search" placeholder="Buscar nome ou e-mail…" value={query.search} onChange={(e) => setQuery({ ...query, search: e.target.value, page: 0 })} /></label><label><span className="sr-only">Filtrar usuários por equipe ou empresa</span><select value={query.scope} onChange={(e) => setQuery({ ...query, scope: e.target.value, page: 0 })}><option value="">Todos os usuários</option><option value="pier">Equipe Pier</option>{data.companies.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label></div>
      <section className="panel admin-list-panel"><DataTable headings={["Nome / e-mail", "Acesso", "Empresas e perfis", "Cadastro", "Ações"]} empty={!data.users.length}>
        {data.users.map((u) => <tr key={u.id}><td><strong>{u.display_name}</strong><small>{u.email}</small></td><td>{u.is_internal ? <span className="admin-status positive">Admin · Equipe Pier</span> : "Cliente"}</td><td>{u.memberships.length ? u.memberships.map((m) => <div className="admin-membership" key={m.id}><span>{companyName(m.company_id)}<small>{roleLabels[m.role]} · {m.is_active ? "Ativo" : "Inativo"}</small></span><button className="button button-secondary" onClick={() => setEditor({ kind: "membership", membership: m, email: u.email })}>Editar vínculo</button></div>) : <span className="muted-copy">{u.is_internal ? "Acesso administrativo a todas as empresas" : "Sem empresa vinculada"}</span>}</td><td><span>{u.email_confirmed_at ? "Cadastro concluído" : u.invited_at ? "Convite pendente" : "Não confirmado"}</span><small>Último acesso: {adminDate(u.last_sign_in_at)}</small></td><td>{u.invited_at && !u.email_confirmed_at ? <button className="button button-secondary" disabled={busy} onClick={() => void run({ action: "resend_invite", id: u.id }, "Convite reenviado.")}>Reenviar convite</button> : "Cadastro concluído"}</td></tr>)}
      </DataTable><div className="admin-pagination"><span>{data.user_count} usuários · página {query.page + 1} de {Math.max(1, Math.ceil(data.user_count / 50))}</span><div><button className="button button-secondary" disabled={!query.page} onClick={() => setQuery({ ...query, page: query.page - 1 })}>Anterior</button><button className="button button-secondary" disabled={(query.page + 1) * 50 >= data.user_count} onClick={() => setQuery({ ...query, page: query.page + 1 })}>Próxima</button></div></div></section>
    </>}
    {section === "audit" && <>
      <div className="admin-filters"><label><span className="sr-only">Buscar arquivo</span><input type="search" placeholder="Buscar identificador ou caminho…" value={search} onChange={(e) => setSearch(e.target.value)} /></label><label><span className="sr-only">Filtrar arquivos por status</span><select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Todos os status</option>{Object.entries(archiveLabels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label><span className="muted-copy">Últimos 50 arquivos</span></div>
      <section className="panel admin-list-panel"><DataTable headings={["Arquivo / SHA-256", "Registros", "Arquivado em", "Validade", "Status", "Download"]} empty={!data.archives.some((a) => matches(`${a.id} ${a.object_path}`) && (!status || a.status === status))}>
        {data.archives.filter((a) => matches(`${a.id} ${a.object_path}`) && (!status || a.status === status)).map((a) => <tr key={a.id}><td className="admin-file"><strong>{a.object_path}</strong><small>{a.id}</small><code>{a.checksum_sha256}</code></td><td>{a.record_count.toLocaleString("pt-BR")}</td><td>{adminDate(a.archived_at)}</td><td>{adminDate(a.expires_at)}</td><td>{archiveLabels[a.status] ?? a.status}</td><td>{archiveLink?.id === a.id ? <a className="button button-primary" href={archiveLink.url} download rel="noreferrer">Baixar arquivo</a> : <button className="button button-secondary" disabled={a.status === "expired" || Date.parse(a.expires_at) <= Date.now() || downloadBusy !== null} onClick={() => void download(a)}>{downloadBusy === a.id ? "Preparando…" : "Preparar download"}</button>}</td></tr>)}
      </DataTable></section>
    </>}
    {editor && <AdminEditor editor={editor} close={() => setEditor(null)} />}
  </>;
}

function ActiveStatus({ active }: { active: boolean }) { return <span className={`admin-status${active ? " positive" : ""}`}>{active ? "Ativa" : "Inativa"}</span>; }
function SyncStatus({ connection }: { connection: AdminConnection }) {
  const status = connection.latest_sync?.status;
  return <span className={`admin-status${status === "failed" || status === "partial" ? " caution" : status === "succeeded" ? " positive" : ""}`}>{status ? syncLabels[status] ?? status : "Sem execução"}{connection.latest_sync && !connection.latest_sync.full_snapshot ? " · Incremental" : ""}</span>;
}
function DataTable({ headings, empty, children }: { headings: string[]; empty: boolean; children: ReactNode }) {
  return <div className="admin-table-scroll" role="region" aria-label={headings[0]} tabIndex={0}><table className="admin-table"><thead><tr>{headings.map((h) => <th scope="col" key={h}>{h}</th>)}</tr></thead><tbody>{empty ? <tr><td colSpan={headings.length}><div className="admin-empty">Nenhum registro encontrado para esta seleção.</div></td></tr> : children}</tbody></table></div>;
}

function AdminEditor({ editor, close }: { editor: Editor; close: () => void }) {
  const { data, busy, run, setIslandHost } = useAdmin();
  const dialog = useRef<HTMLDialogElement>(null);
  const [inviteKind, setInviteKind] = useState("client");
  const [mode, setMode] = useState(editor.kind === "connection" ? editor.connection?.mode ?? "dedicated" : "dedicated");
  useEffect(() => {
    dialog.current?.showModal(); setIslandHost(dialog.current);
    return () => setIslandHost(null);
  }, [setIslandHost]);
  if (!data) return null;
  const activeCompanies = data.companies.filter((c) => c.is_active);
  const title = editor.kind === "company" ? editor.company ? "Editar empresa" : "Nova empresa"
    : editor.kind === "connection" ? editor.connection ? "Editar integração Wazuh" : "Nova integração Wazuh"
    : editor.kind === "invite" ? "Convidar usuário" : editor.kind === "mapping" ? "Vínculo de agente ou grupo"
    : editor.kind === "membership" ? "Editar vínculo com empresa" : `${editor.active ? "Desativar" : "Reativar"} ${editor.name}`;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const field = (key: string) => String(form.get(key) ?? "").trim();
    let payload: Record<string, unknown>; let message: string;
    if (editor.kind === "company") { payload = { action: editor.company ? "update_company" : "create_company", id: editor.company?.id, name: field("name") }; message = editor.company ? "Empresa atualizada." : "Empresa criada."; }
    else if (editor.kind === "connection") { payload = { action: editor.connection ? "update_connection" : "create_connection", id: editor.connection?.id, name: field("name"), endpointUrl: field("endpoint"), mode, tenantId: mode === "dedicated" ? field("company") : null }; message = editor.connection ? "Integração atualizada." : "Integração criada. Copie o segredo do conector."; }
    else if (editor.kind === "invite") { payload = inviteKind === "pier" ? { action: "invite_pier_user", fullName: field("name"), email: field("email") } : { action: "invite_user", email: field("email"), tenantId: field("company"), role: field("role") }; message = "Acesso liberado. Novos usuários recebem o convite por e-mail."; }
    else if (editor.kind === "membership") { payload = { action: "update_membership", id: editor.membership.id, role: field("role"), isActive: field("active") === "true" }; message = "Vínculo atualizado."; }
    else if (editor.kind === "mapping") { payload = { action: "set_agent_mapping", connectionId: editor.connectionId, tenantId: field("company"), matchType: field("matchType"), matchValue: field("matchValue") }; message = "Vínculo de agente ou grupo atualizado."; }
    else { payload = { action: editor.entity === "company" ? "update_company" : "update_connection", id: editor.id, isActive: !editor.active }; message = `${editor.name} ${editor.active ? "desativada" : "reativada"}.`; }
    if (await run(payload, message)) close();
  }
  return <dialog className="admin-dialog" ref={dialog} onCancel={(e) => { if (busy) e.preventDefault(); else close(); }} onClick={(e) => { if (e.target === e.currentTarget && !busy) close(); }} aria-labelledby="admin-dialog-title">
    <div className="admin-dialog-header"><h2 id="admin-dialog-title">{title}</h2><button className="icon-button" aria-label="Fechar formulário" disabled={busy} onClick={close}>Fechar</button></div>
    <form onSubmit={(e) => void submit(e)} className="admin-editor-form"><fieldset disabled={busy}>
      {(editor.kind === "company" || editor.kind === "connection") && <label>Nome<input name="name" required minLength={2} maxLength={160} defaultValue={editor.kind === "company" ? editor.company?.name : editor.connection?.name} autoFocus /></label>}
      {editor.kind === "connection" && <><label>Endpoint HTTPS do Wazuh Indexer<input name="endpoint" type="url" required maxLength={2048} placeholder="https://indexer.exemplo.com:9200" defaultValue={editor.connection?.endpoint_url} pattern="https://.*" /></label><label>Tipo<select value={mode} disabled={!!editor.connection} onChange={(e) => setMode(e.target.value)}><option value="dedicated">Dedicada a uma empresa</option><option value="shared">Compartilhada entre empresas</option></select></label>{mode === "dedicated" && <label>Empresa<select name="company" required disabled={!!editor.connection} defaultValue={editor.connection?.tenant_id ?? ""}><option value="">Selecione uma empresa</option>{(editor.connection ? data.companies : activeCompanies).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>}{editor.connection && <p className="muted-copy">O tipo e a empresa preservam a atribuição dos achados históricos.</p>}</>}
      {editor.kind === "invite" && <><label>Tipo de acesso<select value={inviteKind} onChange={(e) => setInviteKind(e.target.value)}><option value="client">Cliente</option><option value="pier">Equipe Pier (admin interno)</option></select></label>{inviteKind === "pier" && <><label>Nome completo<input name="name" required maxLength={160} autoComplete="name" /></label><p className="muted-copy">Todos os membros da equipe Pier têm acesso administrativo interno.</p></>}<label>E-mail<input name="email" type="email" required maxLength={320} autoComplete="email" /></label></>}
      {(editor.kind === "mapping" || (editor.kind === "invite" && inviteKind === "client")) && <label>Empresa<select name="company" required defaultValue=""><option value="">Selecione uma empresa</option>{activeCompanies.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>}
      {(editor.kind === "membership" || (editor.kind === "invite" && inviteKind === "client")) && <label>Perfil<select name="role" defaultValue={editor.kind === "membership" ? editor.membership.role : "analyst"}>{Object.entries(roleLabels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>}
      {editor.kind === "membership" && <><p className="muted-copy">{editor.email}</p><label>Estado do vínculo<select name="active" defaultValue={String(editor.membership.is_active)}><option value="true">Ativo</option><option value="false">Inativo</option></select></label><p className="muted-copy">Desativar impede o acesso pela empresa e preserva os casos e comentários.</p></>}
      {editor.kind === "mapping" && <><label>Identificador<select name="matchType"><option value="agent_id">ID do agente</option><option value="group">Grupo Wazuh</option></select></label><label>Valor<input name="matchValue" required maxLength={256} /></label></>}
      {editor.kind === "toggle" && <p>{editor.active ? "O acesso será interrompido. Casos, vínculos e histórico serão preservados para uma futura reativação." : "O acesso será restaurado com os mesmos vínculos e histórico."}</p>}
    </fieldset><div className="admin-dialog-footer"><button className="button button-secondary" type="button" disabled={busy} onClick={close}>Cancelar</button><button className="button button-primary" disabled={busy}>{busy ? "Salvando…" : editor.kind === "toggle" ? editor.active ? "Desativar" : "Reativar" : editor.kind === "invite" ? "Liberar acesso" : "Salvar"}</button></div></form>
  </dialog>;
}
