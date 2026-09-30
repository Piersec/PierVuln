"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { SiteIsland } from "@/src/components/site-island";
import { NotificationInbox, NotificationLauncher } from "@/src/components/notification-inbox";
import { changeNotice, enqueueNotice, parseAdminChange, type AdminNotice, type NoticeInput } from "@/src/lib/admin-notifications";
import { MAX_INBOX_NOTICES, noticeKind, parseInbox, parseMutedKinds, toInboxNotice, type InboxNotice } from "@/src/lib/notification-inbox";
import { notificationType, parseDisabledNotificationTypes, type NotificationType } from "@/src/lib/notification-types";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { visibleText } from "@/src/lib/visible-text";
import { usePathname } from "next/navigation";

type Notifications = {
  notify: (notice: NoticeInput) => void;
  clear: () => void;
  setIslandHost: (host: HTMLElement | null) => void;
  beginMutation: () => void;
  endMutation: (entityId?: string) => void;
  revision: number;
  disabledNotificationTypes: NotificationType[];
  setNotificationTypeEnabled: (type: NotificationType, enabled: boolean) => Promise<void>;
};
const Context = createContext<Notifications | null>(null);
const storageKey = (owner: string, part: "history" | "muted") => `piervuln:notifications:v1:${owner}:${part}`;
const isAuthRoute = (path: string) => path === "/login" || path === "/reset-password" || path === "/onboarding";
function readHistory(owner: string): InboxNotice[] {
  try { return typeof window === "undefined" ? [] : parseInbox(localStorage.getItem(storageKey(owner, "history"))); }
  catch { return []; }
}
function readMuted(owner: string): string[] {
  try { return typeof window === "undefined" ? [] : parseMutedKinds(localStorage.getItem(storageKey(owner, "muted"))); }
  catch { return []; }
}
export function useSiteNotifications() {
  const context = useContext(Context);
  if (!context) throw new Error("Site notifications provider required");
  return context;
}

export function SiteNotifications({ children }: { children: ReactNode }) {
  const client = getSupabaseBrowserClient();
  const pathname = usePathname();
  const [notices, setNotices] = useState<AdminNotice[]>([]);
  const [history, setHistory] = useState<InboxNotice[]>([]);
  const [mutedKinds, setMutedKinds] = useState<string[]>([]);
  const [disabledNotificationTypes, setDisabledNotificationTypes] = useState<NotificationType[]>([]);
  const [ownerKey, setOwnerKey] = useState("guest");
  const [storageReady, setStorageReady] = useState(false);
  const [inboxOpen, setInboxOpen] = useState(false);
  const [selectedNoticeId, setSelectedNoticeId] = useState<string | null>(null);
  const [host, setIslandHost] = useState<HTMLElement | null>(null);
  const [revision, setRevision] = useState(0);
  const [adminId, setAdminId] = useState<string | null>(null);
  const [authenticatedId, setAuthenticatedId] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const mutation = useRef(false);
  const recentLocal = useRef(new Map<string, number>());
  const owner = useRef("guest");
  const authenticated = useRef(false);
  const muted = useRef(new Set(mutedKinds));
  const disabled = useRef(new Set<NotificationType>());

  useEffect(() => { setStorageReady(true); }, []);
  useEffect(() => {
    if (!storageReady || ownerKey === "guest") return;
    try { localStorage.setItem(storageKey(ownerKey, "history"), JSON.stringify(history)); } catch { /* Storage can be unavailable in private browsing. */ }
  }, [history, ownerKey, storageReady]);
  useEffect(() => {
    if (!storageReady || ownerKey === "guest") return;
    try { localStorage.setItem(storageKey(ownerKey, "muted"), JSON.stringify(mutedKinds)); } catch { /* Storage can be unavailable in private browsing. */ }
  }, [mutedKinds, ownerKey, storageReady]);

  const notify = useCallback((notice: NoticeInput) => {
    if (!authenticated.current || isAuthRoute(pathname)) return;
    if (disabled.current.has(notificationType(notice))) return;
    if (notice.secret) setSecret(notice.secret);
    const incoming: AdminNotice = { ...notice, title: visibleText(notice.title), detail: notice.detail ? visibleText(notice.detail) : undefined, secret: undefined, id: crypto.randomUUID() };
    setHistory((items) => [toInboxNotice(incoming), ...items].slice(0, MAX_INBOX_NOTICES));
    if (!muted.current.has(noticeKind(incoming))) setNotices((queue) => enqueueNotice(queue, incoming));
  }, [pathname]);
  const clear = useCallback(() => { setNotices([]); setSecret(null); }, []);
  const dismiss = useCallback((id: string) => setNotices((queue) => queue.filter((notice) => notice.id !== id)), []);
  const switchOwner = useCallback((next: string) => {
    if (owner.current === next) return;
    owner.current = next;
    authenticated.current = false;
    setAuthenticatedId(null);
    clear();
    setInboxOpen(false);
    setSelectedNoticeId(null);
    setHistory(next === "guest" ? [] : readHistory(next));
    const preferences = next === "guest" ? [] : readMuted(next);
    muted.current = new Set(preferences);
    setMutedKinds(preferences);
    disabled.current = new Set();
    setDisabledNotificationTypes([]);
    setOwnerKey(next);
  }, [clear]);
  const setNotificationTypeEnabled = useCallback(async (type: NotificationType, enabled: boolean) => {
    const id = owner.current;
    if (!client || id === "guest" || !authenticated.current) throw new Error("Sua sessão precisa estar ativa para alterar notificações.");
    const next = new Set(disabled.current);
    if (enabled) next.delete(type); else next.add(type);
    const { data, error } = await client.from("user_profiles")
      .update({ disabled_notification_types: [...next] }).eq("id", id).select("id").single();
    if (error || !data || owner.current !== id) throw new Error("Não foi possível salvar as notificações. Tente novamente.");
    disabled.current = next;
    setDisabledNotificationTypes([...next]);
    if (!enabled) setNotices((queue) => queue.filter((notice) => notificationType(notice) !== type));
  }, [client]);
  const markRead = useCallback((id: string) => setHistory((items) => items.map((item) => item.id === id ? { ...item, read: true } : item)), []);
  const openInbox = useCallback((id?: string) => {
    setSelectedNoticeId(id ?? null);
    if (id) markRead(id);
    setInboxOpen(true);
  }, [markRead]);
  const removeHistory = useCallback((id: string) => {
    setHistory((items) => items.filter((item) => item.id !== id));
    setNotices((queue) => queue.filter((item) => item.id !== id));
    setSelectedNoticeId((selected) => selected === id ? null : selected);
  }, []);
  const clearHistory = useCallback(() => { setHistory([]); setNotices([]); setSelectedNoticeId(null); }, []);
  const markAllRead = useCallback(() => setHistory((items) => items.map((item) => item.read ? item : { ...item, read: true })), []);
  const setKindMuted = useCallback((kind: string, selected: boolean) => {
    const next = new Set(muted.current);
    if (selected) next.add(kind); else next.delete(kind);
    muted.current = next;
    setMutedKinds([...next]);
    if (selected) setNotices((queue) => queue.filter((item) => noticeKind(item) !== kind));
  }, []);
  const beginMutation = useCallback(() => { mutation.current = true; }, []);
  const endMutation = useCallback((entityId?: string) => {
    if (entityId) recentLocal.current.set(entityId, Date.now());
    for (const [id, time] of recentLocal.current) if (Date.now() - time > 8000) recentLocal.current.delete(id);
    mutation.current = false;
  }, []);

  useEffect(() => {
    if (isAuthRoute(pathname)) { clear(); setInboxOpen(false); }
  }, [clear, pathname]);

  useEffect(() => {
    let lastInvalid = 0;
    const offline = () => notify({ title: "Você está sem conexão.", detail: "As alterações precisam de internet para serem salvas.", error: true, key: "network" });
    const online = () => notify({ title: "Conexão restabelecida.", detail: "Você pode atualizar os dados e tentar novamente.", key: "network" });
    const invalid = (event: Event) => {
      if (Date.now() - lastInvalid < 100) return;
      lastInvalid = Date.now();
      const field = event.target;
      if (field instanceof HTMLInputElement || field instanceof HTMLSelectElement || field instanceof HTMLTextAreaElement) {
        notify({ title: "Revise o formulário.", detail: field.validationMessage, error: true, key: "form-validation" });
      }
    };
    const rejected = () => notify({ title: "Não foi possível concluir a operação.", detail: "Tente novamente em alguns instantes.", error: true, key: "unexpected-error" });
    window.addEventListener("offline", offline);
    window.addEventListener("online", online);
    window.addEventListener("unhandledrejection", rejected);
    document.addEventListener("invalid", invalid, true);
    return () => {
      window.removeEventListener("offline", offline);
      window.removeEventListener("online", online);
      window.removeEventListener("unhandledrejection", rejected);
      document.removeEventListener("invalid", invalid, true);
    };
  }, [notify]);

  useEffect(() => {
    if (!client) return;
    let mounted = true;
    let generation = 0;
    let userId: string | null | undefined;
    async function check(id: string | null) {
      const version = ++generation;
      if (userId !== id) { userId = id; switchOwner(id ?? "guest"); setAdminId(null); recentLocal.current.clear(); }
      if (!id) { authenticated.current = false; setAuthenticatedId(null); return; }
      const { data, error } = await client!.rpc("current_user_context");
      if (mounted && version === generation) {
        const contextValid = !error && data?.user_id === id;
        const preferences = contextValid
          ? await client!.from("user_profiles").select("disabled_notification_types").eq("id", id).single()
          : null;
        if (!mounted || version !== generation) return;
        const valid = contextValid && !preferences?.error && !!preferences?.data;
        const categories = parseDisabledNotificationTypes(preferences?.data?.disabled_notification_types);
        disabled.current = new Set(categories);
        setDisabledNotificationTypes(categories);
        authenticated.current = valid;
        setAuthenticatedId(valid ? id : null);
        setAdminId(valid && data?.is_internal_admin === true ? id : null);
        if (!valid || data?.is_internal_admin !== true) clear();
      }
    }
    void client.auth.getSession().then(({ data }) => { if (mounted) void check(data.session?.user.id ?? null); });
    const { data } = client.auth.onAuthStateChange((_event, session) => {
      // Auth callbacks finish before RPC calls to avoid the auth client lock.
      setTimeout(() => {
        if (!mounted) return;
        const id = session?.user.id ?? null;
        void check(id);
      }, 0);
    });
    return () => { mounted = false; generation++; data.subscription.unsubscribe(); };
  }, [client, clear, switchOwner]);

  useEffect(() => {
    if (!client || !adminId) return;
    let mounted = true;
    let hadFailure = false;
    const timers = new Set<ReturnType<typeof setTimeout>>();
    const seen = new Set<string>();
    const channel = client.channel("pier-admin", { config: { private: true } });
    function later(callback: () => void, delay: number) {
      const timer = setTimeout(() => { timers.delete(timer); if (mounted) callback(); }, delay);
      timers.add(timer);
    }
    channel.on("broadcast", { event: "admin_change" }, ({ payload }) => {
      const event = parseAdminChange(payload);
      if (!mounted || !event || seen.has(event.id)) return;
      seen.add(event.id);
      if (seen.size > 500) seen.delete(seen.values().next().value!);
      setRevision((value) => value + 1);
      function deliver() {
        if (mutation.current) { later(deliver, 250); return; }
        const localTime = recentLocal.current.get(event!.entity_id);
        if (localTime && Date.now() - localTime < 8000) return;
        notify(changeNotice(event!));
      }
      later(deliver, 1200);
    });
    void client.realtime.setAuth().then(() => {
      if (!mounted) return;
      channel.subscribe((status) => {
        if (!mounted) return;
        if (status === "SUBSCRIBED") {
          setRevision((value) => value + 1);
          if (hadFailure) { notify({ title: "Notificações em tempo real reconectadas.", key: "realtime-connection" }); hadFailure = false; }
        } else if (["CHANNEL_ERROR", "TIMED_OUT", "CLOSED"].includes(status)) {
          if (!hadFailure) notify({ title: "Tempo real indisponível.", detail: "Use Atualizar para consultar as mudanças.", error: true, key: "realtime-connection" });
          hadFailure = true;
        }
      });
    }).catch(() => { if (mounted) notify({ title: "Não foi possível conectar as notificações em tempo real.", error: true }); });
    return () => { mounted = false; timers.forEach(clearTimeout); void client.removeChannel(channel); };
  }, [adminId, client, notify]);

  return <Context.Provider value={{ notify, clear, setIslandHost, beginMutation, endMutation, revision, disabledNotificationTypes, setNotificationTypeEnabled }}>
    {children}
    {authenticatedId && !isAuthRoute(pathname) && <SiteIsland notices={notices} dismiss={dismiss} host={host} openInbox={openInbox} inboxOpen={inboxOpen} />}
    {storageReady && authenticatedId && !isAuthRoute(pathname) && <><NotificationLauncher unread={history.filter((item) => !item.read).length} open={() => openInbox()} />
      <NotificationInbox open={inboxOpen} close={() => setInboxOpen(false)} notices={history} selectedId={selectedNoticeId} mutedKinds={mutedKinds} markRead={markRead} markAllRead={markAllRead} remove={removeHistory} clearAll={clearHistory} setKindMuted={setKindMuted} /></>}
    {secret && adminId && !isAuthRoute(pathname) && <ConnectorSecret secret={secret} close={() => setSecret(null)} />}
  </Context.Provider>;
}

function ConnectorSecret({ secret, close }: { secret: string; close: () => void }) {
  const { notify, setIslandHost } = useSiteNotifications();
  const dialog = useRef<HTMLDialogElement>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    dialog.current?.showModal(); setIslandHost(dialog.current);
    return () => setIslandHost(null);
  }, [setIslandHost]);
  async function copy() {
    try { await navigator.clipboard.writeText(secret); setCopied(true); notify({ title: "Segredo copiado.", key: "connector-copy" }); }
    catch { setError("Selecione o segredo abaixo para copiar manualmente."); notify({ title: "Não foi possível copiar o segredo.", detail: "Selecione o texto para copiar manualmente.", error: true, key: "connector-copy" }); }
  }
  return <dialog ref={dialog} className="admin-dialog" aria-labelledby="connector-secret-title" onCancel={close}>
    <div className="admin-dialog-header"><h2 id="connector-secret-title">Segredo do conector</h2></div>
    <div className="admin-editor-form island-secret"><p>Copie antes de fechar. Este segredo não será exibido novamente.</p><code tabIndex={0}>{secret}</code>
      {error && <p role="alert">{error}</p>}<button className="button button-primary" onClick={() => void copy()}>{copied ? "Copiado" : "Copiar segredo"}</button>
      <button className="button button-secondary" onClick={close}>Fechar</button>
    </div>
  </dialog>;
}
