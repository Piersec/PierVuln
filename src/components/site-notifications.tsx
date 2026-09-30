"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { SiteIsland } from "@/src/components/site-island";
import { changeNotice, enqueueNotice, parseAdminChange, type AdminNotice, type NoticeInput } from "@/src/lib/admin-notifications";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";

type Notifications = {
  notify: (notice: NoticeInput) => void;
  clear: () => void;
  setIslandHost: (host: HTMLElement | null) => void;
  beginMutation: () => void;
  endMutation: (entityId?: string) => void;
  revision: number;
};
const Context = createContext<Notifications | null>(null);
export function useSiteNotifications() {
  const context = useContext(Context);
  if (!context) throw new Error("Site notifications provider required");
  return context;
}

export function SiteNotifications({ children }: { children: ReactNode }) {
  const client = getSupabaseBrowserClient();
  const [notices, setNotices] = useState<AdminNotice[]>([]);
  const [host, setIslandHost] = useState<HTMLElement | null>(null);
  const [revision, setRevision] = useState(0);
  const [adminId, setAdminId] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const mutation = useRef(false);
  const recentLocal = useRef(new Map<string, number>());
  const notify = useCallback((notice: NoticeInput) => {
    if (notice.secret) setSecret(notice.secret);
    setNotices((queue) => enqueueNotice(queue, { ...notice, secret: undefined, id: crypto.randomUUID() }));
  }, []);
  const clear = useCallback(() => { setNotices([]); setSecret(null); }, []);
  const dismiss = useCallback((id: string) => setNotices((queue) => queue.filter((notice) => notice.id !== id)), []);
  const beginMutation = useCallback(() => { mutation.current = true; }, []);
  const endMutation = useCallback((entityId?: string) => {
    if (entityId) recentLocal.current.set(entityId, Date.now());
    for (const [id, time] of recentLocal.current) if (Date.now() - time > 8000) recentLocal.current.delete(id);
    mutation.current = false;
  }, []);

  useEffect(() => {
    if (!client) return;
    let mounted = true;
    let generation = 0;
    let userId: string | null | undefined;
    async function check(id: string | null) {
      const version = ++generation;
      if (userId !== id) { userId = id; clear(); setAdminId(null); recentLocal.current.clear(); }
      if (!id) return;
      const { data, error } = await client!.rpc("current_user_context");
      if (mounted && version === generation) {
        setAdminId(!error && data?.is_internal_admin === true ? id : null);
        if (error || data?.is_internal_admin !== true) clear();
      }
    }
    void client.auth.getSession().then(({ data }) => { if (mounted) void check(data.session?.user.id ?? null); });
    const { data } = client.auth.onAuthStateChange((_event, session) => {
      // Auth callbacks finish before RPC calls to avoid the auth client lock.
      setTimeout(() => { if (mounted) void check(session?.user.id ?? null); }, 0);
    });
    return () => { mounted = false; generation++; data.subscription.unsubscribe(); };
  }, [client, clear]);

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

  return <Context.Provider value={{ notify, clear, setIslandHost, beginMutation, endMutation, revision }}>
    {children}
    <SiteIsland notices={notices} dismiss={dismiss} host={host} />
    {secret && adminId && <ConnectorSecret secret={secret} close={() => setSecret(null)} />}
  </Context.Provider>;
}

function ConnectorSecret({ secret, close }: { secret: string; close: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { dialog.current?.showModal(); }, []);
  async function copy() {
    try { await navigator.clipboard.writeText(secret); setCopied(true); }
    catch { setError("Selecione o segredo abaixo para copiar manualmente."); }
  }
  return <dialog ref={dialog} className="admin-dialog" aria-labelledby="connector-secret-title" onCancel={close}>
    <div className="admin-dialog-header"><h2 id="connector-secret-title">Segredo do conector</h2></div>
    <div className="admin-editor-form island-secret"><p>Copie antes de fechar. Este segredo não será exibido novamente.</p><code tabIndex={0}>{secret}</code>
      {error && <p role="alert">{error}</p>}<button className="button button-primary" onClick={() => void copy()}>{copied ? "Copiado" : "Copiar segredo"}</button>
      <button className="button button-secondary" onClick={close}>Fechar</button>
    </div>
  </dialog>;
}
