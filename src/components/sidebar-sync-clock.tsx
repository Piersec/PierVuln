"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { readCompanySelection } from "@/src/lib/company-selection";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { withRequestTimeout } from "@/src/lib/request-timeout";
import { readSyncClockSources, syncClockState, type SyncClockSource, type SyncClockState } from "@/src/lib/sync-clock";

export function SyncClockIndicator({ clock, stale = false }: { clock: SyncClockState; stale?: boolean }) {
  const [dismissed, setDismissed] = useState(false);
  const description = stale ? "Não foi possível atualizar o status. A última leitura foi mantida; abra o status para conferir." : clock.detail;
  const heading = stale ? "Status de sincronização indisponível" : clock.heading;
  const hasProgress = !stale && (clock.progress !== null || clock.status === "running");
  return <Link href="/status" className="sidebar-sync-clock" data-state={stale ? "failed" : clock.status}
    aria-label={`${heading}${hasProgress ? `, ${clock.time}` : ""}. ${description}`} data-tooltip-dismissed={dismissed || undefined}
    onKeyDown={(event) => { if (event.key === "Escape") setDismissed(true); }}
    onFocus={() => setDismissed(false)} onMouseEnter={() => setDismissed(false)}>
    <span className="sidebar-sync-ring" role={hasProgress ? "progressbar" : "img"} aria-label={heading}
      aria-valuemin={hasProgress ? 0 : undefined} aria-valuemax={hasProgress ? 100 : undefined}
      aria-valuenow={hasProgress ? clock.progress ?? undefined : undefined} aria-valuetext={hasProgress ? `${clock.time}. ${description}` : undefined}>
      <svg viewBox="0 0 48 48" aria-hidden="true">
        <circle className="sidebar-sync-track" cx="24" cy="24" r="20" />
        {!stale && (clock.progress !== null || clock.status === "running") && <circle className="sidebar-sync-progress" cx="24" cy="24" r="20"
          pathLength="100" strokeDasharray={clock.progress === null ? "20 80" : `${clock.progress} 100`} />}
      </svg>
      <span className="sidebar-sync-time" aria-hidden="true">{stale ? "!" : clock.time}</span>
    </span>
    <span className="sidebar-sync-label" aria-hidden="true">Coleta</span>
    <span className="sidebar-sync-tooltip" aria-hidden="true"><strong>{heading}</strong><span>{description}</span><small>Ver status da coleta →</small></span>
  </Link>;
}

export function SidebarSyncClock({ userId, isInternal, companyId: selectedCompanyId }: { userId: string; isInternal: boolean; companyId?: string }) {
  const pathname = usePathname();
  const client = getSupabaseBrowserClient();
  const [selection, setSelection] = useState<{ owner: string; company: string } | null>(null);
  const [snapshot, setSnapshot] = useState<{ scope: string; sources: SyncClockSource[] } | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [now, setNow] = useState(0);
  const companyId = isInternal ? selectedCompanyId ?? (selection?.owner === userId ? selection.company : null) : "";
  const scope = `${userId}:${companyId}`;

  useEffect(() => {
    const read = () => {
      const selected = new URLSearchParams(window.location.search).get("company") ?? readCompanySelection(userId);
      const company = selected && selected !== "all" ? selected : "";
      setSelection((previous) => previous?.owner === userId && previous.company === company ? previous : { owner: userId, company });
    };
    read();
    window.addEventListener("storage", read);
    window.addEventListener("popstate", read);
    return () => {
      window.removeEventListener("storage", read);
      window.removeEventListener("popstate", read);
    };
  }, [pathname, userId]);

  useEffect(() => {
    if (!client || companyId === null) return;
    let active = true;
    let pending = false;
    const controller = new AbortController();
    setUnavailable(false);
    const load = async () => {
      if (pending || document.hidden) return;
      pending = true;
      try {
        const sources = await withRequestTimeout((signal) => readSyncClockSources(client, companyId, signal), controller.signal, 12_000);
        if (active) { setSnapshot({ scope, sources }); setUnavailable(false); setNow(Date.now()); }
      } catch {
        if (active) setUnavailable(true);
      } finally { pending = false; }
    };
    void load();
    const refresh = window.setInterval(() => void load(), 60_000);
    const tick = window.setInterval(() => { if (!document.hidden) setNow(Date.now()); }, 1000);
    const onVisible = () => { if (!document.hidden) { setNow(Date.now()); void load(); } };
    document.addEventListener("visibilitychange", onVisible);
    return () => { active = false; controller.abort(); window.clearInterval(refresh); window.clearInterval(tick); document.removeEventListener("visibilitychange", onVisible); };
  }, [client, companyId, scope]);

  const sources = snapshot?.scope === scope ? snapshot.sources : null;
  const clock = syncClockState(sources, now);
  if (!isInternal) clock.detail = `Fontes acessíveis à sua conta. ${clock.detail}`;
  return <SyncClockIndicator clock={clock} stale={unavailable} />;
}
