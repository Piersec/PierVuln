"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import type { AdminNotice } from "@/src/lib/admin-notifications";

export function SiteIsland({ notices, dismiss, host }: { notices: AdminNotice[]; dismiss: (id: string) => void; host: HTMLElement | null }) {
  const current = notices[0];
  const [expanded, setExpanded] = useState(true);
  const [paused, setPaused] = useState(false);
  useEffect(() => { setExpanded(true); setPaused(false); }, [current?.id]);
  useEffect(() => {
    if (!current || paused) return;
    const timer = setTimeout(() => dismiss(current.id), current.error ? 9000 : 5000);
    return () => clearTimeout(timer);
  }, [current, dismiss, paused]);
  if (!current) return null;
  const content = <>
    <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{!current.error ? `${current.title} ${current.detail ?? ""}` : ""}</div>
    <div className="sr-only" role="alert" aria-atomic="true">{current.error ? `${current.title} ${current.detail ?? ""}` : ""}</div>
    <aside aria-label="Notificações do site" className={`site-island${current && expanded ? " expanded" : ""}${current?.error ? " has-error" : ""}`}
      onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)} onFocus={() => setPaused(true)} onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setPaused(false); }}
      onKeyDown={(e) => { if (e.key === "Escape" && current) { e.stopPropagation(); dismiss(current.id); } }}>
      <div className="island-summary"><span className={`island-signal ${current.error ? "offline" : "live"}`} aria-hidden="true" />
        {current ? <button className="island-toggle" aria-expanded={expanded} onClick={() => setExpanded((previous) => !previous)}>{expanded ? current.source === "realtime" ? "Atualização do banco" : current.error ? "Ação não concluída" : "Ação concluída" : current.title}{notices.length > 1 && <span className="island-count">+{notices.length - 1}</span>}</button> : null}
        {current && <button className="island-dismiss" aria-label="Dispensar notificação" onClick={() => dismiss(current.id)}>×</button>}
      </div>
      {current && expanded && <div className="island-body"><p className="island-title">{current.title}</p>{current.detail && <p className="island-detail">{current.detail}</p>}
      </div>}
    </aside>
  </>;
  return host ? createPortal(content, host) : content;
}
