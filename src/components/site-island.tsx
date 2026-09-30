"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { Button } from "@heroui/react";
import type { AdminNotice } from "@/src/lib/admin-notifications";

export function SiteIsland({ notices, dismiss, host, openInbox, inboxOpen }: {
  notices: AdminNotice[];
  dismiss: (id: string) => void;
  host: HTMLElement | null;
  openInbox: (id: string) => void;
  inboxOpen: boolean;
}) {
  const current = notices[0];
  const [expanded, setExpanded] = useState(false);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (!current) return;
    setExpanded(false);
    setPaused(false);
    const frame = requestAnimationFrame(() => setExpanded(true));
    return () => cancelAnimationFrame(frame);
  }, [current?.id]);
  useEffect(() => {
    if (!current || paused || inboxOpen) return;
    const timer = setTimeout(() => dismiss(current.id), current.error ? 9000 : 5000);
    return () => clearTimeout(timer);
  }, [current, dismiss, inboxOpen, paused]);
  if (!current) return null;

  const open = () => { openInbox(current.id); dismiss(current.id); };
  const content = <>
    <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{!current.error ? `${current.title} ${current.detail ?? ""}` : ""}</div>
    <div className="sr-only" role="alert" aria-atomic="true">{current.error ? `${current.title} ${current.detail ?? ""}` : ""}</div>
    <aside aria-label="Notificação recente" className={`site-island${expanded ? " expanded" : ""}${current.error ? " has-error" : ""}`}
      onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)} onFocus={() => setPaused(true)} onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setPaused(false); }}
      onKeyDown={(event) => { if (event.key === "Escape") { event.stopPropagation(); dismiss(current.id); } }}>
      <div className="island-summary"><span className={`island-signal ${current.error ? "offline" : "live"}`} aria-hidden="true" />
        <Button variant="ghost" className="island-toggle" aria-haspopup="dialog" onPress={open}>{current.source === "realtime" ? "Atualização do banco" : current.error ? "Ação não concluída" : "Nova notificação"}{notices.length > 1 && <span className="island-count">+{notices.length - 1}</span>}</Button>
        <Button variant="ghost" className="island-dismiss" aria-label="Dispensar toast" onPress={() => dismiss(current.id)}>×</Button>
      </div>
      {expanded && <Button variant="ghost" className="island-body island-open" aria-haspopup="dialog" onPress={open}>
        <span className="island-title">{current.title}</span>{current.detail && <span className="island-detail">{current.detail}</span>}
      </Button>}
    </aside>
  </>;
  return host ? createPortal(content, host) : content;
}
