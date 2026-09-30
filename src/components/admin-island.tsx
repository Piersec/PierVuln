"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import type { AdminNotice } from "@/src/lib/admin-notifications";

export function AdminIsland({ notices, connection, busy, dismiss, host }: { notices: AdminNotice[]; connection: "connecting" | "live" | "offline"; busy: boolean; dismiss: (id: string) => void; host: HTMLElement | null }) {
  const current = notices[0];
  const [expanded, setExpanded] = useState(true);
  const [paused, setPaused] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");
  useEffect(() => { setExpanded(true); setCopied(false); setCopyError(""); }, [current?.id]);
  useEffect(() => {
    if (!current || paused || (current.secret && !copied)) return;
    const timer = setTimeout(() => dismiss(current.id), current.error ? 9000 : 5000);
    return () => clearTimeout(timer);
  }, [copied, current, dismiss, paused]);

  async function copy() {
    if (!current?.secret) return;
    try { await navigator.clipboard.writeText(current.secret); setCopied(true); setCopyError(""); }
    catch { setCopyError("Não foi possível copiar. Selecione o segredo abaixo."); }
  }
  const label = busy ? "Salvando alteração…" : connection === "live" ? "Supabase conectado" : connection === "offline" ? "Tempo real indisponível" : "Conectando ao Supabase…";
  const content = <>
    <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{current && !current.error ? `${current.title} ${current.detail ?? ""}` : ""}{copied ? " Segredo copiado." : ""}</div>
    <div className="sr-only" role="alert" aria-atomic="true">{current?.error ? `${current.title} ${current.detail ?? ""}` : ""}{copyError}</div>
    <aside aria-label="Notificações administrativas" className={`admin-island${current && expanded ? " expanded" : ""}${current?.error ? " has-error" : ""}`}
      onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)} onFocus={() => setPaused(true)} onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setPaused(false); }}
      onKeyDown={(e) => { if (e.key === "Escape" && current) { e.stopPropagation(); dismiss(current.id); } }}>
      <div className="island-summary"><span className={`island-signal ${busy ? "working" : connection}`} aria-hidden="true" />
        {current ? <button className="island-toggle" aria-expanded={expanded} onClick={() => setExpanded((previous) => !previous)}>{expanded ? current.source === "realtime" ? "Atualização do banco" : current.error ? "Ação não concluída" : "Ação concluída" : current.title}{notices.length > 1 && <span className="island-count">+{notices.length - 1}</span>}</button> : <span className="island-idle">{label}</span>}
        {current && <button className="island-dismiss" aria-label="Dispensar notificação" onClick={() => dismiss(current.id)}>×</button>}
      </div>
      {current && expanded && <div className="island-body"><p className="island-title">{current.title}</p>{current.detail && <p className="island-detail">{current.detail}</p>}
        {current.secret && <div className="island-secret"><p>Copie o segredo do conector. Ele só é exibido agora.</p><code tabIndex={0}>{current.secret}</code><button className="button button-primary" onClick={() => void copy()}>{copied ? "Segredo copiado" : "Copiar segredo"}</button>{copyError && <p>{copyError}</p>}</div>}
      </div>}
    </aside>
  </>;
  return host ? createPortal(content, host) : content;
}
