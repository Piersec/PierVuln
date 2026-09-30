"use client";

import { useEffect, useRef } from "react";
import { Button, Checkbox } from "@heroui/react";
import { Bell, Trash2, X } from "lucide-react";
import { noticeKind, type InboxNotice } from "@/src/lib/notification-inbox";

export function NotificationLauncher({ unread, open }: { unread: number; open: () => void }) {
  return <Button variant="secondary" className={`notification-launcher${unread ? " has-unread" : ""}`} aria-label={`Abrir notificações${unread ? `, ${unread} não lidas` : ""}`} onPress={open}>
    <Bell size={19} strokeWidth={1.8} aria-hidden="true" />
    {unread > 0 && <span className="notification-launcher-count" aria-hidden="true">{unread > 99 ? "99+" : unread}</span>}
  </Button>;
}

export function NotificationInbox({ open, close, notices, selectedId, mutedKinds, markRead, markAllRead, remove, clearAll, setKindMuted }: {
  open: boolean;
  close: () => void;
  notices: InboxNotice[];
  selectedId: string | null;
  mutedKinds: string[];
  markRead: (id: string) => void;
  markAllRead: () => void;
  remove: (id: string) => void;
  clearAll: () => void;
  setKindMuted: (kind: string, selected: boolean) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const unread = notices.filter((notice) => !notice.read).length;

  useEffect(() => {
    const panel = dialog.current;
    if (!panel) return;
    if (open) {
      if (!panel.open) panel.showModal();
      panel.dataset.state = "open";
      const frame = requestAnimationFrame(() => panel.querySelector<HTMLElement>('[data-selected="true"]')?.scrollIntoView({ block: "nearest" }));
      return () => cancelAnimationFrame(frame);
    }
    if (!panel.open) return;
    panel.dataset.state = "closing";
    const timer = setTimeout(() => panel.close(), 280);
    return () => clearTimeout(timer);
  }, [open, selectedId]);

  return <dialog ref={dialog} className="notification-drawer" aria-labelledby="notification-drawer-title"
    onCancel={(event) => { event.preventDefault(); close(); }} onClose={close}>
    <header className="notification-drawer-header">
      <div><span className="notification-kicker">CENTRAL DE AVISOS</span><h2 id="notification-drawer-title">Notificações</h2><p>{unread ? `${unread} ${unread === 1 ? "não lida" : "não lidas"}` : "Tudo lido"}</p></div>
      <Button variant="ghost" className="notification-close" aria-label="Fechar notificações" onPress={close}><X size={19} aria-hidden="true" /></Button>
    </header>
    <div className="notification-drawer-actions">
      <Button variant="ghost" isDisabled={unread === 0} onPress={markAllRead}>Marcar todas como lidas</Button>
      <Button variant="ghost" isDisabled={notices.length === 0} onPress={clearAll}>Limpar todas</Button>
    </div>
    <div className="notification-drawer-scroll">
      {notices.length === 0 ? <div className="notification-empty"><strong>Nenhum aviso por enquanto</strong><p>As próximas atualizações do site aparecerão aqui.</p></div>
        : <ol className="notification-list">{notices.map((notice, index) => {
          const kind = noticeKind(notice);
          return <li key={notice.id} className={`notification-item${notice.read ? " is-read" : ""}${notice.error ? " is-error" : ""}${notice.id === selectedId ? " is-selected" : ""}`} data-selected={notice.id === selectedId}
            style={{ animationDelay: `${Math.min(index, 8) * 35}ms` }}>
            <div className="notification-item-top"><span className="notification-item-status" aria-hidden="true" /><time dateTime={new Date(notice.createdAt).toISOString()}>{new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short" }).format(notice.createdAt)}</time>
              <Button variant="ghost" className="notification-remove" aria-label={`Limpar notificação: ${notice.title}`} onPress={() => remove(notice.id)}><Trash2 size={16} aria-hidden="true" /></Button>
            </div>
            <Button variant="ghost" className="notification-item-content" onPress={() => markRead(notice.id)} aria-label={`${notice.read ? "Lida" : "Não lida"}: ${notice.title}. Marcar como lida`}>
              <span className="notification-item-title">{notice.title}</span>{notice.detail && <span className="notification-item-detail">{notice.detail}</span>}
            </Button>
            <Checkbox variant="secondary" className="notification-mute" isSelected={mutedKinds.includes(kind)} onChange={(selected) => setKindMuted(kind, selected)}>
              <Checkbox.Content><Checkbox.Control><Checkbox.Indicator /></Checkbox.Control>Não mostrar toast deste tipo</Checkbox.Content>
            </Checkbox>
          </li>;
        })}</ol>}
    </div>
  </dialog>;
}
