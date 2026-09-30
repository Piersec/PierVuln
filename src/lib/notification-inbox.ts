import type { AdminNotice } from "./admin-notifications";
import { visibleText } from "./visible-text";

export type InboxNotice = Pick<AdminNotice, "id" | "title" | "detail" | "error" | "key" | "source"> & {
  createdAt: number;
  read: boolean;
};

export const MAX_INBOX_NOTICES = 100;

export function noticeKind(notice: Pick<AdminNotice, "key" | "title">): string {
  return notice.key ? `key:${notice.key.split(":", 1)[0]}` : `title:${notice.title.trim().toLocaleLowerCase("pt-BR")}`;
}

export function toInboxNotice(notice: AdminNotice, createdAt = Date.now()): InboxNotice {
  return {
    id: notice.id,
    title: visibleText(notice.title),
    detail: notice.detail ? visibleText(notice.detail) : undefined,
    error: notice.error,
    key: notice.key,
    source: notice.source,
    createdAt,
    read: false,
  };
}

export function parseInbox(value: string | null): InboxNotice[] {
  if (!value) return [];
  try {
    const entries: unknown = JSON.parse(value);
    if (!Array.isArray(entries)) return [];
    return entries.flatMap((entry): InboxNotice[] => {
      if (!entry || typeof entry !== "object") return [];
      const item = entry as Record<string, unknown>;
      if (typeof item.id !== "string" || typeof item.title !== "string" || typeof item.createdAt !== "number" || !Number.isFinite(new Date(item.createdAt).getTime())) return [];
      return [{
        id: item.id.slice(0, 100),
        title: visibleText(item.title).slice(0, 250),
        detail: typeof item.detail === "string" ? visibleText(item.detail).slice(0, 1000) : undefined,
        error: item.error === true,
        key: typeof item.key === "string" ? item.key.slice(0, 160) : undefined,
        source: item.source === "action" || item.source === "realtime" ? item.source : undefined,
        createdAt: item.createdAt,
        read: item.read === true,
      }];
    }).sort((a, b) => b.createdAt - a.createdAt).slice(0, MAX_INBOX_NOTICES);
  } catch {
    return [];
  }
}

export function parseMutedKinds(value: string | null): string[] {
  if (!value) return [];
  try {
    const entries: unknown = JSON.parse(value);
    return Array.isArray(entries) ? [...new Set(entries.filter((entry): entry is string => typeof entry === "string" && entry.length <= 180))].slice(0, 100) : [];
  } catch {
    return [];
  }
}
