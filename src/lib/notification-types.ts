import type { NoticeInput } from "./admin-notifications";

export const notificationTypes = [
  { id: "actions", label: "Resultados de ações", description: "Convites, alterações de casos, comentários e atualizações manuais." },
  { id: "errors", label: "Falhas em operações", description: "Erros ao salvar, consultar ou concluir uma ação." },
  { id: "admin_changes", label: "Mudanças administrativas", description: "Empresas, usuários, vínculos e integrações alterados em tempo real." },
  { id: "sync", label: "Sincronização", description: "Início, conclusão e falhas das leituras das fontes de dados." },
  { id: "archives", label: "Arquivos e retenção", description: "Preparação de downloads e mudanças no estado dos arquivos." },
  { id: "connectivity", label: "Conectividade", description: "Queda e retorno da conexão ou do tempo real." },
  { id: "security", label: "Segurança da conta", description: "Mudanças na sessão e no acesso à conta." },
] as const;

export type NotificationType = (typeof notificationTypes)[number]["id"];
const known = new Set<string>(notificationTypes.map((item) => item.id));

export function parseDisabledNotificationTypes(value: unknown): NotificationType[] {
  return Array.isArray(value)
    ? [...new Set(value.filter((item): item is NotificationType => typeof item === "string" && known.has(item)))]
    : [];
}

export function notificationType(notice: NoticeInput): NotificationType {
  const key = notice.key?.split(":", 1)[0] ?? "";
  if (key.startsWith("auth-") || key === "security") return "security";
  if (key === "network" || key === "realtime-connection") return "connectivity";
  if (key === "sync_runs" || key === "book-sync") return "sync";
  if (key === "archive_manifests" || key === "archive-download") return "archives";
  if (notice.source === "realtime") return "admin_changes";
  if (notice.error) return "errors";
  return "actions";
}
