export type AdminNotice = { id: string; title: string; detail?: string; error?: boolean; secret?: string; key?: string; source?: "action" | "realtime" };
export type NoticeInput = Omit<AdminNotice, "id">;
export type AdminChange = { id: string; table: string; operation: "INSERT" | "UPDATE" | "DELETE"; entity_id: string; label: string; status?: string; is_active?: boolean; connection_id?: string };
const entityLabels: Record<string, string> = {
  companies: "Empresa", user_profiles: "Usuário", company_memberships: "Vínculo de usuário",
  internal_admins: "Equipe Pier", wazuh_connections: "Conexão Wazuh", wazuh_agent_mappings: "Vínculo de agente ou grupo",
  archive_manifests: "Arquivo", sync_runs: "Sincronização Wazuh",
};
const stateLabels: Record<string, string> = { running: "em execução", succeeded: "concluída", failed: "falhou", partial: "parcial", pending: "pendente", verified: "verificado", database_purged: "arquivado", expired: "expirado" };

export function parseAdminChange(value: unknown): AdminChange | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  if (typeof row.id !== "string" || typeof row.entity_id !== "string" || typeof row.table !== "string" || !entityLabels[row.table]
    || !["INSERT", "UPDATE", "DELETE"].includes(String(row.operation))) return null;
  return { id: row.id, table: row.table, operation: row.operation as AdminChange["operation"], entity_id: row.entity_id,
    label: typeof row.label === "string" ? row.label.slice(0, 160) : "", status: typeof row.status === "string" ? row.status : undefined,
    is_active: typeof row.is_active === "boolean" ? row.is_active : undefined, connection_id: typeof row.connection_id === "string" ? row.connection_id : undefined };
}

export function changeNotice(change: AdminChange): NoticeInput {
  const entity = entityLabels[change.table];
  const feminine = ["companies", "wazuh_connections", "internal_admins"].includes(change.table);
  const operation = change.operation === "INSERT" ? feminine ? "criada" : "criado" : change.operation === "DELETE" ? feminine ? "removida" : "removido" : feminine ? "atualizada" : "atualizado";
  const state = change.status ? stateLabels[change.status] ?? change.status : operation;
  const active = change.is_active === undefined ? "" : change.is_active ? feminine ? "Ativa" : "Ativo" : feminine ? "Inativa" : "Inativo";
  return { title: `${entity}: ${state}.`, detail: [change.label, active].filter(Boolean).join(" · ") || "Alteração recebida do banco de dados.", error: change.status === "failed" || change.status === "partial",
    key: `${change.table}:${change.entity_id}`, source: "realtime" };
}

export function enqueueNotice(queue: AdminNotice[], incoming: AdminNotice): AdminNotice[] {
  const index = incoming.key ? queue.findIndex((notice) => notice.key === incoming.key && !notice.secret) : -1;
  if (index < 0) return [...queue, incoming];
  return queue.map((notice, i) => i === index ? incoming : notice);
}
