import type { SupabaseClient } from "@supabase/supabase-js";

export type AdminCompany = { id: string; name: string; slug: string; is_active: boolean; user_count: number; connection_count: number };
export type CompanyStorageUsage = {
  measured_at: string; database_bytes: number; refresh_seconds: number;
  companies: { tenant_id: string; data_bytes: number; allocated_bytes: number; finding_count: number }[];
  deletions?: { tenant_id: string; status: "queued" | "running" | "succeeded" | "failed"; findings_deleted: number; error_message: string | null }[];
};

export function formatStorageBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const unit = Math.min(Math.floor(Math.log(Math.max(bytes, 1)) / Math.log(1000)), units.length - 1);
  return `${(bytes / 1000 ** unit).toLocaleString("pt-BR", { maximumFractionDigits: 1 })} ${units[unit]}`;
}
export type AdminSync = { id: string; status: string; started_at: string; finished_at: string | null; full_snapshot: boolean; documents_received: number };
export type AdminConnection = { id: string; name: string; mode: string; tenant_id: string | null; endpoint_url: string; is_active: boolean; latest_sync: AdminSync | null };
export type AdminMapping = { id: string; connection_id: string; tenant_id: string; match_type: string; match_value: string; is_active: boolean };
export type AdminMembership = { id: string; company_id: string; role: string; is_active: boolean };
export type AdminUser = { id: string; email: string; display_name: string; is_internal: boolean; invited_at: string | null; email_confirmed_at: string | null; last_sign_in_at: string | null; memberships: AdminMembership[] };
export type AdminArchive = { id: string; bucket_name: string; object_path: string; checksum_sha256: string; record_count: number; archived_at: string; expires_at: string; status: string };
export type AdminData = {
  stats: { active_companies: number; inactive_companies: number; users: number; connections: number; active_connections: number };
  companies: AdminCompany[]; connections: AdminConnection[]; mappings: AdminMapping[];
  users: AdminUser[]; user_count: number; archives: AdminArchive[];
};

export class AdminRequestError extends Error {
  constructor(message: string, public status?: number) { super(message); }
}

export async function invokeAdmin<T = Record<string, unknown>>(client: SupabaseClient, body: Record<string, unknown>): Promise<T> {
  const { data, error } = await client.functions.invoke("admin-actions", { body });
  if (error) {
    const detail = error.context instanceof Response ? await error.context.json().catch(() => null) : null;
    throw new AdminRequestError(detail?.error || "Não foi possível concluir a operação. Tente novamente.", error.context instanceof Response ? error.context.status : undefined);
  }
  if (!data || data.error) throw new Error(data?.error || "Resposta administrativa inválida.");
  return data as T;
}

export const adminDate = (value: string | null | undefined) => value ? new Date(value).toLocaleString("pt-BR") : "Não disponível";
export const syncLabels: Record<string, string> = { running: "Em execução", succeeded: "Concluída", partial: "Parcial", failed: "Falhou" };
export const roleLabels: Record<string, string> = { owner: "Proprietário", admin: "Administrador", analyst: "Analista", viewer: "Leitor" };
export const archiveLabels: Record<string, string> = { pending: "Pendente", verified: "Verificado", database_purged: "Arquivado", expired: "Expirado" };
