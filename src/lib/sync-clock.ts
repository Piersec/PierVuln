import type { SupabaseClient } from "@supabase/supabase-js";
import { visibleText } from "./visible-text";

// The worker's default interval starts after a successful run finishes.
// Its retry schedule is private to the worker, so failures never get a countdown.
export const estimatedSyncIntervalMs = 60 * 60 * 1000;

export type SyncClockSource = {
  id: string;
  name: string;
  latest: { status: string; started_at: string; finished_at: string | null } | null;
};

export type SyncClockState = {
  status: "loading" | "empty" | "running" | "waiting" | "due" | "failed";
  time: string;
  progress: number | null;
  heading: string;
  detail: string;
};

function clockTime(milliseconds: number): string {
  const seconds = Math.max(0, Math.ceil(milliseconds / 1000));
  if (seconds >= 3600) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 60).toString().padStart(2, "0")}:${(seconds % 60).toString().padStart(2, "0")}`;
}

export function syncClockState(sources: SyncClockSource[] | null, now: number): SyncClockState {
  if (sources === null) return { status: "loading", time: "…", progress: null, heading: "Consultando sincronização", detail: "Carregando o status da coleta." };
  if (!sources.length) return { status: "empty", time: "Ⅱ", progress: null, heading: "Sem coleta ativa", detail: "A empresa está sem fonte ativa ou sem acesso a uma fonte." };

  const running = sources.find((source) => source.latest?.status === "running");
  if (running) {
    const start = Date.parse(running.latest!.started_at);
    return { status: "running", time: Number.isFinite(start) ? clockTime(now - start) : "…", progress: null,
      heading: "Sincronizando", detail: `${visibleText(running.name)} · tempo decorrido. O tempo restante ainda não está disponível.` };
  }
  const failed = sources.find((source) => ["failed", "partial"].includes(source.latest?.status ?? ""));
  if (failed) return { status: "failed", time: "!", progress: null, heading: "Coleta requer atenção",
    detail: `${visibleText(failed.name)} · a última tentativa falhou ou ficou incompleta. Consulte o status para acompanhar a nova tentativa.` };

  const scheduled = sources.map((source) => ({ source, finished: Date.parse(source.latest?.finished_at ?? "") }));
  if (scheduled.some((item) => !Number.isFinite(item.finished))) return { status: "due", time: "…", progress: null,
    heading: "Aguardando primeira coleta", detail: "Ainda não há uma execução concluída para calcular a previsão." };
  const next = scheduled.reduce((earliest, item) => item.finished < earliest.finished ? item : earliest);
  const elapsed = Math.max(0, now - next.finished);
  const due = elapsed >= estimatedSyncIntervalMs;
  return { status: due ? "due" : "waiting", time: clockTime(estimatedSyncIntervalMs - elapsed),
    progress: Math.min(100, elapsed / estimatedSyncIntervalMs * 100),
    heading: due ? "Aguardando próximo ciclo" : "Próxima sincronização prevista",
    detail: `${visibleText(next.source.name)} · previsão pelo ciclo padrão de 1 hora após a conclusão. O início depende do agendador da coleta.` };
}

export async function readSyncClockSources(client: SupabaseClient, companyId: string, signal: AbortSignal): Promise<SyncClockSource[]> {
  const [connections, mappings] = await Promise.all([
    client.from("wazuh_connections")
      .select("id,name,tenant_id,mode,sync_runs!sync_runs_connection_id_fkey(status,started_at,finished_at)")
      .eq("is_active", true)
      .order("started_at", { referencedTable: "sync_runs", ascending: false })
      .limit(1, { referencedTable: "sync_runs" }).abortSignal(signal),
    companyId ? client.from("wazuh_agent_mappings").select("connection_id")
      .eq("tenant_id", companyId).eq("is_active", true).abortSignal(signal) : Promise.resolve({ data: [], error: null }),
  ]);
  if (connections.error) throw connections.error;
  if (mappings.error) throw mappings.error;
  const mappedIds = new Set((mappings.data ?? []).map((row) => row.connection_id));
  return (connections.data ?? [])
    .filter((connection) => !companyId || connection.tenant_id === companyId || (connection.mode === "shared" && mappedIds.has(connection.id)))
    .map((connection) => ({ id: connection.id, name: connection.name, latest: connection.sync_runs[0] ?? null }));
}
