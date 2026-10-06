import type { SupabaseClient } from "@supabase/supabase-js";

type PublicationMarker = { id: string; published_sync_run_id: string | null };

async function readPublicationMarkers(client: SupabaseClient, signal?: AbortSignal): Promise<string> {
  let query = client.from("wazuh_connections").select("id,published_sync_run_id");
  if (signal) query = query.abortSignal(signal);
  const { data, error } = await query;
  if (error) throw error;
  return JSON.stringify(
    ((data ?? []) as PublicationMarker[])
      .map(({ id, published_sync_run_id }) => [id, published_sync_run_id] as const)
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

export async function withConsistentInventoryRead<T>(
  client: SupabaseClient,
  read: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("Leitura interrompida.");
    const before = await readPublicationMarkers(client, signal);
    const result = await read();
    const after = await readPublicationMarkers(client, signal);
    if (before === after) return result;
    if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 40 * (attempt + 1)));
  }
  throw new Error("A sincronização do inventário mudou durante a leitura. Atualize para carregar um snapshot completo.");
}

