import { createHash } from "node:crypto";
import type { NormalizedFinding, SearchPage, WazuhIndexerClient } from "./wazuh.js";

export type ConnectorConfig = {
  supabaseUrl: string;
  publishableKey: string;
  connectionId: string;
  ingestToken: string;
  syncIntervalSeconds: number;
  pageSize: number;
  pageDelayMilliseconds: number;
  indexerIndexPattern: string;
};

type FunctionReply = Record<string, unknown>;

export class SupabaseIngestClient {
  private readonly ingestUrl: string;

  constructor(private readonly config: ConnectorConfig) {
    this.ingestUrl = `${config.supabaseUrl.replace(/\/$/, "")}/functions/v1/wazuh-ingest`;
  }

  async startSync(indexerVersion: string): Promise<string> {
    const reply = await this.post(this.ingestUrl, {
      action: "start",
      indexerVersion,
    });
    if (typeof reply.runId !== "string") throw new Error("Supabase não devolveu o ID da execução.");
    return reply.runId;
  }

  async ingestPage(runId: string, pageNumber: number, items: NormalizedFinding[], signal?: AbortSignal): Promise<number> {
    const reply = await this.post(this.ingestUrl, { action: "page", runId, pageNumber, items }, true, signal);
    return Number(reply.findingsChanged ?? 0);
  }

  async finishSync(runId: string, expectedPages: number, expectedDocuments: number, version: string): Promise<void> {
    const reply = await this.post(this.ingestUrl, {
      action: "finish", runId, expectedPages, expectedDocuments, indexerVersion: version,
    });
    if (reply.completed !== true) throw new Error("Supabase marcou a leitura como parcial; nenhum achado foi encerrado.");
  }

  async failSync(runId: string, error: string): Promise<void> {
    await this.post(this.ingestUrl, { action: "fail", runId, error: error.slice(0, 1500) });
  }

  private async post(url: string, payload: Record<string, unknown>, retrySafe = false, signal?: AbortSignal): Promise<FunctionReply> {
    const body = JSON.stringify(payload);
    const maximumAttempts = retrySafe ? 5 : 1;
    for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
      if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("Sincronização interrompida.");
      let response: Response;
      try {
        response = await fetch(url, {
          method: "POST",
          headers: {
            apikey: this.config.publishableKey,
            authorization: `Bearer ${this.config.ingestToken}`,
            "x-connection-id": this.config.connectionId,
            "content-type": "application/json",
          },
          body,
          signal: signal
            ? AbortSignal.any([signal, AbortSignal.timeout(120_000)])
            : AbortSignal.timeout(120_000),
        });
      } catch (error) {
        if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("Sincronização interrompida.");
        if (attempt + 1 < maximumAttempts) {
          await wait(Math.min(250 * 2 ** attempt, 30_000), signal);
          continue;
        }
        throw error;
      }
      if (response.ok) return await response.json() as FunctionReply;
      const retryable = response.status === 429 || response.status >= 500;
      if (!retryable || attempt + 1 >= maximumAttempts) {
        await response.body?.cancel();
        throw new Error(`Supabase recusou ${String(payload.action)} com HTTP ${response.status}.`);
      }
      const retryAfter = retryAfterMilliseconds(response.headers.get("retry-after"));
      await response.body?.cancel();
      await wait(retryAfter ?? Math.min(250 * 2 ** attempt, 30_000), signal);
    }
    throw new Error(`Supabase recusou ${String(payload.action)} após várias tentativas.`);
  }
}

export async function synchronizeSnapshot(
  indexer: WazuhIndexerClient,
  destination: SupabaseIngestClient,
  pageSize: number,
  pageDelayMilliseconds = 250,
  signal?: AbortSignal,
): Promise<{ pages: number; documents: number; changed: number }> {
  const runId = await destination.startSync("unknown");
  let pitId: string | null = null;
  let pages = 0;
  let documents = 0;
  try {
    const version = await indexer.getVersion(signal);
    pitId = await indexer.createPointInTime("5m", signal);
    let page: SearchPage = await indexer.searchPointInTime(pitId, pageSize, null, "5m", signal);
    pitId = page.pitId;
    const expectedDocuments = page.total;
    if (expectedDocuments === null) throw new Error("O snapshot PIT não devolveu uma contagem exata.");
    let changed = 0;
    let searchAfter: unknown[] | null = null;

    while (true) {
      const items = page.hits.map(normalizeHit);
      if (items.length > 0 || pages === 0) {
        changed += await destination.ingestPage(runId, pages, items, signal);
        pages += 1;
        documents += items.length;
      }
      if (documents > expectedDocuments) throw new Error("A paginação trouxe mais documentos que o total informado.");
      if (page.hits.length === 0 || page.hits.length < pageSize) break;

      searchAfter = page.hits[page.hits.length - 1].sortValues;
      await wait(pageDelayMilliseconds, signal);
      page = await indexer.searchPointInTime(pitId, pageSize, searchAfter, "5m", signal);
      pitId = page.pitId;
    }

    if (documents !== expectedDocuments) throw new Error("A paginação não recebeu todos os documentos do Indexer.");
    if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("Sincronização interrompida.");
    await destination.finishSync(runId, pages, expectedDocuments, version);
    return { pages, documents, changed };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Falha desconhecida na sincronização.";
    try { await destination.failSync(runId, message); } catch { /* The next run retires stale records safely. */ }
    throw error;
  } finally {
    if (pitId) {
      try { await indexer.closePointInTime(pitId); } catch { /* PIT cleanup failure does not change snapshot completeness. */ }
    }
  }
}

function normalizeHit(hit: { _id: string; _source: unknown }): NormalizedFinding {
  // The parser is imported lazily here to keep the transport independent in tests.
  return normalizeWazuhDocument(hit._id, hit._source);
}

import { normalizeWazuhDocument } from "./wazuh.js";

export function hashJson(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function wait(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason instanceof Error ? signal.reason : new Error("Sincronização interrompida."));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(signal?.reason instanceof Error ? signal.reason : new Error("Sincronização interrompida."));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function retryAfterMilliseconds(value: string | null): number | null {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 30_000);
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.min(Math.max(0, date - Date.now()), 30_000) : null;
}
