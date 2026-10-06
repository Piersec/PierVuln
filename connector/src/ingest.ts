import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, open, rm } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { NormalizedFinding, ScrollPage, WazuhIndexerClient } from "./wazuh.js";

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

export class SnapshotSyncError extends Error {
  constructor(
    message: string,
    readonly runId: string,
    readonly pages: number,
    readonly documents: number,
    readonly durationMs: number,
  ) {
    super(message);
    this.name = "SnapshotSyncError";
  }
}

export class SupabaseIngestClient {
  private readonly ingestUrl: string;

  constructor(private readonly config: ConnectorConfig) {
    this.ingestUrl = `${config.supabaseUrl.replace(/\/$/, "")}/functions/v1/wazuh-ingest`;
  }

  async startSync(indexerVersion: string, signal?: AbortSignal): Promise<string> {
    const protocol = await this.post(this.ingestUrl, { action: "protocol" }, false, signal);
    if (Number(protocol.snapshotProtocol) !== 2) throw new Error("Supabase não confirmou o protocolo de snapshot atômico v2.");
    const requestId = randomUUID();
    const reply = await this.post(this.ingestUrl, {
      action: "start",
      requestId,
      snapshotProtocol: 2,
      indexerVersion,
    }, true, signal);
    if (typeof reply.runId !== "string") throw new Error("Supabase não devolveu o ID da execução.");
    return reply.runId;
  }

  async ingestPage(runId: string, pageNumber: number, items: NormalizedFinding[], signal?: AbortSignal): Promise<number> {
    const reply = await this.post(this.ingestUrl, { action: "page", runId, pageNumber, items }, true, signal);
    return Number(reply.findingsChanged ?? 0);
  }

  async finishSync(runId: string, expectedPages: number, expectedDocuments: number, version: string, signal?: AbortSignal): Promise<number> {
    for (;;) {
      const reply = await this.post(this.ingestUrl, {
        action: "finish", runId, expectedPages, expectedDocuments, indexerVersion: version,
      }, true, signal);
      if (reply.completed === true) return Number.isSafeInteger(reply.findingsChanged) ? Number(reply.findingsChanged) : 0;
      if (reply.pending !== true) throw new Error("A publicação do snapshot não foi concluída; os dados anteriores foram mantidos.");
      await wait(10_000, signal);
    }
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
): Promise<{ runId: string; pages: number; documents: number; changed: number; durationMs: number }> {
  const startedAt = Date.now();
  const deadline = AbortSignal.timeout(30 * 60 * 1000);
  const runSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
  const runId = await destination.startSync("unknown", runSignal);
  const spoolDirectory = await mkdtemp(join(tmpdir(), "piervuln-snapshot-"));
  const spoolPath = join(spoolDirectory, "pages.ndjson");
  const spool = await open(spoolPath, "wx", 0o600);
  let scrollId: string | null = null;
  let pages = 0;
  let documents = 0;
  const documentIds = new Set<string>();
  try {
    const version = await indexer.getVersion(runSignal);
    let page: ScrollPage = await indexer.startScroll(pageSize, "2m", runSignal);
    scrollId = page.scrollId;
    const expectedDocuments = page.total;
    if (expectedDocuments === null) throw new Error("O snapshot scroll não devolveu uma contagem exata.");
    let changed = 0;

    while (true) {
      const items = page.hits.map(normalizeHit);
      for (const item of items) {
        if (documentIds.has(item.documentId)) {
          throw new Error(`O Indexer devolveu o _id ${item.documentId} mais de uma vez nesta conexão.`);
        }
        documentIds.add(item.documentId);
      }
      if (items.length > 0 || pages === 0) {
        await spool.writeFile(JSON.stringify(items) + "\n");
        pages += 1;
        documents += items.length;
      }
      if (documents > expectedDocuments) throw new Error("A paginação trouxe mais documentos que o total informado.");
      if (page.hits.length === 0 || page.hits.length < pageSize) break;

      await wait(pageDelayMilliseconds, runSignal);
      page = await indexer.continueScroll(scrollId, "2m", runSignal);
      scrollId = page.scrollId;
    }

    if (documents !== expectedDocuments) throw new Error("A paginação não recebeu todos os documentos do Indexer.");
    await spool.close();
    if (scrollId) {
      await indexer.clearScroll(scrollId).catch(() => undefined);
      scrollId = null;
    }
    console.info(`[connector] runId=${runId} status=downloaded documents=${documents} pages=${pages}; enviando snapshot completo.`);
    let uploadPage = 0;
    const stream = createReadStream(spoolPath);
    const reader = createInterface({ input: stream, crlfDelay: Infinity });
    try {
      for await (const line of reader) {
        if (runSignal.aborted) throw runSignal.reason;
        changed += await destination.ingestPage(runId, uploadPage, JSON.parse(line) as NormalizedFinding[], runSignal);
        uploadPage += 1;
      }
    } finally { reader.close(); stream.destroy(); }
    if (uploadPage !== pages) throw new Error("O snapshot local não contém todas as páginas baixadas.");
    if (runSignal.aborted) throw runSignal.reason instanceof Error ? runSignal.reason : new Error("Sincronização interrompida.");
    changed += await destination.finishSync(runId, pages, expectedDocuments, version, runSignal);
    return { runId, pages, documents, changed, durationMs: Date.now() - startedAt };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Falha desconhecida na sincronização.";
    try { await destination.failSync(runId, message); } catch { /* The next run retires stale records safely. */ }
    throw new SnapshotSyncError(message, runId, pages, documents, Date.now() - startedAt);
  } finally {
    await spool.close().catch(() => undefined);
    await rm(spoolDirectory, { recursive: true, force: true });
    if (scrollId) {
      try { await indexer.clearScroll(scrollId); } catch { /* The Indexer expires unclosed contexts after the keep-alive. */ }
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
