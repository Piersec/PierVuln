import { createHash } from "node:crypto";
import type { NormalizedFinding, ScrollPage, WazuhIndexerClient } from "./wazuh.js";

export type ConnectorConfig = {
  supabaseUrl: string;
  publishableKey: string;
  connectionId: string;
  ingestToken: string;
  syncIntervalSeconds: number;
  pageSize: number;
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

  async ingestPage(runId: string, pageNumber: number, items: NormalizedFinding[]): Promise<number> {
    const reply = await this.post(this.ingestUrl, { action: "page", runId, pageNumber, items });
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

  private async post(url: string, payload: Record<string, unknown>): Promise<FunctionReply> {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        apikey: this.config.publishableKey,
        authorization: `Bearer ${this.config.ingestToken}`,
        "x-connection-id": this.config.connectionId,
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(120_000),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Supabase recusou ${String(payload.action)} com HTTP ${response.status}.`);
    }
    return await response.json() as FunctionReply;
  }
}

export async function synchronizeSnapshot(
  indexer: WazuhIndexerClient,
  destination: SupabaseIngestClient,
  pageSize: number,
): Promise<{ pages: number; documents: number; changed: number }> {
  const runId = await destination.startSync("unknown");
  let scrollId: string | null = null;
  let pages = 0;
  let documents = 0;
  try {
    const version = await indexer.getVersion();
    let page: ScrollPage = await indexer.openScroll(pageSize);
    scrollId = page.scrollId;
    const expectedDocuments = page.total;
    let changed = 0;

    while (true) {
      const items = page.hits.map(normalizeHit);
      if (items.length > 0 || pages === 0) {
        changed += await destination.ingestPage(runId, pages, items);
        pages += 1;
        documents += items.length;
      }
      if (!page.scrollId || page.hits.length === 0) break;
      scrollId = page.scrollId;
      page = await indexer.nextScroll(scrollId);
      if (page.scrollId) scrollId = page.scrollId;
      if (documents > expectedDocuments) throw new Error("A paginação trouxe mais documentos que o total informado.");
    }

    if (documents !== expectedDocuments) throw new Error("A paginação não recebeu todos os documentos do Indexer.");
    await destination.finishSync(runId, pages, expectedDocuments, version);
    return { pages, documents, changed };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Falha desconhecida na sincronização.";
    try { await destination.failSync(runId, message); } catch { /* The next run retires stale records safely. */ }
    throw error;
  } finally {
    if (scrollId) {
      try { await indexer.clearScroll(scrollId); } catch { /* Scroll cleanup failure does not change snapshot completeness. */ }
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
