import { SupabaseIngestClient, synchronizeSnapshot, type ConnectorConfig } from "./ingest.js";
import { WazuhIndexerClient } from "./wazuh.js";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Variável obrigatória ausente: ${name}`);
  return value;
}

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  const parsed = value ? Number(value) : fallback;
  if (!Number.isInteger(parsed) || parsed < 1) throw new Error(`${name} deve ser um inteiro positivo.`);
  return parsed;
}

function nonNegativeInteger(value: string | undefined, fallback: number, name: string): number {
  const parsed = value ? Number(value) : fallback;
  if (!Number.isInteger(parsed) || parsed < 0) throw new Error(`${name} deve ser um inteiro não negativo.`);
  return parsed;
}

function wait(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function readConfig(): ConnectorConfig & { indexerUrl: string; username: string; password: string } {
  const supabaseUrl = required("SUPABASE_URL").replace(/\/$/, "");
  const config: ConnectorConfig = {
    supabaseUrl,
    publishableKey: required("SUPABASE_PUBLISHABLE_KEY"),
    connectionId: required("WAZUH_CONNECTION_ID"),
    ingestToken: required("WAZUH_INGEST_TOKEN"),
    syncIntervalSeconds: positiveInteger(process.env.SYNC_INTERVAL_SECONDS, 60, "SYNC_INTERVAL_SECONDS"),
    pageSize: positiveInteger(process.env.INDEXER_PAGE_SIZE, 500, "INDEXER_PAGE_SIZE"),
    pageDelayMilliseconds: nonNegativeInteger(process.env.INDEXER_PAGE_DELAY_MS, 250, "INDEXER_PAGE_DELAY_MS"),
    indexerIndexPattern: process.env.INDEXER_INDEX_PATTERN?.trim() || "wazuh-states-vulnerabilities-*",
  };
  if (!/^https:\/\//i.test(supabaseUrl)) throw new Error("SUPABASE_URL precisa usar HTTPS.");
  if (!/^[0-9a-f-]{36}$/i.test(config.connectionId)) throw new Error("WAZUH_CONNECTION_ID precisa ser UUID.");
  if (config.syncIntervalSeconds < 60) throw new Error("SYNC_INTERVAL_SECONDS não pode ser menor que 60.");
  if (config.pageSize > 500) throw new Error("INDEXER_PAGE_SIZE não pode ser maior que 500.");
  if (config.pageDelayMilliseconds > 30_000) throw new Error("INDEXER_PAGE_DELAY_MS não pode ser maior que 30000.");
  return {
    ...config,
    indexerUrl: required("WAZUH_INDEXER_URL"),
    username: required("WAZUH_INDEXER_USERNAME"),
    password: required("WAZUH_INDEXER_PASSWORD"),
  };
}

async function main() {
  const config = readConfig();
  const shutdown = new AbortController();
  const requestShutdown = (signal: NodeJS.Signals) => {
    console.info(`[connector] Recebido ${signal}; encerrando esta execução com segurança.`);
    shutdown.abort(new Error(`Execução interrompida por ${signal}.`));
  };
  process.once("SIGTERM", () => requestShutdown("SIGTERM"));
  process.once("SIGINT", () => requestShutdown("SIGINT"));
  const indexer = new WazuhIndexerClient(
    config.indexerUrl,
    config.username,
    config.password,
    config.indexerIndexPattern,
  );
  const destination = new SupabaseIngestClient(config);
  if (process.argv.includes("--check")) {
    const version = await indexer.getVersion(shutdown.signal);
    const count = await indexer.countDocuments(shutdown.signal);
    const pitId = await indexer.createPointInTime("5m", shutdown.signal);
    try {
      await indexer.searchPointInTime(pitId, 1, null, "5m", shutdown.signal);
    } finally {
      await indexer.closePointInTime(pitId).catch(() => undefined);
    }
    console.info(`[connector] Indexer ${version} validado; ${count} documentos no snapshot.`);
    return;
  }
  const once = process.argv.includes("--once");
  if (once) {
    const result = await synchronizeSnapshot(indexer, destination, config.pageSize, config.pageDelayMilliseconds, shutdown.signal);
    console.info(`[connector] Snapshot completo: ${result.documents} documentos em ${result.pages} páginas.`);
    return;
  }
  while (!shutdown.signal.aborted) {
    const startedAt = Date.now();
    try {
      const result = await synchronizeSnapshot(indexer, destination, config.pageSize, config.pageDelayMilliseconds, shutdown.signal);
      console.info(`[connector] Leitura completa: ${result.documents} documentos em ${result.pages} páginas.`);
    } catch (error) {
      if (!shutdown.signal.aborted) console.error(`[connector] Sincronização parcial/falha: ${safeMessage(error)}`);
    }

    if (shutdown.signal.aborted) break;

    const elapsed = Date.now() - startedAt;
    await wait(Math.max(0, config.syncIntervalSeconds * 1000 - elapsed), shutdown.signal);
  }
}

function safeMessage(error: unknown) {
  return error instanceof Error ? error.message.slice(0, 500) : "erro desconhecido";
}

main().catch((error) => {
  console.error(`[connector] Inicialização cancelada: ${safeMessage(error)}`);
  process.exitCode = 1;
});
