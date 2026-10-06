import { spawn, type ChildProcess } from "node:child_process";
import { chmod, unlink, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

type RemoteConnection = {
  id: string;
  name: string;
  indexerUrl: string;
  indexPattern: string;
  indexerUsername: string;
  indexerPassword: string;
  ingestToken: string;
  caCertificate: string | null;
};

const supabaseUrl = required("SUPABASE_URL").replace(/\/$/, "");
const publishableKey = required("SUPABASE_PUBLISHABLE_KEY");
const workerToken = required("WAZUH_WORKER_CONFIG_TOKEN");
const syncIntervalSeconds = positiveInteger(process.env.SYNC_INTERVAL_SECONDS, 3600, "SYNC_INTERVAL_SECONDS");
const configPollSeconds = positiveInteger(process.env.WORKER_CONFIG_POLL_SECONDS, 300, "WORKER_CONFIG_POLL_SECONDS");
if (!/^https:\/\//i.test(supabaseUrl)) throw new Error("SUPABASE_URL precisa usar HTTPS.");
if (syncIntervalSeconds < 60) throw new Error("SYNC_INTERVAL_SECONDS não pode ser menor que 60.");
if (configPollSeconds < 30 || configPollSeconds > 3600) {
  throw new Error("WORKER_CONFIG_POLL_SECONDS precisa ficar entre 30 e 3600.");
}

const shutdown = new AbortController();
let activeChild: ChildProcess | null = null;

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

function wait(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
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

function requestShutdown(signal: NodeJS.Signals) {
  if (shutdown.signal.aborted) return;
  console.info(`[connector] Recebido ${signal}; encerrando o worker com segurança.`);
  shutdown.abort();
  activeChild?.kill("SIGTERM");
}

process.once("SIGTERM", () => requestShutdown("SIGTERM"));
process.once("SIGINT", () => requestShutdown("SIGINT"));

function validateConnection(value: unknown): RemoteConnection | null {
  if (!value || typeof value !== "object") return null;
  const connection = value as Partial<RemoteConnection>;
  if (typeof connection.id !== "string" || !/^[0-9a-f-]{36}$/i.test(connection.id)
      || typeof connection.name !== "string" || connection.name.length > 160
      || typeof connection.indexerUrl !== "string"
      || typeof connection.indexPattern !== "string"
      || typeof connection.indexerUsername !== "string" || !connection.indexerUsername
      || typeof connection.indexerPassword !== "string" || !connection.indexerPassword
      || typeof connection.ingestToken !== "string" || connection.ingestToken.length < 16 || connection.ingestToken.length > 512
      || (connection.caCertificate !== null && typeof connection.caCertificate !== "string")) return null;

  let endpoint: URL;
  try { endpoint = new URL(connection.indexerUrl); } catch { return null; }
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password) return null;
  if (!/^wazuh-states-vulnerabilities[-a-zA-Z0-9_*]*$/.test(connection.indexPattern)) return null;
  if (connection.caCertificate && (connection.caCertificate.length > 65536
      || !connection.caCertificate.includes("-----BEGIN CERTIFICATE-----")
      || !connection.caCertificate.includes("-----END CERTIFICATE-----"))) return null;
  return { ...connection, indexerUrl: endpoint.toString() } as RemoteConnection;
}

async function loadConnections(): Promise<{ connections: RemoteConnection[]; skipped: number }> {
  const connections: RemoteConnection[] = [];
  let offset = 0;
  let skipped = 0;
  while (true) {
    const response = await fetch(`${supabaseUrl}/functions/v1/wazuh-worker-config?offset=${offset}`, {
      method: "GET",
      headers: { apikey: publishableKey, "x-worker-token": workerToken },
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`Edge Function de configuração respondeu HTTP ${response.status}.`);
    const payload = await response.json() as {
      connections?: unknown;
      hasMore?: unknown;
      skipped?: unknown;
    };
    if (!Array.isArray(payload.connections) || typeof payload.hasMore !== "boolean") {
      throw new Error("Resposta inválida da Edge Function de configuração.");
    }
    for (const value of payload.connections) {
      const connection = validateConnection(value);
      if (connection) connections.push(connection);
      else skipped += 1;
    }
    skipped += Number.isSafeInteger(payload.skipped) && Number(payload.skipped) > 0 ? Number(payload.skipped) : 0;
    if (!payload.hasMore) break;
    offset += 100;
    if (offset > 1_000_000) throw new Error("Limite de paginação das configurações excedido.");
  }
  return { connections, skipped };
}

function childEnvironment(connection: RemoteConnection, caFile: string | null): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    NODE_ENV: process.env.NODE_ENV,
    SUPABASE_URL: supabaseUrl,
    SUPABASE_PUBLISHABLE_KEY: publishableKey,
    SYNC_INTERVAL_SECONDS: String(syncIntervalSeconds),
    INDEXER_PAGE_SIZE: process.env.INDEXER_PAGE_SIZE ?? "500",
    INDEXER_PAGE_DELAY_MS: process.env.INDEXER_PAGE_DELAY_MS ?? "250",
    INDEXER_INDEX_PATTERN: connection.indexPattern,
    WAZUH_CONNECTION_ID: connection.id,
    WAZUH_INGEST_TOKEN: connection.ingestToken,
    WAZUH_INDEXER_URL: connection.indexerUrl,
    WAZUH_INDEXER_USERNAME: connection.indexerUsername,
    WAZUH_INDEXER_PASSWORD: connection.indexerPassword,
  };
  if (caFile) environment.NODE_EXTRA_CA_CERTS = caFile;
  return environment;
}

async function runConnection(connection: RemoteConnection): Promise<void> {
  const caFile = connection.caCertificate ? `/tmp/piervuln-indexer-${connection.id}.pem` : null;
  try {
    if (caFile) {
      await writeFile(caFile, connection.caCertificate!, { encoding: "utf8", mode: 0o600 });
      await chmod(caFile, 0o600);
    }
    await new Promise<void>((resolve, reject) => {
      const entrypoint = fileURLToPath(new URL("./index.ts", import.meta.url));
      const child = spawn(process.execPath, ["--import", "tsx", entrypoint, "--once"], {
        cwd: process.cwd(),
        env: childEnvironment(connection, caFile),
        stdio: "inherit",
      });
      activeChild = child;

      child.once("error", (error) => {
        activeChild = null;
        reject(error);
      });
      child.once("close", (code, signal) => {
        activeChild = null;
        if (shutdown.signal.aborted) return resolve();
        if (code === 0) return resolve();
        reject(new Error(`Worker encerrou com código ${String(code)}${signal ? ` (${signal})` : ""}.`));
      });
    });
  } finally {
    if (caFile) await unlink(caFile).catch(() => undefined);
  }
}

async function main() {
  const nextRunAt = new Map<string, number>();
  const failuresByConnection = new Map<string, number>();
  console.info(`[connector] Worker dinâmico iniciado; consulta de fontes a cada ${configPollSeconds}s; sincronização a cada ${syncIntervalSeconds}s por fonte.`);
  while (!shutdown.signal.aborted) {
    try {
      const { connections, skipped } = await loadConnections();
      const activeIds = new Set(connections.map((connection) => connection.id));
      for (const id of nextRunAt.keys()) {
        if (!activeIds.has(id)) {
          nextRunAt.delete(id);
          failuresByConnection.delete(id);
        }
      }
      if (skipped > 0) console.warn(`[connector] ${skipped} fonte(s) sem configuração válida foram ignoradas.`);

      for (const connection of connections) {
        if (shutdown.signal.aborted) break;
        if ((nextRunAt.get(connection.id) ?? 0) > Date.now()) continue;
        console.info(`[connector] ${new Date().toISOString()} connectionId=${connection.id} status=starting.`);
        try {
          await runConnection(connection);
          failuresByConnection.delete(connection.id);
          nextRunAt.set(connection.id, Date.now() + syncIntervalSeconds * 1000);
          if (!shutdown.signal.aborted) console.info(`[connector] ${new Date().toISOString()} connectionId=${connection.id} status=completed.`);
        } catch (error) {
          if (shutdown.signal.aborted) break;
          const consecutiveFailures = (failuresByConnection.get(connection.id) ?? 0) + 1;
          failuresByConnection.set(connection.id, consecutiveFailures);
          const backoff = Math.min(15 * 60_000, 30_000 * 2 ** Math.min(consecutiveFailures - 1, 5));
          const nextDelay = backoff + Math.round(backoff * Math.random() * 0.2);
          nextRunAt.set(connection.id, Date.now() + nextDelay);
          console.error(`[connector] ${new Date().toISOString()} connectionId=${connection.id} status=failed consecutiveFailures=${consecutiveFailures} nextRetryMs=${nextDelay} error=${safeMessage(error)}`);
        }
      }
      if (connections.length === 0) console.info("[connector] Nenhuma fonte ativa e configurada no momento.");
    } catch (error) {
      console.error(`[connector] Não foi possível atualizar as configurações: ${safeMessage(error)}.`);
    }
    const now = Date.now();
    const nextScheduledRunAt = Math.min(...[...nextRunAt.values()].filter((time) => time > now));
    const retryDelay = Number.isFinite(nextScheduledRunAt) ? Math.max(1_000, nextScheduledRunAt - now) : configPollSeconds * 1000;
    await wait(Math.min(configPollSeconds * 1000, retryDelay), shutdown.signal);
  }
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 500) : "erro desconhecido";
}

main().catch((error) => {
  console.error(`[connector] Worker encerrado: ${safeMessage(error)}.`);
  process.exitCode = 1;
});
