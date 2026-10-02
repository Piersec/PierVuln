import { spawn, type ChildProcess } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";

const requiredConnectionVariables = [
  "WAZUH_CONNECTION_ID",
  "WAZUH_INGEST_TOKEN",
  "WAZUH_INDEXER_URL",
  "WAZUH_INDEXER_USERNAME",
  "WAZUH_INDEXER_PASSWORD",
] as const;

const connectionsDirectory = process.env.CONNECTOR_CONNECTIONS_DIR?.trim() || "/run/piervuln/connections";
const intervalSeconds = positiveInteger(process.env.SYNC_INTERVAL_SECONDS, 3600, "SYNC_INTERVAL_SECONDS");
if (intervalSeconds < 60) throw new Error("SYNC_INTERVAL_SECONDS não pode ser menor que 60.");

const shutdown = new AbortController();
let activeChild: ChildProcess | null = null;

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

async function loadConnections(): Promise<Array<{ name: string; environment: NodeJS.ProcessEnv }>> {
  const entries = await readdir(connectionsDirectory, { withFileTypes: true });
  const directories = entries
    .filter((entry) => entry.isDirectory() && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(entry.name))
    .sort((left, right) => left.name.localeCompare(right.name));

  const connections: Array<{ name: string; environment: NodeJS.ProcessEnv }> = [];
  for (const directory of directories) {
    const envPath = `${connectionsDirectory}/${directory.name}/.env`;
    try {
      const environment = parseEnv(await readFile(envPath, "utf8"));
      const missing = requiredConnectionVariables.filter((name) => !environment[name]?.trim());
      if (missing.length > 0) {
        console.error(`[connector] Configuração ${directory.name} ignorada; faltam: ${missing.join(", ")}.`);
        continue;
      }
      connections.push({ name: directory.name, environment });
    } catch (error) {
      console.error(`[connector] Não foi possível ler ${directory.name}/.env: ${safeMessage(error)}.`);
    }
  }

  if (connections.length === 0) {
    throw new Error(`Nenhuma conexão válida encontrada em ${connectionsDirectory}/<nome>/.env.`);
  }
  return connections;
}

function childEnvironment(connectionEnvironment: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const shared = Object.fromEntries(
    Object.entries(process.env).filter(([key, value]) =>
      value !== undefined && !key.startsWith("WAZUH_") && !key.startsWith("INDEXER_")),
  );
  return { ...shared, ...connectionEnvironment };
}

function runConnection(name: string, environment: NodeJS.ProcessEnv): Promise<void> {
  return new Promise((resolve, reject) => {
    const entrypoint = fileURLToPath(new URL("./index.ts", import.meta.url));
    const child = spawn(process.execPath, ["--import", "tsx", entrypoint, "--once"], {
      cwd: process.cwd(),
      env: childEnvironment(environment),
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
      reject(new Error(`Worker da conexão ${name} encerrou com código ${String(code)}${signal ? ` (${signal})` : ""}.`));
    });
  });
}

async function main() {
  console.info(`[connector] Worker contínuo iniciado; intervalo entre ciclos: ${intervalSeconds}s.`);
  while (!shutdown.signal.aborted) {
    const cycleStartedAt = Date.now();
    let failedConnections = 0;
    const connections = await loadConnections();

    for (const connection of connections) {
      if (shutdown.signal.aborted) break;
      console.info(`[connector] Iniciando snapshot da conexão ${connection.name}.`);
      try {
        await runConnection(connection.name, connection.environment);
      } catch (error) {
        failedConnections += 1;
        console.error(`[connector] Falha na conexão ${connection.name}: ${safeMessage(error)}.`);
      }
    }

    if (shutdown.signal.aborted) break;
    const elapsedSeconds = Math.ceil((Date.now() - cycleStartedAt) / 1000);
    console.info(`[connector] Ciclo encerrado: ${connections.length - failedConnections}/${connections.length} conexões concluídas em ${elapsedSeconds}s.`);
    await wait(intervalSeconds * 1000, shutdown.signal);
  }
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 500) : "erro desconhecido";
}

main().catch((error) => {
  console.error(`[connector] Worker encerrado: ${safeMessage(error)}.`);
  process.exitCode = 1;
});
