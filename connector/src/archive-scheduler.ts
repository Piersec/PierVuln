function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Variável obrigatória ausente: ${name}`);
  return value;
}

const supabaseUrl = required("SUPABASE_URL").replace(/\/$/, "");
const publishableKey = required("SUPABASE_PUBLISHABLE_KEY");
const configuredArchiveToken = process.env.ARCHIVE_JOB_TOKEN?.trim();
const archiveToken = configuredArchiveToken || required("WAZUH_INGEST_TOKEN");
const connectionId = configuredArchiveToken ? undefined : required("WAZUH_CONNECTION_ID");
const intervalSeconds = Number(process.env.ARCHIVE_INTERVAL_SECONDS ?? "86400");

if (!supabaseUrl.startsWith("https://") || !Number.isInteger(intervalSeconds) || intervalSeconds < 3600) {
  throw new Error("Configure HTTPS e ARCHIVE_INTERVAL_SECONDS de pelo menos 3600 segundos.");
}

async function runArchive() {
  const response = await fetch(`${supabaseUrl}/functions/v1/archive-runner`, {
    method: "POST",
    headers: {
      apikey: publishableKey,
      "content-type": "application/json",
      "x-archive-token": archiveToken,
      ...(connectionId ? { "x-connection-id": connectionId } : {}),
    },
    body: "{}",
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`Supabase respondeu HTTP ${response.status} para a rotina de retenção.`);
  }
  const result = await response.json() as { expiredManifests?: number; purgedFindings?: number };
  console.info(`[archive-scheduler] arquivos expirados=${result.expiredManifests ?? 0}; achados arquivados=${result.purgedFindings ?? 0}`);
}

async function main() {
  while (true) {
    try { await runArchive(); }
    catch (error) { console.error(`[archive-scheduler] rotina falhou: ${error instanceof Error ? error.message.slice(0, 300) : "erro desconhecido"}`); }
    await new Promise((resolve) => setTimeout(resolve, intervalSeconds * 1000));
  }
}

main().catch((error) => {
  console.error(`[archive-scheduler] inicialização cancelada: ${error instanceof Error ? error.message : "erro desconhecido"}`);
  process.exitCode = 1;
});
