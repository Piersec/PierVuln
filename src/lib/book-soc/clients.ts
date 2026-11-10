// Registro dos clientes do Book SOC. Só roda no servidor.
// Cada cliente tem a própria conta somente leitura no Indexer dele; é essa conta que isola os dados.
// Nada daqui vai para o banco: a configuração vem das variáveis de ambiente.

export type BookClient = {
  slug: string; name: string; url: string; user: string; password: string;
  index: string;                 // vulnerabilidades
  alertsIndex: string | null;    // alertas; sem isso, o painel de alertas fica indisponível para o cliente
  excludedGroups: string[];      // grupos de regra fora das análises de alertas
};
export type PublicClient = { id: string; name: string; alerts: boolean };

const envId = /^[A-Z][A-Z0-9_]{0,40}$/;
const indexName = /^[a-z0-9._*-]{1,120}$/;

export function slugFor(envKey: string): string {
  return envKey.toLowerCase().replace(/_/g, "-");
}

export function loadClients(env: Record<string, string | undefined> = process.env): BookClient[] {
  const keys = (env.BOOK_SOC_CLIENTS ?? "").split(",").map((key) => key.trim()).filter(Boolean);
  const clients: BookClient[] = [];
  for (const key of keys) {
    if (!envId.test(key)) continue;
    const read = (field: string) => env[`BOOK_SOC_${key}_${field}`];
    const url = read("URL"), user = read("USER"), encoded = read("PASSWORD_B64"), index = read("INDEX");
    if (!url || !user || !encoded || !index || !indexName.test(index)) continue;
    let protocol = "";
    try { protocol = new URL(url).protocol; } catch { continue; }
    if (protocol !== "https:") continue;
    const password = Buffer.from(encoded, "base64").toString("utf8");
    if (!password) continue;
    const alertsIndex = read("ALERTS_INDEX");
    const groups = (read("EXCLUDED_GROUPS") ?? "").split(",").map((group) => group.trim()).filter((group) => /^[\w.-]{1,64}$/.test(group));
    clients.push({
      slug: slugFor(key), name: read("NAME") || key, url: url.replace(/\/$/, ""), user, password, index,
      alertsIndex: alertsIndex && indexName.test(alertsIndex) ? alertsIndex : null,
      excludedGroups: groups.length ? groups : ["vulnerability-detector"],
    });
  }
  return clients;
}

export function publicClients(clients: BookClient[]): PublicClient[] {
  return clients.map((client) => ({ id: client.slug, name: client.name, alerts: client.alertsIndex !== null }));
}

export function findClient(clients: BookClient[], id: unknown): BookClient | undefined {
  return typeof id === "string" ? clients.find((client) => client.slug === id) : undefined;
}
