export type NormalizedFinding = {
  documentId: string;
  agentId: string | null;
  agentName: string | null;
  agentGroups: string[];
  hostOs: string | null;
  packageName: string | null;
  packageVersion: string | null;
  packageType: string | null;
  packageArchitecture: string | null;
  vulnerabilityId: string;
  description: string | null;
  severity: string;
  cvssBase: number | null;
  references: string[];
  sourceStatus: string | null;
};

type UnknownRecord = Record<string, unknown>;

function atPath(record: UnknownRecord, path: string): unknown {
  return path.split(".").reduce<unknown>((value, part) => {
    if (!value || typeof value !== "object") return undefined;
    return (value as UnknownRecord)[part];
  }, record);
}

function asRecord(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function asString(value: unknown, max = 2000): string | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const normalized = String(value).trim();
  return normalized ? normalized.slice(0, max) : null;
}

function stringArray(value: unknown, maxItems = 100, maxLength = 256): string[] {
  const candidates = Array.isArray(value)
    ? value
    : typeof value === "string" ? value.split(/[;,\n]/g) : [];
  return [...new Set(candidates.map((item) => asString(item, maxLength)).filter((item): item is string => Boolean(item)))].slice(0, maxItems);
}

function normalizeSeverity(value: unknown): string {
  const severity = asString(value, 40)?.toLowerCase();
  if (severity === "critical") return "Critical";
  if (severity === "high") return "High";
  if (severity === "medium" || severity === "moderate") return "Medium";
  if (severity === "low") return "Low";
  if (severity === "informational" || severity === "info") return "Informational";
  return "Unknown";
}

function normalizeScore(value: unknown): number | null {
  if (typeof value !== "number" && typeof value !== "string") return null;
  const score = Number(value);
  return Number.isFinite(score) && score >= 0 && score <= 10 ? score : null;
}

export function normalizeWazuhDocument(documentId: string, sourceValue: unknown): NormalizedFinding {
  const source = asRecord(sourceValue);
  const agent = asRecord(source.agent);
  const pkg = asRecord(source.package);
  const vulnerability = asRecord(source.vulnerability);
  const host = asRecord(source.host);
  const hostOs = asRecord(host.os);
  const os = asRecord(source.os);
  const score = asRecord(vulnerability.score);
  const cvss = asRecord(vulnerability.cvss);
  const cvss3 = asRecord(cvss.cvss3);
  const detector = asRecord(vulnerability.scanner);

  const refsValue = vulnerability.reference ?? vulnerability.references ?? source.references;
  const agentGroups = stringArray(agent.groups ?? source.agent_groups);
  const references = stringArray(refsValue, 50, 2048);
  const vulnerabilityId = asString(vulnerability.id, 128) ?? "UNKNOWN";

  return {
    documentId: documentId.slice(0, 512),
    agentId: asString(agent.id, 128) ?? asString(source.agent_id, 128),
    agentName: asString(agent.name, 256) ?? asString(source.agent_name, 256),
    agentGroups,
    hostOs: asString(hostOs.name, 256) ?? asString(os.name, 256) ?? asString(source.host_os, 256),
    packageName: asString(pkg.name, 512) ?? asString(source.package_name, 512),
    packageVersion: asString(pkg.version, 256) ?? asString(source.package_version, 256),
    packageType: asString(pkg.type, 128) ?? asString(source.package_type, 128),
    packageArchitecture: asString(pkg.architecture, 128) ?? asString(source.package_architecture, 128),
    vulnerabilityId,
    description: asString(vulnerability.description, 50_000) ?? asString(source.description, 50_000),
    severity: normalizeSeverity(vulnerability.severity ?? source.severity),
    cvssBase: normalizeScore(score.base ?? cvss3.base ?? atPath(source, "vulnerability.score.base")),
    references,
    sourceStatus: asString(vulnerability.status ?? detector.status ?? source.status, 128),
  };
}

export type WazuhHit = { _id: string; _source: unknown };
export type ScrollPage = { hits: WazuhHit[]; total: number; scrollId: string | null; version: string };

class IndexerHttpError extends Error {
  constructor(readonly status: number, method: string, path: string) {
    super(`Indexer retornou HTTP ${status} (${method} ${path}).`);
  }
}

const networkErrorCodes = new Set([
  "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_SOCKET",
  "ETIMEDOUT", "ECONNREFUSED", "ECONNRESET", "EHOSTUNREACH", "ENETUNREACH",
  "ENOTFOUND", "EAI_AGAIN", "CERT_HAS_EXPIRED", "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "ERR_TLS_CERT_ALTNAME_INVALID",
]);

function networkFailureReason(error: unknown): string {
  const pending = [error];
  const seen = new Set<unknown>();
  while (pending.length) {
    const current = pending.shift();
    if (!current || typeof current !== "object" || seen.has(current)) continue;
    seen.add(current);
    const record = current as { code?: unknown; cause?: unknown; errors?: unknown; name?: unknown };
    if (typeof record.code === "string" && networkErrorCodes.has(record.code)) return record.code;
    if (record.name === "TimeoutError") return "INDEXER_REQUEST_TIMEOUT";
    if (record.cause) pending.push(record.cause);
    if (Array.isArray(record.errors)) pending.push(...record.errors);
  }
  return "INDEXER_NETWORK_ERROR";
}

export class WazuhIndexerClient {
  private readonly baseUrl: string;
  private readonly authorization: string;

  constructor(
    baseUrl: string,
    username: string,
    password: string,
    private readonly indexPattern: string,
    private readonly timeoutMs = 45_000,
  ) {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== "https:") throw new Error("WAZUH_INDEXER_URL precisa usar HTTPS.");
    if (!/^wazuh-states-vulnerabilities[-a-zA-Z0-9_*]*$/.test(indexPattern)) {
      throw new Error("INDEXER_INDEX_PATTERN deve apontar apenas para wazuh-states-vulnerabilities*.");
    }
    this.baseUrl = parsed.toString().replace(/\/$/, "");
    this.authorization = `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`;
  }

  async getVersion(): Promise<string> {
    try {
      const info = await this.requestJson("GET", "/");
      const version = asString(atPath(asRecord(info), "version.number"), 160);
      if (!version) throw new Error("O Indexer respondeu sem a versão esperada.");
      return version;
    } catch (error) {
      // Reading cluster metadata is optional when the Indexer account is
      // restricted to the vulnerability index. Keep the least-privilege
      // account usable without hiding authentication or connectivity errors.
      if (error instanceof IndexerHttpError && error.status === 403) return "not-exposed";
      throw error;
    }
  }

  async countDocuments(): Promise<number> {
    const result = asRecord(await this.requestJson("GET", `/${this.indexPattern}/_count`));
    const count = Number(result.count);
    if (!Number.isSafeInteger(count) || count < 0) throw new Error("O Indexer devolveu uma contagem inválida.");
    return count;
  }

  async openScroll(pageSize: number, scrollTtl = "2m"): Promise<ScrollPage> {
    const query = new URLSearchParams({ scroll: scrollTtl });
    const path = `/${this.indexPattern}/_search?${query.toString()}`;
    const response = asRecord(await this.requestJson("POST", path, {
      size: pageSize,
      sort: ["_doc"],
      track_total_hits: true,
      query: { match_all: {} },
    }));
    return this.parseScrollPage(response, true);
  }

  async nextScroll(scrollId: string, scrollTtl = "2m"): Promise<ScrollPage> {
    const response = asRecord(await this.requestJson("POST", "/_search/scroll", {
      scroll: scrollTtl,
      scroll_id: scrollId,
    }));
    return this.parseScrollPage(response, false);
  }

  async clearScroll(scrollId: string): Promise<void> {
    await this.requestJson("DELETE", "/_search/scroll", { scroll_id: [scrollId] });
  }

  private parseScrollPage(result: UnknownRecord, requireExactTotal: boolean): ScrollPage {
    if (result.timed_out === true) throw new Error("O Indexer encerrou a consulta por timeout.");
    const shards = asRecord(result._shards);
    if (Number(shards.failed ?? 0) > 0) throw new Error("O Indexer devolveu shards com falha.");
    const hitsBlock = asRecord(result.hits);
    const totalBlock = hitsBlock.total;
    const total = typeof totalBlock === "number"
      ? totalBlock
      : Number(asRecord(totalBlock).value);
    const relation = typeof totalBlock === "object" ? asRecord(totalBlock).relation : "eq";
    if ((!Number.isSafeInteger(total) || total < 0 || relation !== "eq") && requireExactTotal) {
      throw new Error("A leitura não trouxe uma contagem exata do Indexer.");
    }
    const rawHits = Array.isArray(hitsBlock.hits) ? hitsBlock.hits : [];
    const hits = rawHits.map((value) => {
      const hit = asRecord(value);
      if (typeof hit._id !== "string" || !hit._id) throw new Error("Documento do Indexer sem _id estável.");
      return { _id: hit._id, _source: hit._source };
    });
    return {
      hits,
      total: Number.isSafeInteger(total) && total >= 0 ? total : -1,
      scrollId: asString(result._scroll_id, 8192),
      version: asString(atPath(result, "_version"), 160) ?? "",
    };
  }

  private async requestJson(method: string, path: string, body?: unknown): Promise<unknown> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          authorization: this.authorization,
          accept: "application/json",
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new Error(`Conexão com o Indexer falhou (${networkFailureReason(error)}) em ${method} ${path.split("?")[0]}.`);
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new IndexerHttpError(response.status, method, path.split("?")[0]);
    }
    if (response.status === 204) return {};
    return response.json();
  }
}
