import { createHash } from "node:crypto";

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  return value;
}

export class ConfigurationChanges {
  private readonly fingerprints = new Map<string, string>();

  changed(jobs: { key: string; connection: unknown; tenant?: unknown }[]): string[] {
    const active = new Set(jobs.map((job) => job.key));
    for (const key of this.fingerprints.keys()) if (!active.has(key)) this.fingerprints.delete(key);
    return jobs.flatMap((job) => {
      const fingerprint = createHash("sha256").update(JSON.stringify(canonical({ connection: job.connection, tenant: job.tenant }))).digest("hex");
      const changed = this.fingerprints.get(job.key) !== fingerprint;
      this.fingerprints.set(job.key, fingerprint);
      return changed ? [job.key] : [];
    });
  }
}
