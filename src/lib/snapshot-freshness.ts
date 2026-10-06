export type SnapshotFreshness = "fresh" | "aging" | "stale";

const agingAfterMs = 60 * 60 * 1000;
const staleAfterMs = 2 * 60 * 60 * 1000;

export function snapshotFreshness(value: string | null | undefined, now = Date.now()): SnapshotFreshness {
  if (!value) return "stale";
  const observedAt = Date.parse(value);
  const age = now - observedAt;
  if (!Number.isFinite(age) || age < 0 || age >= staleAfterMs) return "stale";
  return age >= agingAfterMs ? "aging" : "fresh";
}

