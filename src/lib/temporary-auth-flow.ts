export type TemporaryAuthFlow = "invite" | "recovery";

const storageKey = "piervuln:temporary-auth-flow:v1";
const lifetimeMs: Record<TemporaryAuthFlow, number> = {
  invite: 60 * 60 * 1000,
  recovery: 20 * 60 * 1000,
};

export function grantTemporaryAuthFlow(flow: TemporaryAuthFlow, userId: string) {
  try {
    sessionStorage.setItem(storageKey, JSON.stringify({ flow, userId, expiresAt: Date.now() + lifetimeMs[flow] }));
  } catch { return false; }
  return true;
}

export function hasTemporaryAuthFlow(flow: TemporaryAuthFlow, userId: string) {
  try {
    const raw = sessionStorage.getItem(storageKey);
    if (!raw) return false;
    const saved: unknown = JSON.parse(raw);
    if (typeof saved !== "object" || saved === null) return false;
    const entry = saved as { flow?: unknown; userId?: unknown; expiresAt?: unknown };
    if (entry.flow === flow && entry.userId === userId && typeof entry.expiresAt === "number" && entry.expiresAt > Date.now()) return true;
    sessionStorage.removeItem(storageKey);
  } catch { return false; }
  return false;
}

export function clearTemporaryAuthFlow() {
  try { sessionStorage.removeItem(storageKey); } catch { /* Storage can be unavailable. */ }
}

export function hasInviteLink() {
  const hash = new URLSearchParams(window.location.hash.slice(1));
  return hash.get("type") === "invite" && hash.has("access_token") && hash.has("refresh_token");
}
