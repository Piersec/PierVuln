export type DeletionIdentity = { agentId: string; agentName: string; registeredAt: string; ipAddress: string | null };
export type DeletionOutcome = { outcome: "succeeded" | "failed" | "uncertain"; code: string };
type Http = (url: string, init?: RequestInit) => Promise<Response>;

export async function deleteExactAgent(apiUrl: string, token: string, expected: DeletionIdentity, http: Http = fetch): Promise<DeletionOutcome> {
  const base = new URL(apiUrl);
  if (base.protocol !== "https:" || base.username || base.password || base.search || base.hash || !/^[0-9]{3,8}$/.test(expected.agentId) || /^0+$/.test(expected.agentId) || !expected.agentName || !Number.isFinite(Date.parse(expected.registeredAt))) return { outcome: "failed", code: "identity_changed" };
  const headers = { Authorization: `Bearer ${token}` };
  let sent = false;
  try {
    const query = new URL("agents", base.href.replace(/\/?$/, "/"));
    query.search = new URLSearchParams({ agents_list: expected.agentId, select: "id,name,ip,dateAdd", limit: "2" }).toString();
    const before = await http(query.href, { headers, redirect: "error", signal: AbortSignal.timeout(30_000) });
    if (!before.ok) return { outcome: "failed", code: before.status === 403 ? "source_denied" : "preflight_failed" };
    const payload = await before.json();
    const items = payload?.data?.affected_items;
    const item = items?.[0];
    if (payload.error !== 0 || payload.data?.total_failed_items !== 0 || payload.data?.total_affected_items !== 1 || !Array.isArray(items) || items.length !== 1 || item?.id !== expected.agentId || item?.name !== expected.agentName || !Number.isFinite(Date.parse(item?.dateAdd)) || Date.parse(item.dateAdd) !== Date.parse(expected.registeredAt) || (expected.ipAddress !== null && item.ip !== expected.ipAddress)) return { outcome: "failed", code: "identity_changed" };
    const target = new URL("agents", base.href.replace(/\/?$/, "/"));
    target.search = new URLSearchParams({ agents_list: expected.agentId, status: "all", older_than: "0s", name: expected.agentName, q: `dateAdd=${new Date(expected.registeredAt).toISOString()}`, ...(expected.ipAddress ? { ip: expected.ipAddress } : {}) }).toString();
    sent = true;
    const response = await http(target.href, { method: "DELETE", headers, redirect: "error", signal: AbortSignal.timeout(30_000) });
    if (response.status === 401 || response.status === 403) return { outcome: "failed", code: "source_denied" };
    if (!response.ok) return { outcome: "uncertain", code: "network_uncertain" };
    const result = await response.json();
    const data = result?.data;
    if (result.error === 0 && data?.total_failed_items === 0 && data.total_affected_items === 1 && Array.isArray(data.affected_items) && data.affected_items.length === 1 && data.affected_items[0] === expected.agentId) return { outcome: "succeeded", code: "source_confirmed" };
    return { outcome: "uncertain", code: "source_failed" };
  } catch {
    return { outcome: sent ? "uncertain" : "failed", code: sent ? "network_uncertain" : "preflight_failed" };
  }
}
