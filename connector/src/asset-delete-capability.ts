export type DeleteCapability = { status: "allowed" | "restricted" | "denied" | "unknown"; reason: "policies" | "policies_unavailable" | "authentication_failed" | "network_error" };

export function deleteCapability(payload: unknown): DeleteCapability {
  const unknown: DeleteCapability = { status: "unknown", reason: "policies_unavailable" };
  if (!payload || typeof payload !== "object") return unknown;
  const response = payload as { error?: unknown; data?: Record<string, unknown> };
  const data = response.data;
  if (response.error !== 0 || !data || !["white", "black"].includes(String(data.rbac_mode))) return unknown;
  const policy = data["agent:delete"];
  if (policy !== undefined && (!policy || typeof policy !== "object" || Array.isArray(policy))) return unknown;
  const entries = Object.entries(policy ?? {});
  if (entries.some(([resource, effect]) => !/^(agent:(id|group):[^:]+|\*:\*:\*)$/.test(resource) || !["allow", "deny"].includes(String(effect)))) return unknown;
  const allows = entries.filter(([, effect]) => effect === "allow");
  const denies = entries.filter(([, effect]) => effect === "deny");
  const broad = ([resource]: [string, unknown]) => resource === "agent:id:*" || resource === "*:*:*";
  const broadAllow = allows.some(broad), broadDeny = denies.some(broad);
  let status: DeleteCapability["status"];
  if (broadDeny) status = allows.length ? "restricted" : "denied";
  else if (data.rbac_mode === "black") status = denies.length ? "restricted" : "allowed";
  else if (broadAllow && !denies.length) status = "allowed";
  else status = allows.length ? "restricted" : "denied";
  return { status, reason: "policies" };
}
