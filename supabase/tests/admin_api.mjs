import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const local = readFileSync(new URL("../../.env.local", import.meta.url), "utf8");
const value = (key) => process.env[key] || local.match(new RegExp(`^${key}=(.*)$`, "m"))?.[1]?.trim().replace(/^['"]|['"]$/g, "");
const url = value("NEXT_PUBLIC_SUPABASE_URL");
const key = value("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY");
assert.ok(url && key, "Configure the public Supabase environment before this integration check");
for (const action of ["panel_data", "update_company", "update_membership"]) {
  const response = await fetch(`${url}/functions/v1/admin-actions`, { method: "POST", headers: { apikey: key, "content-type": "application/json" }, body: JSON.stringify({ action }) });
  assert.equal(response.status, 401, `Unauthenticated ${action} must be rejected`);
}
const response = await fetch(`${url}/rest/v1/rpc/admin_panel_data`, { method: "POST", headers: { apikey: key, "content-type": "application/json" }, body: "{}" });
assert.ok([401, 403, 404].includes(response.status), "Public clients must not access administrative Auth data");
console.log("PASS: deployed administrative actions and Auth-data RPC reject anonymous clients");
