import test from "node:test";
import assert from "node:assert/strict";
import { deleteExactAgent } from "../src/asset-deletion-protocol";

const identity = { agentId: "007", agentName: "TEST-SRV", registeredAt: "2026-10-01T10:00:00Z", ipAddress: "192.0.2.7" };
const source = { id: "007", name: "TEST-SRV", dateAdd: identity.registeredAt, ip: identity.ipAddress };
const reply = (items: unknown[], failed = 0) => Response.json({ error: 0, data: { affected_items: items, total_affected_items: items.length, total_failed_items: failed } });

test("deletes only the confirmed single ID with explicit status and age", async () => {
  const requests: { url: URL; method: string }[] = [];
  const result = await deleteExactAgent("https://manager.example:55000", "test-token", identity, async (url, init) => {
    requests.push({ url: new URL(url), method: init?.method ?? "GET" });
    return init?.method === "DELETE" ? reply(["007"]) : reply([source]);
  });
  assert.equal(result.outcome, "succeeded");
  assert.equal(requests.length, 2);
  assert.equal(requests[1].url.pathname, "/agents");
  assert.equal(requests[1].url.searchParams.get("agents_list"), "007");
  assert.equal(requests[1].url.searchParams.get("older_than"), "0s");
  assert.equal(requests[1].url.searchParams.get("status"), "all");
  assert.equal(requests[1].url.searchParams.get("name"), identity.agentName);
  assert.equal(requests[1].url.searchParams.get("q"), "dateAdd=2026-10-01T10:00:00.000Z");
});
test("rejects wildcards, bulk IDs, the Manager ID and non-HTTPS endpoints before HTTP", async () => {
  for (const agentId of ["all", "000", "007,008", "007&agents_list=all", "*"]) {
    const result = await deleteExactAgent("https://manager.example", "token", { ...identity, agentId }, async () => { throw new Error("must not call HTTP"); });
    assert.equal(result.code, "identity_changed");
  }
  assert.equal((await deleteExactAgent("http://manager.example", "token", identity)).outcome, "failed");
});
test("blocks agent ID reuse, renamed hosts and changed registration/IP", async () => {
  for (const changed of [{ ...source, id: "008" }, { ...source, name: "ANOTHER-HOST" }, { ...source, dateAdd: "2026-11-02T00:00:00Z" }, { ...source, ip: "192.0.2.8" }]) {
    let deletes = 0;
    const result = await deleteExactAgent("https://manager.example", "token", identity, async (_url, init) => { if (init?.method === "DELETE") deletes++; return reply([changed]); });
    assert.equal(result.code, "identity_changed"); assert.equal(deletes, 0);
  }
});
test("an unauthorized preflight never issues DELETE", async () => {
  let calls = 0;
  const result = await deleteExactAgent("https://manager.example", "token", identity, async () => { calls++; return new Response(null, { status: 403 }); });
  assert.equal(result.code, "source_denied"); assert.equal(calls, 1);
});
test("a timeout after sending DELETE is uncertain and is never retried", async () => {
  let deletes = 0;
  const result = await deleteExactAgent("https://manager.example", "token", identity, async (_url, init) => {
    if (init?.method === "DELETE") { deletes++; throw new Error("timeout"); }
    return reply([source]);
  });
  assert.equal(result.outcome, "uncertain"); assert.equal(deletes, 1);
});
test("a 200 response with a failed or different agent cannot confirm removal", async () => {
  for (const response of [() => reply(["008"]), () => reply(["007"], 1), () => Response.json({ error: 0, data: {} })]) {
    const result = await deleteExactAgent("https://manager.example", "token", identity, async (_url, init) => init?.method === "DELETE" ? response() : reply([source]));
    assert.equal(result.outcome, "uncertain");
  }
});
