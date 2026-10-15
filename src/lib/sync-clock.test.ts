import assert from "node:assert/strict";
import test from "node:test";
import type { SupabaseClient } from "@supabase/supabase-js";
import { readSyncClockSources, syncClockState, type SyncClockSource } from "./sync-clock";

const now = Date.parse("2026-10-15T16:30:00Z");
const source = (status = "succeeded", finished_at: string | null = "2026-10-15T16:00:00Z"): SyncClockSource => ({
  id: "dedicated", name: "Fonte dedicada", latest: { status, started_at: "2026-10-15T15:00:00Z", finished_at },
});

test("countdown starts after completion, including a long-running collection", () => {
  const clock = syncClockState([source()], now);
  assert.equal(clock.status, "waiting");
  assert.equal(clock.time, "30:00");
  assert.equal(clock.progress, 50);
  assert.match(clock.heading, /prevista/);
});

test("overdue cycles never wrap around to a new countdown", () => {
  const clock = syncClockState([source()], now + 3 * 3600_000);
  assert.equal(clock.status, "due");
  assert.equal(clock.time, "00:00");
  assert.equal(clock.progress, 100);
});

test("running collection shows elapsed time without inventing a progress percentage", () => {
  const active = source("running", null);
  active.latest!.started_at = "2026-10-15T16:28:30Z";
  const clock = syncClockState([source("failed"), active], now);
  assert.equal(clock.status, "running");
  assert.equal(clock.time, "01:30");
  assert.equal(clock.progress, null);
});

test("a failed or partial attempt has no made-up retry schedule", () => {
  for (const status of ["failed", "partial"]) {
    const clock = syncClockState([source(status)], now);
    assert.equal(clock.status, "failed");
    assert.equal(clock.progress, null);
    assert.equal(clock.time, "!");
  }
});

test("loading, paused and first collection remain distinguishable", () => {
  assert.equal(syncClockState(null, now).status, "loading");
  assert.equal(syncClockState([], now).status, "empty");
  assert.equal(syncClockState([{ ...source(), latest: null }], now).progress, null);
  assert.equal(syncClockState([source("succeeded", "invalid")], now).heading, "Aguardando primeira coleta");
});

test("multiple sources use the earliest expected cycle and clamp future timestamps", () => {
  const clock = syncClockState([source("succeeded", "2026-10-15T16:20:00Z"), source()], now);
  assert.equal(clock.time, "30:00");
  assert.equal(syncClockState([source("succeeded", "2026-10-15T17:00:00Z")], now).progress, 0);
});

test("company metadata query scopes dedicated and shared sources and limits each run history", async () => {
  const calls: { table: string; method: string; args: unknown[] }[] = [];
  const rows = [
    { id: "a", name: "A", mode: "dedicated", tenant_id: "company-a", sync_runs: [source().latest] },
    { id: "b", name: "B", mode: "dedicated", tenant_id: "company-b", sync_runs: [] },
    { id: "shared", name: "Compartilhada", mode: "shared", tenant_id: null, sync_runs: [] },
  ];
  const client = { from(table: string) {
    const result = { data: table.endsWith("connections") ? rows : [{ connection_id: "shared" }], error: null };
    const query: Record<string, unknown> = {};
    for (const method of ["select", "eq", "order", "limit", "abortSignal"]) query[method] = (...args: unknown[]) => {
      calls.push({ table, method, args });
      return method === "abortSignal" ? Promise.resolve(result) : query;
    };
    return query;
  } } as unknown as SupabaseClient;
  const result = await readSyncClockSources(client, "company-a", new AbortController().signal);
  assert.deepEqual(result.map((item) => item.id), ["a", "shared"]);
  assert.deepEqual(calls.find((call) => call.method === "limit")?.args, [1, { referencedTable: "sync_runs" }]);
  assert.ok(calls.some((call) => call.method === "eq" && call.args[0] === "tenant_id" && call.args[1] === "company-a"));
  assert.ok(calls.some((call) => call.method === "eq" && call.args[0] === "is_active" && call.args[1] === true));
});
