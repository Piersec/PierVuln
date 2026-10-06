import assert from "node:assert/strict";
import test from "node:test";
import { normalizeWazuhDocument, WazuhIndexerClient } from "../src/wazuh.js";
import { synchronizeSnapshot, type SupabaseIngestClient } from "../src/ingest.js";

test("records a failed run when the Indexer is unreachable before the first page", async () => {
  const calls: string[] = [];
  const indexer = {
    getVersion: async () => { throw new Error("Indexer connection timeout"); },
  };
  const destination = {
    startSync: async () => { calls.push("start"); return "failed-run"; },
    failSync: async (id: string, message: string) => {
      assert.equal(id, "failed-run");
      assert.match(message, /timeout/);
      calls.push("fail");
    },
    finishSync: async () => { calls.push("finish"); },
  };
  await assert.rejects(synchronizeSnapshot(indexer as unknown as WazuhIndexerClient, destination as unknown as SupabaseIngestClient, 500), /timeout/);
  assert.deepEqual(calls, ["start", "fail"]);
});

test("normalizes Wazuh Indexer fields without depending on the CSV column order", () => {
  const item = normalizeWazuhDocument("indexer-stable-id", {
    agent: { id: "004", name: "linux-prod-04", groups: ["linux", "production"] },
    host: { os: { name: "Ubuntu 24.04" } },
    package: { name: "openssl", version: "3.0.13", type: "deb", architecture: "amd64" },
    vulnerability: {
      id: "CVE-2026-11111",
      description: "Example description",
      severity: "High",
      score: { base: 8.2 },
      reference: ["https://example.test/advisory"],
      status: "Active",
    },
  });

  assert.equal(item.documentId, "indexer-stable-id");
  assert.equal(item.agentId, "004");
  assert.equal(item.packageVersion, "3.0.13");
  assert.equal(item.vulnerabilityId, "CVE-2026-11111");
  assert.equal(item.severity, "High");
  assert.equal(item.cvssBase, 8.2);
  assert.deepEqual(item.agentGroups, ["linux", "production"]);
  assert.deepEqual(item.references, ["https://example.test/advisory"]);
});

test("rejects Indexer URLs without TLS and unrelated index patterns", () => {
  assert.throws(() => new WazuhIndexerClient("http://indexer:9200", "u", "p", "wazuh-states-vulnerabilities-*"));
  assert.throws(() => new WazuhIndexerClient("https://indexer:9200", "u", "p", "wazuh-alerts-*"));
});

test("finishes a snapshot only after every page is received", async () => {
  const sent: number[] = [];
  let nextCall = 0;
  let finishCalls = 0;
  const indexer = {
    getVersion: async () => "4.14.0",
    startScroll: async () => ({ total: 2, scrollId: "scroll-1", hits: [{ _id: "one", _source: {} }] }),
    continueScroll: async () => {
      nextCall += 1;
      return nextCall === 1
        ? { total: null, scrollId: "scroll-2", hits: [{ _id: "two", _source: {} }] }
        : { total: null, scrollId: "scroll-2", hits: [] };
    },
    clearScroll: async () => undefined,
  };
  const destination = {
    startSync: async () => "run-id",
    ingestPage: async (_run: string, page: number) => { sent.push(page); return 1; },
    finishSync: async () => { finishCalls += 1; return 0; },
    failSync: async () => undefined,
  } as unknown as SupabaseIngestClient;

  const result = await synchronizeSnapshot(indexer as never, destination, 1);
  assert.deepEqual(sent, [0, 1]);
  assert.equal(result.documents, 2);
  assert.equal(result.changed, 2);
  assert.equal(finishCalls, 1);
});

test("marks incomplete pagination failed and never calls the complete operation", async () => {
  let finishCalls = 0;
  let failCalls = 0;
  const indexer = {
    getVersion: async () => "4.14.0",
    startScroll: async () => ({ total: 2, scrollId: "scroll-1", hits: [{ _id: "one", _source: {} }] }),
    continueScroll: async () => ({ total: null, scrollId: "scroll-2", hits: [] }),
    clearScroll: async () => undefined,
  };
  const destination = {
    startSync: async () => "run-id",
    ingestPage: async () => 1,
    finishSync: async () => { finishCalls += 1; return 0; },
    failSync: async () => { failCalls += 1; },
  } as unknown as SupabaseIngestClient;

  await assert.rejects(() => synchronizeSnapshot(indexer as never, destination, 1), /não recebeu todos os documentos/);
  assert.equal(finishCalls, 0);
  assert.equal(failCalls, 1);
});
