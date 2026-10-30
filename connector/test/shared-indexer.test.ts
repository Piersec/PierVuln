import test from "node:test";
import assert from "node:assert/strict";
import { SharedIndexer } from "../src/shared-indexer.js";
import type { WazuhIndexerClient, ScrollPage } from "../src/wazuh.js";
function client(ids: string[], fail = false) {
  let position = 0, pageSize = 0, cleared = false;
  const page = (): ScrollPage => { const hits = ids.slice(position, position += pageSize).map((_id) => ({ _id, _source: {} })); return { hits, total: ids.length, scrollId: "cursor" }; };
  return { api: { getVersion: async () => "test", countDocuments: async () => ids.length,
    startScroll: async (size: number) => { if (fail) throw new Error("tenant offline"); pageSize = size; return page(); },
    continueScroll: async () => page(), clearScroll: async () => { cleared = true; },
  } as unknown as WazuhIndexerClient, cleared: () => cleared };
}
test("pagination spans tenant boundaries without a short intermediate page", async () => {
 const a = client(["a", "b", "c"]), b = client(["d", "e", "f", "g"]);
 const source = new SharedIndexer([a.api, b.api]);
 const first = await source.startScroll(2, "5m"); assert.equal(first.total, 7);
 const pages = [first]; while (pages.at(-1)!.hits.length === 2) pages.push(await source.continueScroll("shared", "5m"));
 assert.deepEqual(pages.map((p) => p.hits.length), [2, 2, 2, 1]);
 assert.deepEqual(pages.flatMap((p) => p.hits.map((h) => h._id)), ["a", "b", "c", "d", "e", "f", "g"]);
 await source.clearScroll("shared"); assert.ok(a.cleared() && b.cleared());
});
test("a failed tenant prevents a partial snapshot and clears opened scrolls", async () => {
 const a = client(["a"]), b = client([], true); const source = new SharedIndexer([a.api,b.api]);
 await assert.rejects(source.startScroll(2, "5m"), /tenant offline/); assert.ok(a.cleared());
});
test("an empty tenant does not hide the following tenant", async () => {
 const source = new SharedIndexer([client([]).api, client(["a"]).api]);
 const page = await source.startScroll(2, "5m"); assert.equal(page.total, 1); assert.equal(page.hits[0]._id, "a");
 await source.clearScroll("shared");
});
