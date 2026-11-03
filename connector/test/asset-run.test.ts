import test from "node:test";
import assert from "node:assert/strict";
import { runAssetCollection } from "../src/asset-run";

test("records authentication and TLS failures before the first agent page", async () => {
  const events: string[] = [];
  const error = new Error("fetch failed", { cause: { code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" } });
  await assert.rejects(runAssetCollection(async () => { events.push("start"); }, async () => { throw error; }, async (message) => { events.push(message); }), (received) => received === error);
  assert.deepEqual(events, ["start", "fetch failed (UNABLE_TO_VERIFY_LEAF_SIGNATURE)"]);
});

test("does not collect when registration fails or hide the original failure when reporting fails", async () => {
  let collected = false;
  await assert.rejects(runAssetCollection(async () => { throw Error("registration failed"); }, async () => { collected = true; }, async () => { throw Error("must not report"); }), /registration failed/);
  assert.equal(collected, false);
  const original = Error("authentication HTTP 401");
  await assert.rejects(runAssetCollection(async () => {}, async () => { throw original; }, async () => { throw Error("database unavailable"); }), (received) => received === original);
});
