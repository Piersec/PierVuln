import assert from "node:assert/strict";
import test from "node:test";
import { isSyncBoundary } from "./live-events";

test("live refresh ignores per-page progress and includes completion and failure", () => {
  assert.equal(isSyncBoundary("INSERT", { status: "running" }), true);
  assert.equal(isSyncBoundary("UPDATE", { status: "running" }), false);
  assert.equal(isSyncBoundary("UPDATE", { status: "succeeded" }), true);
  assert.equal(isSyncBoundary("UPDATE", { status: "failed" }), true);
  assert.equal(isSyncBoundary("DELETE", {}), true);
});
