import test from "node:test";
import assert from "node:assert/strict";
import { deleteCapability } from "../src/asset-delete-capability";
const policies = (mode: string, rules?: Record<string, string>) => ({ error: 0, data: { rbac_mode: mode, ...(rules ? { "agent:delete": rules } : {}) } });

test("white mode requires an explicit delete grant and preserves scope restrictions", () => {
  assert.equal(deleteCapability(policies("white")).status, "denied");
  assert.equal(deleteCapability(policies("white", { "agent:id:*": "allow" })).status, "allowed");
  assert.equal(deleteCapability(policies("white", { "agent:group:tenant": "allow" })).status, "restricted");
  assert.equal(deleteCapability(policies("white", { "agent:id:*": "allow", "agent:id:001": "deny" })).status, "restricted");
});

test("black mode defaults to allow and reports explicit denials conservatively", () => {
  assert.equal(deleteCapability(policies("black")).status, "allowed");
  assert.equal(deleteCapability(policies("black", { "agent:id:001": "deny" })).status, "restricted");
  assert.equal(deleteCapability(policies("black", { "agent:id:*": "deny" })).status, "denied");
  assert.equal(deleteCapability(policies("black", { "agent:id:*": "deny", "agent:id:002": "allow" })).status, "restricted");
});

test("unexpected or failed responses never become an unrestricted grant", () => {
  for (const value of [null, {}, { error: 1, data: {} }, { error: 0, data: {} }, policies("future"), policies("white", { "agent:id:*": "unexpected" }), policies("white", { "other:id:*": "allow" })]) assert.equal(deleteCapability(value).status, "unknown");
});
