import test from "node:test";
import assert from "node:assert/strict";
import { ConfigurationChanges } from "../src/configuration-changes";

test("a corrected endpoint or credential becomes due without waiting for failure backoff", () => {
  const changes = new ConfigurationChanges();
  const job = { key: "a", connection: { url: "https://old.example", password: "old" } };
  assert.deepEqual(changes.changed([job]), ["a"]);
  assert.deepEqual(changes.changed([job]), []);
  assert.deepEqual(changes.changed([{ ...job, connection: { ...job.connection, url: "https://new.example" } }]), ["a"]);
  assert.deepEqual(changes.changed([{ ...job, connection: { url: "https://new.example", password: "new" } }]), ["a"]);
});

test("equivalent configuration order does not continuously restart collection", () => {
  const changes = new ConfigurationChanges();
  changes.changed([{ key: "a", connection: { tenants: [{ id: "1" }, { id: "2" }], url: "https://source.example" } }]);
  assert.deepEqual(changes.changed([{ key: "a", connection: { url: "https://source.example", tenants: [{ id: "2" }, { id: "1" }] } }]), []);
});

test("unchanged companies retain their retry schedule and reactivated jobs run immediately", () => {
  const changes = new ConfigurationChanges();
  const a = { key: "a", connection: { password: "a" } };
  const b = { key: "b", connection: { password: "b" } };
  changes.changed([a, b]);
  assert.deepEqual(changes.changed([{ ...a, connection: { password: "new" } }, b]), ["a"]);
  changes.changed([b]);
  assert.deepEqual(changes.changed([a, b]), ["a"]);
});
