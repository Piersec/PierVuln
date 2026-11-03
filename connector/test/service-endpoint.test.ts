import test from "node:test";
import assert from "node:assert/strict";
import { serviceEndpoint } from "../../supabase/functions/_shared/service-endpoint";

test("accepts independently certified addresses for Indexer and Manager", () => {
  assert.equal(serviceEndpoint("https://127.0.0.1:9200")?.hostname, "127.0.0.1");
  assert.equal(serviceEndpoint("https://192.168.15.9:55000")?.hostname, "192.168.15.9");
  assert.equal(serviceEndpoint("https://manager.example:55000")?.hostname, "manager.example");
});

test("rejects malformed URLs and credentials embedded in endpoint URLs", () => {
  for (const value of [null, "invalid", "http://manager.example", "https://user:secret@manager.example", "https://manager.example?token=secret", "https://manager.example#secret"]) assert.equal(serviceEndpoint(value), null);
});
