import test from "node:test";
import assert from "node:assert/strict";
import { changeNotice, enqueueNotice, parseAdminChange } from "./admin-notifications";
import type { AdminNotice } from "./admin-notifications";

test("notifications accept only administrative entities and discard secret fields", () => {
  assert.equal(parseAdminChange({ id: "1", table: "wazuh_ingest_credentials", entity_id: "c", operation: "UPDATE" }), null);
  const change = parseAdminChange({ id: "2", table: "wazuh_connections", entity_id: "c", operation: "UPDATE", label: "Wazuh compartilhado MAXIPARK", is_active: false, ingestToken: "secret", endpoint_url: "https://user:secret@example.com" });
  assert.ok(change);
  assert.equal(JSON.stringify(change).includes("secret"), false);
  assert.equal(changeNotice(change).title, "Conexão: atualizada.");
  assert.equal(changeNotice(change).detail, "Indexador compartilhado MAXIPARK · Inativa");
});

test("sync failures become error notices and successful syncs stay informational", () => {
  const base = { id: "1", table: "sync_runs", entity_id: "run", operation: "UPDATE" as const, label: "" };
  assert.equal(changeNotice({ ...base, status: "failed" }).error, true);
  assert.equal(changeNotice({ ...base, status: "succeeded" }).error, false);
});

test("queue coalesces updates to the same entity without losing a one-time secret", () => {
  const secret = { id: "secret", title: "Conexão criada", secret: "one-time", key: "connection:1" };
  const first = { id: "first", title: "Executando", key: "sync:1" };
  const latest = { id: "latest", title: "Concluída", key: "sync:1" };
  const queue = enqueueNotice(enqueueNotice([secret], first), latest);
  assert.deepEqual(queue.map((item) => item.id), ["secret", "latest"]);
  assert.equal(enqueueNotice([secret], { id: "next", title: "Atualizada", key: "connection:1" }).length, 2);
});

test("notification bursts keep the visible notice, retain errors, and cap the queue", () => {
  let queue: AdminNotice[] = [{ id: "visible", title: "Em leitura" }, { id: "failure", title: "Falha", error: true }];
  for (let i = 0; i < 30; i++) queue = enqueueNotice(queue, { id: `notice-${i}`, title: "Filtro atualizado" });
  assert.equal(queue.length, 8);
  assert.equal(queue[0].id, "visible");
  assert.ok(queue.some((notice) => notice.id === "failure"));
  assert.ok(queue.some((notice) => notice.id === "notice-29"));
});

test("informational notices do not replace a queue filled with failures", () => {
  const failures = Array.from({ length: 8 }, (_, i) => ({ id: String(i), title: "Falha", error: true }));
  assert.deepEqual(enqueueNotice(failures, { id: "filter", title: "Filtro atualizado" }), failures);
});
