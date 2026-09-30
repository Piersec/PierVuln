import assert from "node:assert/strict";
import test from "node:test";
import { notificationType, parseDisabledNotificationTypes } from "./notification-types";

test("notification categories remain stable across realtime and action notices", () => {
  assert.equal(notificationType({ title: "Leitura falhou", key: "sync_runs:1", source: "realtime", error: true }), "sync");
  assert.equal(notificationType({ title: "Conexão caiu", key: "network", error: true }), "connectivity");
  assert.equal(notificationType({ title: "Empresa atualizada", key: "companies:1", source: "realtime" }), "admin_changes");
  assert.equal(notificationType({ title: "Não foi possível salvar", error: true }), "errors");
  assert.equal(notificationType({ title: "Comentário publicado" }), "actions");
});

test("stored preferences discard unknown and duplicate categories", () => {
  assert.deepEqual(parseDisabledNotificationTypes(["sync", "sync", "unknown", 1, "actions"]), ["sync", "actions"]);
});
