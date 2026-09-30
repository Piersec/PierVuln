import test from "node:test";
import assert from "node:assert/strict";
import { noticeKind, parseInbox, parseMutedKinds, toInboxNotice } from "./notification-inbox";

test("the inbox keeps the message but never stores a one-time connector secret", () => {
  const notice = toInboxNotice({ id: "1", title: "Conexão criada", detail: "Pronta para uso", key: "connection:123", secret: "one-time-token" }, 1000);
  assert.equal(notice.title, "Conexão criada");
  assert.equal(JSON.stringify(notice).includes("one-time-token"), false);
  assert.equal(noticeKind(notice), "key:connection");
  assert.equal(noticeKind({ title: "Falha ao salvar" }), "title:falha ao salvar");
});

test("stored notices are validated and old data is cleaned before display", () => {
  const stored = JSON.stringify([
    { id: "1", title: "Wazuh atualizado", detail: "Wazuh respondeu", createdAt: 1000, read: false, secret: "do-not-show" },
    { id: "2", title: "Inválida", createdAt: Number.MAX_VALUE },
  ]);
  assert.deepEqual(parseInbox(stored).map(({ title, detail }) => ({ title, detail })), [{ title: "Indexador atualizado", detail: "Indexador respondeu" }]);
  assert.equal(JSON.stringify(parseInbox(stored)).includes("do-not-show"), false);
  assert.deepEqual(parseMutedKinds('["key:network","key:network",42]'), ["key:network"]);
});
