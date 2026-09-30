import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { SiteIsland } from "./site-island";

test("the site has no island or connection indicator without a notification", () => {
  assert.equal(renderToStaticMarkup(createElement(SiteIsland, { notices: [], dismiss: () => {}, host: null, openInbox: () => {}, inboxOpen: false })), "");
});

test("site action notifications expose their result and dismissal control", () => {
  const html = renderToStaticMarkup(createElement(SiteIsland, { notices: [{ id: "1", title: "Comentário publicado." }], dismiss: () => {}, host: null, openInbox: () => {}, inboxOpen: false }));
  assert.ok(html.includes("Comentário publicado."));
  assert.ok(html.includes("Dispensar toast"));
  assert.ok(html.includes("Notificação recente"));
  assert.ok(html.includes('aria-haspopup="dialog"'));
  assert.equal(html.includes("Supabase conectado"), false);
});
