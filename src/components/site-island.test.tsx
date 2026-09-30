import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { SiteIsland } from "./site-island";

test("the site has no island or connection indicator without a notification", () => {
  assert.equal(renderToStaticMarkup(createElement(SiteIsland, { notices: [], dismiss: () => {}, host: null })), "");
});

test("site action notifications expose their result and dismissal control", () => {
  const html = renderToStaticMarkup(createElement(SiteIsland, { notices: [{ id: "1", title: "Comentário publicado." }], dismiss: () => {}, host: null }));
  assert.ok(html.includes("Comentário publicado."));
  assert.ok(html.includes("Dispensar notificação"));
  assert.ok(html.includes("Notificações do site"));
  assert.equal(html.includes("Supabase conectado"), false);
});
