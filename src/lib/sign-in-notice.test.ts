import test from "node:test";
import assert from "node:assert/strict";
import { signInNotice } from "./sign-in-notice";

test("server timeouts and backend failures do not suggest changing credentials", () => {
  for (const status of [500, 502, 503, 504]) {
    const text = signInNotice({ status });
    assert.match(text, /indisponível/);
    assert.doesNotMatch(text, /senha|convite/);
  }
});
test("transport failures returned by the Auth SDK are treated as unavailability", () => {
  assert.match(signInNotice({ status: 0, name: "AuthRetryableFetchError" }), /indisponível/);
});
test("captcha and rate limits keep their own recovery instructions", () => {
  assert.match(signInNotice({ status: 500, code: "captcha_failed" }), /desafio de segurança/);
  assert.match(signInNotice({ status: 429 }), /Muitas tentativas/);
});
test("invalid credentials stay generic and do not disclose account existence", () => {
  assert.equal(signInNotice({ status: 400, code: "invalid_credentials" }), "Não foi possível entrar. Confira o e-mail e a senha.");
});
