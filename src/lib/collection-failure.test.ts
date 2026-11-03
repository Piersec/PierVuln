import test from "node:test";
import assert from "node:assert/strict";
import { collectionFailure } from "./collection-failure";

test("distinguishes certificate identity, trust and expiry from credentials", () => {
  assert.match(collectionFailure("ERR_TLS_CERT_ALTNAME_INVALID"), /endereço.*certificado/);
  assert.match(collectionFailure("SELF_SIGNED_CERT_IN_CHAIN"), /certificado CA/);
  assert.match(collectionFailure("CERT_HAS_EXPIRED"), /expirou/);
  assert.match(collectionFailure("Indexer HTTP 401"), /usuário e a senha/);
  assert.match(collectionFailure("Indexer HTTP 403"), /permissão/);
});

test("identifies publication and network failures without echoing sensitive raw errors", () => {
  assert.match(collectionFailure("Supabase recusou finish com HTTP 500."), /banco não concluiu/);
  assert.match(collectionFailure("ECONNREFUSED"), /endereço, a porta/);
  assert.doesNotMatch(collectionFailure("secret-token"), /secret-token/);
});
