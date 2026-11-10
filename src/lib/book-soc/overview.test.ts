import { test } from "node:test";
import assert from "node:assert/strict";
import { buildOverviewQuery, parseOverviewRequest, parseOverviewResponse, scopeFromMappings, VULNERABILITY_INDEX } from "./overview";

const COMPANY = "a9842897-fd0f-458a-a413-8e2c09d47b25";

test("aceita pedido sem empresa ou com empresa válida e recusa o resto", () => {
  assert.deepEqual(parseOverviewRequest({}), {});
  assert.deepEqual(parseOverviewRequest({ companyId: COMPANY }), { companyId: COMPANY });
  assert.equal(parseOverviewRequest({ companyId: "not-a-uuid" }), null);
  assert.equal(parseOverviewRequest(null), null);
});

test("consulta o índice de vulnerabilidades só com agregados", () => {
  assert.equal(VULNERABILITY_INDEX, "wazuh-states-vulnerabilities-*");
  const query = buildOverviewQuery() as any;
  assert.equal(query.size, 0);
  assert.deepEqual(query.query, { match_all: {} });
  assert.deepEqual(Object.keys(query.aggs), ["severidade", "cve", "agente"]);
});

test("recorta pelas mesmas regras do PierVuln: agent_id e prefixo de nome", () => {
  const scope = scopeFromMappings([
    { match_type: "agent_name_prefix", match_value: "100-pbxyamam*" },
    { match_type: "agent_id", match_value: "001" },
    { match_type: "group", match_value: "linux" },
  ]);
  assert.deepEqual(scope, { agentIds: ["001"], namePrefixes: ["100-pbxyamam"] });
  const query = buildOverviewQuery(scope!) as any;
  assert.deepEqual(query.query.bool.should, [
    { terms: { "agent.id": ["001"] } },
    { prefix: { "agent.name": { value: "100-pbxyamam", case_insensitive: true } } },
  ]);
  assert.equal(scopeFromMappings([{ match_type: "group", match_value: "linux" }]), null);
});

test("lê total e agregados sem devolver documentos", () => {
  const overview = parseOverviewResponse({
    hits: { total: { value: 42 }, hits: [{ _source: { secret: "documento bruto" } }] },
    aggregations: {
      severidade: { buckets: [{ key: "High", doc_count: 30 }, { key: "Low", doc_count: 12 }] },
      cve: { buckets: [{ key: "CVE-2024-0001", doc_count: 30 }] },
      agente: { buckets: [{ key: "srv-01", doc_count: 42 }] },
    },
  });
  assert.equal(overview.total, 42);
  assert.deepEqual(overview.porSeveridade, [{ severidade: "High", registros: 30 }, { severidade: "Low", registros: 12 }]);
  assert.deepEqual(overview.porCve, [{ cve: "CVE-2024-0001", registros: 30 }]);
  assert.deepEqual(overview.porAgente, [{ agente: "srv-01", registros: 42 }]);
  assert.equal(JSON.stringify(overview).includes("documento bruto"), false);
});

test("recusa contagem total inválida", () => {
  assert.throws(() => parseOverviewResponse({ hits: { total: { value: -1 } } }));
});
