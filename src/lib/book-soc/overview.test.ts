import { test } from "node:test";
import assert from "node:assert/strict";
import { AGE_LABELS, buildOverviewQuery, lastMonths, parseOverviewRequest, parseOverviewResponse } from "./overview";

test("aceita só um identificador de cliente válido", () => {
  assert.deepEqual(parseOverviewRequest({ client: "jean-piaget" }), { client: "jean-piaget" });
  assert.equal(parseOverviewRequest({ client: "../x" }), null);
  assert.equal(parseOverviewRequest({ client: 5 }), null);
  assert.equal(parseOverviewRequest({}), null);
  assert.equal(parseOverviewRequest(null), null);
});

test("monta a consulta só com agregações e limites de idade vindos do servidor", () => {
  const now = new Date("2026-11-10T12:00:00.000Z");
  const query = buildOverviewQuery(now) as any;
  assert.equal(query.size, 0);
  assert.deepEqual(query.query, { match_all: {} });
  assert.deepEqual(Object.keys(query.aggs), ["severidade", "hosts", "cves", "idade", "meses", "topCves"]);
  assert.deepEqual(query.aggs.idade.date_range.ranges, [
    { from: "2026-11-03T12:00:00.000Z" },
    { from: "2026-10-11T12:00:00.000Z", to: "2026-11-03T12:00:00.000Z" },
    { from: "2026-08-12T12:00:00.000Z", to: "2026-10-11T12:00:00.000Z" },
    { to: "2026-08-12T12:00:00.000Z" },
  ]);
  assert.equal(query.aggs.idade.date_range.field, "vulnerability.detected_at");
});

test("lê as faixas de idade pelo limite inferior, não pela posição devolvida", () => {
  // O Elasticsearch devolve a faixa mais antiga (sem limite inferior) primeiro.
  const overview = parseOverviewResponse({
    hits: { total: { value: 100 } },
    aggregations: {
      idade: { buckets: [
        { to: 1000, doc_count: 4 },
        { from: 1000, to: 2000, doc_count: 3 },
        { from: 2000, to: 3000, doc_count: 2 },
        { from: 3000, doc_count: 91 },
      ] },
    },
  });
  assert.deepEqual(overview.idade, [
    { label: AGE_LABELS[0], registros: 91 },
    { label: AGE_LABELS[1], registros: 2 },
    { label: AGE_LABELS[2], registros: 3 },
    { label: AGE_LABELS[3], registros: 4 },
  ]);
});

test("lê total, hosts, CVEs, severidade e principais CVEs sem devolver documentos", () => {
  const overview = parseOverviewResponse({
    hits: { total: { value: 42 }, hits: [{ _source: { secret: "documento bruto" } }] },
    aggregations: {
      severidade: { buckets: [{ key: "High", doc_count: 30 }, { key: "Low", doc_count: 12 }] },
      hosts: { value: 7 },
      cves: { value: 9 },
      meses: { buckets: [{ key_as_string: "2026-11", key: 1, doc_count: 42 }] },
      topCves: { buckets: [{
        key: "CVE-2026-0001", doc_count: 30, hosts: { value: 5 },
        severidade: { buckets: [{ key: "High", doc_count: 30 }] }, cvss: { value: 7.800000190734863 },
      }] },
    },
  });
  assert.equal(overview.total, 42);
  assert.equal(overview.hosts, 7);
  assert.equal(overview.cves, 9);
  assert.deepEqual(overview.porSeveridade, [{ severidade: "High", registros: 30 }, { severidade: "Low", registros: 12 }]);
  assert.deepEqual(overview.meses, [{ mes: "2026-11", registros: 42 }]);
  assert.deepEqual(overview.topCves, [{ cve: "CVE-2026-0001", severidade: "High", cvss: 7.8, registros: 30, hosts: 5 }]);
  assert.equal(JSON.stringify(overview).includes("documento bruto"), false);
});

test("trata resposta vazia e recusa contagem total inválida", () => {
  const empty = parseOverviewResponse({ hits: { total: { value: 0 } } });
  assert.equal(empty.total, 0);
  assert.deepEqual(empty.topCves, []);
  assert.deepEqual(empty.idade.map((item) => item.registros), [0, 0, 0, 0]);
  assert.throws(() => parseOverviewResponse({ hits: { total: { value: -1 } } }));
});

test("preenche com zero os meses sem registro, terminando no mês atual", () => {
  const months = lastMonths([{ mes: "2026-11", registros: 5 }, { mes: "2026-08", registros: 2 }], 6, new Date(2026, 10, 10));
  assert.deepEqual(months.map((item) => item.key), ["2026-06", "2026-07", "2026-08", "2026-09", "2026-10", "2026-11"]);
  assert.deepEqual(months.map((item) => item.registros), [0, 0, 2, 0, 0, 5]);
});
