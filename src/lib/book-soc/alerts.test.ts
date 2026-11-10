import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAlertsQuery, DEFAULT_FILTERS, filterLabel, normalizeFilters, parseAlertsRequest, parseAlertsResponse, periodWindow } from "./alerts";

test("os filtros padrão são os do Book: níveis 12 a 16, todas as origens", () => {
  assert.deepEqual(normalizeFilters(undefined), DEFAULT_FILTERS);
  assert.deepEqual(normalizeFilters({}), DEFAULT_FILTERS);
  assert.equal(filterLabel(DEFAULT_FILTERS), "Níveis 12–16 · Todas as origens");
});

test("valida níveis, decoder e listas de regras como o Book", () => {
  assert.deepEqual(normalizeFilters({ nivelMinimo: 5, nivelMaximo: 11, decoder: "json", regrasIncluidas: ["5712", "5710", "5710"] }),
    { nivelMinimo: 5, nivelMaximo: 11, decoder: "json", regrasIncluidas: ["5710", "5712"], regrasExcluidas: [] });
  assert.equal(normalizeFilters({ nivelMinimo: 13, nivelMaximo: 12 }), null);
  assert.equal(normalizeFilters({ nivelMaximo: 17 }), null);
  assert.equal(normalizeFilters({ nivelMinimo: -1 }), null);
  assert.equal(normalizeFilters({ nivelMinimo: "5" }), null);
  assert.equal(normalizeFilters({ decoder: "a'b" }), null);
  assert.equal(normalizeFilters({ regrasIncluidas: ["0"] }), null);
  assert.equal(normalizeFilters({ regrasIncluidas: ["1234567"] }), null);
  assert.equal(normalizeFilters({ regrasIncluidas: Array.from({ length: 21 }, (_, i) => String(i + 1)) }), null);
  assert.equal(normalizeFilters({ regrasIncluidas: ["5710"], regrasExcluidas: ["5710"] }), null);
  assert.equal(normalizeFilters({ qualquerOutro: 1 }), null);
  assert.equal(normalizeFilters([]), null);
});

test("o pedido exige cliente, datas válidas, período de até 93 dias e filtros válidos", () => {
  const ok = parseAlertsRequest({ client: "yamam", start: "2026-10-01", end: "2026-10-31" });
  assert.deepEqual(ok, { client: "yamam", start: "2026-10-01", end: "2026-10-31", filtros: DEFAULT_FILTERS });
  assert.equal(parseAlertsRequest({ client: "../x", start: "2026-10-01", end: "2026-10-31" }), null);
  assert.equal(parseAlertsRequest({ client: "yamam", start: "2026-10-31", end: "2026-10-01" }), null);
  assert.equal(parseAlertsRequest({ client: "yamam", start: "2026-02-30", end: "2026-03-01" }), null);
  assert.equal(parseAlertsRequest({ client: "yamam", start: "2026-01-01", end: "2026-04-04" }), null); // 94 dias
  assert.ok(parseAlertsRequest({ client: "yamam", start: "2026-01-01", end: "2026-04-03" })); // 93 dias
  assert.equal(parseAlertsRequest({ client: "yamam", start: "2026-10-01", end: "2026-10-31", filtros: { nivelMinimo: 99 } }), null);
});

test("o fim do período é exclusivo e o dia final entra inteiro, em horário de Brasília", () => {
  assert.deepEqual(periodWindow("2026-09-01", "2026-09-30"), { gte: "2026-09-01T00:00:00-03:00", lt: "2026-10-01T00:00:00-03:00" });
  assert.deepEqual(periodWindow("2026-12-31", "2026-12-31"), { gte: "2026-12-31T00:00:00-03:00", lt: "2027-01-01T00:00:00-03:00" });
});

test("monta a consulta com as regras do Book e sem devolver documentos", () => {
  const query = buildAlertsQuery({ start: "2026-10-01", end: "2026-10-31", filtros: DEFAULT_FILTERS }) as any;
  assert.equal(query.size, 0);
  assert.deepEqual(query.query, { range: { timestamp: { gte: "2026-10-01T00:00:00-03:00", lt: "2026-11-01T00:00:00-03:00" } } });
  const escopo = query.aggs.escopo;
  assert.deepEqual(escopo.filter, { bool: { must_not: [{ terms: { "rule.groups": ["vulnerability-detector"] } }] } });
  assert.deepEqual(escopo.aggs.revisao.filter.bool.filter, [{ range: { "rule.level": { gte: 12, lte: 16 } } }]);
  assert.equal(escopo.aggs.revisao.filter.bool.must_not, undefined);
  assert.deepEqual(escopo.aggs.admins.filter.bool.filter[0], { terms: { "data.win.system.eventID": ["4728", "4729"] } });
  assert.equal(escopo.aggs.admins.filter.bool.filter[1].wildcard["data.win.eventdata.targetSid"].value, "S-1-5-21-*-512");
});

test("aplica decoder e inclusão ou exclusão de regras só ao conjunto de revisão", () => {
  const filtros = { nivelMinimo: 10, nivelMaximo: 14, decoder: "json", regrasIncluidas: ["5710"], regrasExcluidas: ["100001"] };
  const query = buildAlertsQuery({ start: "2026-10-01", end: "2026-10-01", filtros }, ["grupo-x"]) as any;
  const review = query.aggs.escopo.aggs.revisao.filter.bool;
  assert.deepEqual(review.filter, [
    { range: { "rule.level": { gte: 10, lte: 14 } } }, { term: { "decoder.name": "json" } }, { terms: { "rule.id": ["5710"] } },
  ]);
  assert.deepEqual(review.must_not, [{ terms: { "rule.id": ["100001"] } }]);
  assert.deepEqual(query.aggs.escopo.filter.bool.must_not, [{ terms: { "rule.groups": ["grupo-x"] } }]);
  // Os filtros do painel não alteram o recorte de Domain Admins nem a lista de decoders.
  assert.equal(JSON.stringify(query.aggs.escopo.aggs.admins).includes("100001"), false);
  assert.equal(JSON.stringify(query.aggs.escopo.aggs.decoders).includes("json"), false);
});

test("lê volume, escopo, revisão, regras com participação e o restante fora da lista", () => {
  const result = parseAlertsResponse({
    hits: { total: { value: 1000 }, hits: [{ _source: { secret: "evento bruto" } }] },
    aggregations: { escopo: {
      doc_count: 990,
      decoders: { buckets: [{ key: "json", doc_count: 600 }, { key: "pfsense", doc_count: 390 }] },
      admins: { doc_count: 2 },
      revisao: { doc_count: 100, regras: { buckets: [
        { key: "5712", doc_count: 75, nivel: { buckets: [{ key: 12, doc_count: 75 }] }, exemplo: { hits: { hits: [{ fields: { "rule.description": ["Ataque de força bruta"] } }] } } },
        { key: "204", doc_count: 15, nivel: { buckets: [{ key: 12, doc_count: 15 }] }, exemplo: { hits: { hits: [] } } },
      ] } },
    } },
  });
  assert.equal(result.volume, 1000);
  assert.equal(result.escopo, 990);
  assert.equal(result.revisao, 100);
  assert.equal(result.admins, 2);
  assert.deepEqual(result.decoders, [{ nome: "json", registros: 600 }, { nome: "pfsense", registros: 390 }]);
  assert.deepEqual(result.regras, [
    { id: "5712", descricao: "Ataque de força bruta", nivel: 12, registros: 75, participacao: 0.75 },
    { id: "204", descricao: null, nivel: 12, registros: 15, participacao: 0.15 },
  ]);
  assert.equal(result.outrasRegras, 10);
  assert.equal(JSON.stringify(result).includes("evento bruto"), false);
});

test("trata resposta vazia sem dividir por zero e recusa total inválido", () => {
  const empty = parseAlertsResponse({ hits: { total: { value: 0 } } });
  assert.deepEqual([empty.volume, empty.revisao, empty.admins, empty.regras.length, empty.outrasRegras], [0, 0, 0, 0, 0]);
  assert.throws(() => parseAlertsResponse({ hits: { total: { value: -1 } } }));
});
