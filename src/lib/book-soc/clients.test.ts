import { test } from "node:test";
import assert from "node:assert/strict";
import { findClient, loadClients, publicClients, slugFor } from "./clients";

const b64 = (value: string) => Buffer.from(value, "utf8").toString("base64");
const env = {
  BOOK_SOC_CLIENTS: "ALFA, BETA_DOIS ,SEM_HTTPS,SEM_SENHA,INDICE_RUIM,minusculo",
  BOOK_SOC_ALFA_NAME: "Alfa", BOOK_SOC_ALFA_URL: "https://10.0.0.1:9200/", BOOK_SOC_ALFA_USER: "book_alfa",
  BOOK_SOC_ALFA_PASSWORD_B64: b64("p@ss$word#1"), BOOK_SOC_ALFA_INDEX: "wazuh-states-vulnerabilities-env1-manager",
  BOOK_SOC_ALFA_ALERTS_INDEX: "wazuh-alerts-4.x-alfa-*", BOOK_SOC_ALFA_EXCLUDED_GROUPS: "vulnerability-detector, grupo.x ,inv@lido",
  BOOK_SOC_BETA_DOIS_NAME: "Beta Dois", BOOK_SOC_BETA_DOIS_URL: "https://10.0.0.2:9200", BOOK_SOC_BETA_DOIS_USER: "book",
  BOOK_SOC_BETA_DOIS_PASSWORD_B64: b64("outra"), BOOK_SOC_BETA_DOIS_INDEX: "wazuh-states-vulnerabilities-*",
  BOOK_SOC_SEM_HTTPS_URL: "http://10.0.0.3:9200", BOOK_SOC_SEM_HTTPS_USER: "u", BOOK_SOC_SEM_HTTPS_PASSWORD_B64: b64("x"), BOOK_SOC_SEM_HTTPS_INDEX: "idx",
  BOOK_SOC_SEM_SENHA_URL: "https://10.0.0.4:9200", BOOK_SOC_SEM_SENHA_USER: "u", BOOK_SOC_SEM_SENHA_INDEX: "idx",
  BOOK_SOC_INDICE_RUIM_URL: "https://10.0.0.5:9200", BOOK_SOC_INDICE_RUIM_USER: "u", BOOK_SOC_INDICE_RUIM_PASSWORD_B64: b64("x"), BOOK_SOC_INDICE_RUIM_INDEX: "../_all",
};

test("carrega só clientes completos e com HTTPS, decodificando a senha", () => {
  const clients = loadClients(env);
  assert.deepEqual(clients.map((client) => client.slug), ["alfa", "beta-dois"]);
  assert.equal(clients[0].password, "p@ss$word#1");
  assert.equal(clients[0].url, "https://10.0.0.1:9200");
  assert.equal(clients[1].name, "Beta Dois");
});

test("a lista pública não traz endereço, usuário nem senha", () => {
  const publicList = publicClients(loadClients(env));
  assert.deepEqual(publicList, [{ id: "alfa", name: "Alfa", alerts: true }, { id: "beta-dois", name: "Beta Dois", alerts: false }]);
  const text = JSON.stringify(publicList);
  for (const secret of ["10.0.0.1", "book_alfa", "p@ss", "wazuh-states", "wazuh-alerts", "vulnerability-detector"]) assert.equal(text.includes(secret), false);
});

test("índice de alertas é opcional e os grupos excluídos têm padrão seguro", () => {
  const [alfa, beta] = loadClients(env);
  assert.equal(alfa.alertsIndex, "wazuh-alerts-4.x-alfa-*");
  assert.deepEqual(alfa.excludedGroups, ["vulnerability-detector", "grupo.x"]); // descarta o grupo inválido
  assert.equal(beta.alertsIndex, null);
  assert.deepEqual(beta.excludedGroups, ["vulnerability-detector"]);
});

test("sem variável de clientes, a lista é vazia", () => {
  assert.deepEqual(loadClients({}), []);
});

test("encontra o cliente só pelo identificador exato", () => {
  const clients = loadClients(env);
  assert.equal(findClient(clients, "alfa")?.name, "Alfa");
  assert.equal(findClient(clients, "ALFA"), undefined);
  assert.equal(findClient(clients, undefined), undefined);
  assert.equal(slugFor("JEAN_PIAGET"), "jean-piaget");
});
