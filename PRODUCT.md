# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- A equipe interna da Pier administra empresas, usuários, conexões Wazuh e vínculos de agentes.
- Usuários convidados de clientes acompanham vulnerabilidades e o tratamento da própria empresa.
- Administradores internos podem alternar entre empresas; usuários de cliente veem somente a empresa à qual pertencem.

## Product Purpose

O PierVuln apresenta vulnerabilidades detectadas pelo Wazuh e permite acompanhar o tratamento com histórico. Sucesso significa que os números representam os achados atuais do Wazuh, a atualização da fonte é visível e as informações de cada cliente permanecem isoladas.

## Operating Context

- O Wazuh compartilhado é separado por vínculos manuais de agente ou grupo.
- A conexão Wazuh compartilhada é segmentada por vínculos manuais de agentes ou grupos cadastrados no banco.
- Os dados são sincronizados do índice de vulnerabilidades do Wazuh por um conector; o painel usa as leituras completas mais recentes do banco.

## Capabilities and Constraints

- O repositório usa Next.js App Router, React, TypeScript, Supabase Auth/Postgres com RLS e um conector para a API do Indexer Wazuh.
- O app oferece painel de vulnerabilidades, acompanhamento de fluxo, comentários, histórico e ferramentas internas de administração.
- Achados sem associação válida a uma empresa não aparecem na visão do cliente.
- Uma leitura parcial ou falha não confirma resolução. Achados ativos permanecem no painel; o histórico resolvido tem retenção limitada.
- O conector compartilhado ainda precisa manter a associação de agentes e grupos de cada cliente atualizada.
- O painel deve indicar quando a última leitura completa está ausente ou desatualizada; a meta de cinco minutos começa após o Wazuh indexar o dado.
- A base atual não guarda snapshots mensais do total histórico. Gráficos mensais devem dizer quando agrupam achados atuais pela data de primeira detecção, sem afirmar que são totais históricos do Wazuh.

## Brand Commitments

- O produto se chama PierVuln e mantém a marca existente no repositório.

## Evidence on Hand

- As três capturas fornecidas em 2026-09-29 orientam o Book dos Clientes: resumo da exposição, distribuição por severidade, série temporal, faixas de idade, top vulnerabilidades e contagem de ativos/CVEs.
- Os dados de produção vêm do Wazuh sincronizado; valores ilustrativos nas referências não devem ser copiados para a interface.
- O CSV inicial é apenas referência de mapeamento e não tem identificadores e estado suficientes para ser a fonte operacional.

## Product Principles

- Isolar os dados de cada empresa em toda consulta e visualização.
- Tratar o Wazuh como fonte do estado atual e exibir o horário da última leitura completa.
- Nunca resolver um caso por causa de uma leitura incompleta.
- Usar métricas inteiras e rótulos que expliquem qual período e estado estão sendo contados.
