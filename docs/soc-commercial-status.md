# Execução do plano SOC e comercial

## Entregue nesta etapa

- Alertas: estado independente para erros de resumo e lista; timeout de 20 segundos; valores indisponíveis não aparecem como zero; período e horário da medição visíveis.
- Trocar empresa remonta o painel de alertas. Nenhuma medição anterior acompanha a nova empresa.
- Administração em `/admin/commercial`: cadastro e edição de planos, adicionais e leads; ativação e desativação de preços; seleção de plano e adicionais na ficha.
- Valores em centavos, calculados exclusivamente pela função `set_commercial_lead_selection`; adicionais duplicados contam uma vez; preços inativos são rejeitados.
- Seleção armazena revisão e snapshot dos preços. Editar o catálogo não altera uma ficha já calculada.
- Auditoria de alterações comerciais, sem copiar dados de contato para os eventos.
- Cinco tabelas comerciais com RLS e acesso exclusivo de administradores internos. Nenhum acesso anônimo. Fichas comerciais só recebem valores pela função protegida.
- Nenhum preço sugerido ou texto jurídico foi publicado como aprovado.

## Validação realizada

- Migração aplicada ao projeto de produção.
- Consulta transacional com rollback verificou implantação de R$ 1.510,00 e mensalidade de R$ 169,00 para plano de R$ 1.500,00 / R$ 149,00 mais adicional de R$ 10,00 / R$ 20,00.
- A mesma consulta verificou deduplicação de adicionais e ausência de SELECT anônimo e UPDATE direto nas condições comerciais.
- RLS confirmado nas cinco tabelas.
- TypeScript validado após ajuste do menu.
- Contraste das combinações novas de texto e fundo: 7,29:1 a 17,32:1.

## Próximas etapas do documento — ainda não entregues

1. Completar telas SOC de referência: analytics, risco, incidentes, monitoria, mapa e integridade; incluir somente métricas instrumentadas e estados explícitos de ausência de dados.
2. Instrumentar os tempos e o histórico dos incidentes antes de apresentar MTTD, MTTA, MTTR ou indicadores de automação.
3. Propostas públicas: tokens opacos armazenados como hash, expiração, limites de requisição, escolha por endpoint servidor e atualização da ficha única.
4. Configuração jurídica e identidade da prestadora; contratos PDF versionados, snapshots, indicação de versão anterior, assinaturas e arquivos privados.
5. Auditoria do fluxo público e dos contratos, validação anônima, reconciliação das contagens com a fonte autorizada e revisão visual das referências.
6. Conteúdo comercial público somente com preços, condições jurídicas e afirmações operacionais confirmados.

O plano completo permanece em execução. A página comercial atual é uma ferramenta interna, sem proposta pública ou geração de contrato.
