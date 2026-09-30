# Planos 1 e 2: implementação e validação

Data: 30/09/2026. Ambiente publicado: https://piervuln.vercel.app.

O painel contém visão geral, empresas, integrações, usuários e auditoria. Empresa e conexão podem ser desativadas e restauradas com histórico preservado. A listagem de usuários do Auth passa pela Edge Function protegida. A equipe Pier mantém acesso administrativo interno.

Após a correção de escopo solicitada durante a execução, o Dynamic Island é um toast geral do site. Não existe pílula em repouso nem indicador permanente de conexão. Sucessos desaparecem em 5 segundos e erros em 9 segundos; foco e leitura com o mouse pausam a contagem. É possível expandir, recolher ou dispensar. O segredo de uma nova conexão aparece em um diálogo separado para cópia.

As ações de casos, comentários, acesso e administração usam o componente global. Eventos administrativos do banco usam um canal privado do Supabase, disponível à equipe Pier nas páginas do site. Eles não expõem endpoints nem credenciais. Alterações locais e eventos do mesmo registro são deduplicados.

## Verificações executadas

- `pnpm build`: todas as rotas compiladas.
- `pnpm typecheck`: sem erros.
- Testes de notificações: parser, campos permitidos, falha de sincronização, fila, ausência de pílula em repouso e controles do toast.
- `supabase/tests/admin_api.mjs`: ações administrativas e RPC de dados do Auth recusam acesso anônimo no ambiente publicado.
- `supabase/tests/admin_access.sql`: executado com rollback; isolamento entre empresas, desativação/restauração, bloqueio de conexão inativa, manutenção de histórico e proteção do canal privado.
- Navegador autenticado: dados reais carregados em visão geral, empresas, usuários e auditoria; busca sem resultados; editor de empresa; salvar o nome existente; formulário de convite e opção Equipe Pier; cancelamento. Integrações e seus vínculos também foram inspecionados durante a implementação.
- Versão final publicada: ausência do indicador fixo confirmada no DOM. Na auditoria, a largura do documento ficou dentro da janela no teste de viewport de 390 px.
- Contraste calculado sobre a superfície mais clara usada nos novos componentes: texto principal 14,11:1, secundário 6,34:1, verde 8,80:1, alerta 10,35:1 e erro 5,74:1.

Não foram enviados convites nem criadas credenciais de teste em produção. Não havia manifestos para exercitar um download real. A captura de um toast de Broadcast fora do admin e a última passagem visual foram interrompidas por falhas de controle do navegador; o envio de eventos ao canal foi verificado no banco, mas a entrega visual completa não foi confirmada. Essas limitações não são registradas como testes aprovados.

## Delivery Gate de design

Escopo: componentes e telas novos dos planos. Direção: `DESIGN.md`, referências do usuário e pílula de notificação solicitada. ENERGY 2 / RHYTHM 2 / MOTION 2: métricas na visão geral, tabelas para trabalho diário, movimento restrito à notificação e desativado quando solicitado pelo sistema.

| Item | Estado e evidência |
| --- | --- |
| R-02 | PASS: textos novos sem travessão editorial. |
| R-03 | PASS na verificação realizada: rolagem das tabelas contida em regiões próprias; documento dentro do viewport móvel medido. |
| R-17 | PASS: métricas obtidas de registros e execuções do banco. |
| R-18 | PASS: nenhum depoimento criado. |
| R-23 | PASS: marca existente e navegação autorizada no plano. |
| R-24 | PASS: cinco rotas administrativas presentes no build. |
| R-25 | PASS: relações de contraste medidas acima de 4,5:1. |
| R-26 | PASS na revisão de implementação: controles ligados a navegação, filtros, diálogos ou ações protegidas; operações de produção não exercitadas estão discriminadas acima. |
| R-27 | PASS: carregamento, erro e ausência de registros implementados; estado vazio observado. |
| R-28 | PASS: sem FAQ adicionado. |
| R-32 | PASS na revisão: controles nativos, foco existente e diálogos com Escape; fechamento/cancelamento observados. |
| R-33 | PASS: comportamento definido nos componentes e CSS versionados; nenhum script modifica a interface em execução. |
| R-34 | PASS: nenhum seletor de tema adicionado. |
| R-35 | Verificação parcial: build e percurso seguro registrados; convites, credenciais, download e captura final têm as limitações descritas acima. |
| R-36 | PASS: sem alegações de segurança ou desempenho criadas para a interface. |
| R-37 | PASS: direção existente preservada; dials declarados nesta entrega. |
| R-38 | PASS: dados reais; avisos técnicos de teste identificados como teste. |
| R-01 | PASS: sem gradiente novo. |
| R-04 | PASS: símbolos existentes representam as áreas do produto. |
| R-06 | PASS: IBM Plex da marca; monospace reservado a identificadores e segredo. |
| R-07 | PASS: sem padrão de fundo novo. |
| R-08 | PASS: ações administrativas usam verbos explícitos. |
| R-09 | PASS: estados mostram situação real; pílula solicitada aparece somente com aviso. |
| R-10 | PASS: sem vidro novo. |
| R-12 | PASS: sombra restrita ao toast para separar a notificação sobreposta do conteúdo. |
| R-13 | PASS: sem glow novo. |
| R-14 | PASS: três métricas comparáveis; listagens usam tabelas adequadas aos dados. |
| R-19 | PASS: movimento do toast serve expansão; reduced motion definido. |
| R-22 | PASS: nenhuma ilustração adicionada. |
| Liveliness | PASS: verde da marca, hierarquia por título/ação/tabela, espaços entre tarefas e números reais; dials consistentes com a direção. |
| C-1 / C-3 / C-5 | PASS: decisões orientadas por dados administrativos e referências aprovadas; sem seção de preenchimento ou número inventado. |
| C-2 / C-4 | Revisão e testes seguros realizados; limites de validação de produção discriminados acima. |
| R-05 / R-11 | PASS: composição operacional, diferentes raios para tabelas, campos, diálogo e toast solicitado. |
| R-15 / R-16 | PASS: ações nomeadas por tarefa; sem linguagem promocional. |
| R-20 / R-21 | PASS: conteúdo da fonte de dados e identidade escura do projeto preservados. |
| R-29 / R-30 / R-31 | PASS: paleta existente, inspiração Apple limitada ao toast pedido; tabelas agrupam registros, diálogo concentra edição e notificações aparecem sob demanda. |
