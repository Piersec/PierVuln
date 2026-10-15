# Relógio de coleta na sidebar

Data: 15/10/2026. Escopo: novo indicador acima do perfil e passagem da empresa selecionada ao indicador.

A rosca usa o último status de cada fonte autorizada. Na visão interna, dashboard, casos, ativos e Book passam a seleção atual; as demais páginas usam a seleção lembrada. Contas de clientes mostram as fontes acessíveis à conta, identificadas assim no tooltip, pois as regras de associação são restritas à administração.

A contagem é uma **previsão pelo intervalo padrão de uma hora após a conclusão**. O próximo horário e o backoff de falhas existem apenas na memória do worker. Durante a coleta, aparece tempo decorrido com rosca indeterminada. Falhas, ausência de fonte e primeira coleta têm estados próprios; o relógio vencido permanece em zero. Atualizações de metadados ocorrem a cada minuto em aba visível, com prazo de 12 segundos e preservação da última leitura em caso de erro. O tique de um segundo é local.

Direção: tema escuro existente, tokens de texto existentes, ciano para ciclo normal, amarelo para previsão vencida e vermelho para falha. ENERGY 1 / RHYTHM 1 / MOTION 2: movimento restrito à coleta em andamento, desativado por preferência de movimento reduzido.

## Verificação funcional

- PASS: sete testes de cálculo, limites, falhas e consulta filtrada em `src/lib/sync-clock.test.ts`.
- PASS: `pnpm typecheck` e `pnpm build`, incluindo geração da rota `/status`.
- PASS: consulta SQL somente de leitura no projeto confirmou a relação `sync_runs_connection_id_fkey` e leitura da última execução por fonte ativa.
- PASS: componente real renderizado em fixture local no Chrome, em 1280 e 375 px, nos estados aguardando ciclo, executando, falha, vencido, sem fonte, carregando e consulta indisponível.
- PASS: 14 combinações verificadas sem overflow nem erros de console; tooltip dentro da viewport, Escape fecha, Enter segue `/status`, preferência de movimento reduzido desliga animação. A página de destino foi interceptada na fixture; não houve teste de sessão autenticada no site publicado.
- PASS: no desktop, limites geométricos confirmam a rosca acima do perfil. No celular, usa a linha compacta existente da conta.

## Gate antislop

Aplicado ao componente alterado; páginas e conteúdo existentes fora desse escopo não foram auditados.

- R-02 PASS: nenhuma frase usa travessão; estado sem dados usa pausa ou reticências.
- R-03 PASS: testes em 375 e 1280 px não encontraram overflow.
- R-17 PASS: status e horários vêm das execuções; previsão explicitamente identificada.
- R-18 PASS: nenhum depoimento ou pessoa fictícia adicionado.
- R-23 PASS: a rosca solicitada é SVG de interface; nenhum logo ou avatar criado.
- R-24 PASS: link aponta para a rota existente `/status`.
- R-25 PASS: menor contraste de texto testado: 6,34:1; ciano contra trilho: 5,73:1; amarelo contra trilho: 5,72:1; vermelho contra trilho: 3,80:1.
- R-26 PASS: único controle abre o status; Enter foi exercitado na fixture.
- R-27 PASS: carregamento, indisponibilidade, primeira coleta, ausência de fonte, atraso e falha representados.
- R-28 PASS: nenhuma FAQ adicionada.
- R-32 PASS: foco visível, nome acessível, sem anúncios a cada segundo; tooltip pode ser dispensado com Escape.
- R-33 PASS: alterações feitas diretamente nos arquivos-fonte; scripts locais usados somente para validação.
- R-34 PASS: tokens do tema existente; nenhuma alternância de tema adicionada ou alterada.
- R-35 PASS: build, TypeScript e interação da fixture do componente real passaram.
- R-36 PASS: nenhuma alegação de segurança, disponibilidade ou desempenho adicionada.
- R-37 PASS: direção herdada do tema e da sidebar existentes; propósito e intensidade registrados acima.
- R-38 PASS: fixtures de teste estão identificadas; nenhuma métrica fictícia no produto.
- R-01 PASS: sem gradiente, brilho ou efeito decorativo novo.
- R-04 PASS: círculo representa o ciclo solicitado; pausa e alerta representam estados reais.
- R-06 PASS: números monoespaçados pequenos evitam mudança de largura durante a contagem.
- R-19 PASS: animação limitada ao estado executando, com suporte a movimento reduzido.
- R-05 PASS: nenhum template ou seção nova; indicador encaixado na área da conta.
- R-11 PASS: formato circular serve à medida de ciclo; tooltip usa raio do sistema.
- R-15 PASS: ação explícita “Ver status da coleta”.
- R-16 PASS: texto funcional sem linguagem promocional.
- R-20 PASS: formato e posição derivam da sidebar compacta existente.
- R-21 PASS: tema escuro solicitado pelo projeto preservado.
- R-29 PASS: apenas tokens existentes e cores semânticas de estado.
- R-30 PASS: nenhuma interface externa copiada.
- R-31 PASS: razões de cor, tipografia, posição e movimento registradas acima.
- Liveliness PASS: foco no relógio; espaço separa o indicador da navegação e do perfil; ciano e tipografia seguem a identidade existente.
- C-1 PASS: cada decisão corresponde ao relógio solicitado ou a um estado operacional.
- C-2 PASS: nenhuma interação sem destino.
- C-3 PASS: nenhum conteúdo ou seção adicionado para preencher espaço.
- C-4 PASS: estados, teclado e duas larguras exercitados; nenhum controle depende apenas de hover.
- C-5 PASS: a previsão informa seu fundamento e limite, sem representar agendamento exato.
