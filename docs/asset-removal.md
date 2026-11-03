# Remoção de ativos pela aplicação

Na página Ativos, administradores da plataforma e responsáveis com papel `owner` ou `admin` podem abrir o menu do ativo pelo botão direito ou pelo botão de ações. Analistas e leitores não podem solicitar exclusão.

A confirmação exige o nome exato (`EXCLUIR nome-do-ativo`), motivo de pelo menos dez caracteres e confirmação por deslizamento. A empresa, o ID e o IP aparecem na janela. O servidor vincula o pedido ao nome, IP e data de cadastro exibidos, e recusa um ativo que mudou enquanto a janela estava aberta.

## Caminho da operação

1. `request_asset_deletion` valida o usuário, vínculo da empresa, identidade e disponibilidade recente do coletor. O pedido recebe um UUID para evitar duplicação em tentativas de confirmação.
2. O daemon de ativos consulta uma fila leve de pedidos pendentes a cada dez segundos, em um ciclo independente da coleta de inventário. A consulta retorna somente empresa e conexão, sem credenciais ou detalhes dos agentes. Um pedido pendente inicia a validação sem esperar o próximo inventário; indisponibilidade de rede pode ampliar a espera. A mesma empresa nunca executa dois processadores de comandos em paralelo. A verificação de permissões e heartbeat continua no ciclo de configuração. Somente o token de configuração do coletor permite obter ou finalizar comandos. A função retorna um único pedido, com token exclusivo de execução.
3. O processo usa as credenciais e o certificado da API do Manager daquela empresa. A conexão compartilhada mantém uma credencial por empresa. As credenciais não passam pelo navegador.
4. Antes da exclusão, consulta o ID exato e compara nome, IP e data de cadastro. A chamada é `DELETE /agents`, com um único `agents_list`, `status=all`, `older_than=0s`, nome, IP e filtro da data de cadastro. Nunca envia `agents_list=all`.
5. Só aceita sucesso se a resposta confirmar exatamente aquele ID, um item afetado e zero falhas. Então o servidor retira aquela mesma versão do ativo da tabela local. Um snapshot antigo não pode recriá-la; uma nova inscrição, com outra data de cadastro, pode aparecer normalmente.

A conta da API precisa de `agent:read` e `agent:delete` restritos aos agentes/grupos da empresa. A aplicação não altera permissões da origem. TLS continua validando certificado e nome do servidor. A remoção retira o cadastro do Manager; não desinstala o software do equipamento. Alertas e incidentes históricos permanecem.

## Falhas e auditoria

O histórico registra solicitante, motivo, identificação, horários e resultado. Pedidos pendentes podem ser cancelados e expiram após 15 minutos. Não há reenvio automático da exclusão. Falta de resposta após o envio resulta em `uncertain`; somente o envio da confirmação de resultado pode ser repetido. Um resultado incerto exige conferência na origem e não libera um segundo pedido para aquele ativo. Uma confirmação tardia do mesmo coletor pode concluir o pedido.

O UUID do pedido, os parâmetros de empresa e conexão e o token de execução precisam coincidir na confirmação. Somente o serviço do coletor pode obter o token. Clientes autenticados não têm permissão de escrita direta nas tabelas de pedidos.

Na empresa `demonstracao`, o mesmo fluxo de confirmação simula a remoção local e grava `demo_simulated`; não chama um Manager real.

## Implantação e validação

A integração e a janela de exclusão mostram o último estado observado de `agent:delete`. O coletor autentica a conta de cada empresa e consulta `GET /security/users/me/policies` durante a verificação periódica de comandos, normalmente a cada minuto. Essa consulta não envia exclusões.

O indicador diferencia permissão irrestrita, permissão com restrições de agentes/grupos, ausência de permissão e resultado desconhecido. Mudança de configuração ou verificação com mais de três minutos invalida o resultado salvo. A conta da aplicação precisa ter autorização administrativa sobre a empresa para consultar o indicador; somente o serviço do coletor pode gravá-lo. A verificação informa a política observada e a API continua validando a operação real sobre o agente escolhido.

Aplicar as migrations de comandos e identidade, publicar a função `asset-commands` e atualizar o daemon junto dos arquivos `asset-deletions.ts` e `asset-deletion-protocol.ts`. O daemon de ativos deve executar com `ASSET_ONLY=true` e o token já usado para consultar sua configuração. Sem heartbeat recente do processador, a aplicação recusa pedidos reais.

Testes do protocolo: `pnpm exec tsx --test connector/test/asset-deletion.test.ts`. Validar pedidos e isolamento com transações revertidas no banco. Não usar um agente real como teste de exclusão sem confirmação específica do responsável.

Referência: [API de remoção de agentes](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remove-agents/restful-api-remove.html).
