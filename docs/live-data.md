# Atualização dos dados

O painel de vulnerabilidades e o Book recebem eventos do Supabase Realtime,
respeitando as permissões existentes de cada usuário. Os eventos de sincronização,
histórico e comentários provocam uma nova consulta; as linhas retornadas continuam
sujeitas às políticas de acesso por empresa. As atualizações são agrupadas por um
segundo e aguardam a consulta em andamento.

Uma consulta automática a cada 30 segundos recupera eventos perdidos. Voltar à aba,
recuperar a conexão ou reconectar o canal também provoca uma consulta. A idade da
última leitura completa é recalculada a cada 15 segundos.

Os cards do cenário e os totais do Kanban acompanham o mesmo sinal de atualização
da lista. Os botões Atualizar e Atualizar cenário também consultam esses dados.
As consultas em segundo plano mantêm o quadro montado e preservam os filtros de
cada coluna. Se uma leitura falhar, os últimos dados válidos continuam visíveis
até a próxima tentativa automática.

O KPI principal e o Book contam todos os documentos ativos do inventário,
independentemente do estado de workflow. Casos continuam sendo a unidade de
tratamento e podem ter estado, comentários e histórico próprios.

O conector percorre o Indexer por scroll em páginas de até 500 documentos. Ele
preserva o `_id` original, exige uma contagem inicial exata e interrompe a leitura
se detectar IDs repetidos, páginas incompletas, shards com falha ou timeout. Uma
execução leva no máximo 30 minutos. Se ocorrer uma falha, o staging é descartado e
os achados ativos já publicados permanecem visíveis.

As páginas recebidas ficam em staging privado. A conclusão valida contagem,
sequência e identidade e publica achados, casos e resoluções na mesma transação.
O início também usa um ID de requisição para que uma resposta HTTP perdida não
deixe uma execução órfã nem impeça a repetição segura do pedido.
O painel compara o marcador da última publicação antes e depois das consultas e
repete a leitura se uma publicação ocorrer no meio. Componentes separados ainda
podem atualizar em instantes distintos.

A leitura completa é considerada atual por 1 hora, recebe aviso de atualização
entre 1 e 2 horas e fica atrasada após 2 horas. Realtime acelera a atualização do
painel depois que uma publicação chega ao Supabase; não substitui a coleta periódica
nem prova que o Indexer foi consultado.

O horário exibido corresponde à conclusão de um snapshot completo, nunca à mera
abertura do painel. Falhas também são registradas em `sync_runs`. Leituras parciais
não confirmam resolução de vulnerabilidades.

Para instalações existentes, configure `SYNC_INTERVAL_SECONDS` e
`INDEXER_PAGE_SIZE=500` no `.env` privado do conector e reinicie o serviço. A
publicação atômica exige a migração de protocolo 2, a Edge Function `wazuh-ingest`
e a versão correspondente do conector. Não atualize somente o conector antes que
o endpoint confirme esse protocolo.
