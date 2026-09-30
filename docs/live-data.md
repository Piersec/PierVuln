# Atualização dos dados

O painel de vulnerabilidades e o Book recebem eventos do Supabase Realtime,
respeitando as permissões existentes de cada usuário. Os eventos de sincronização,
histórico e comentários provocam uma nova consulta; as linhas retornadas continuam
sujeitas às políticas de acesso por empresa. As atualizações são agrupadas por um
segundo e aguardam a consulta em andamento.

Uma consulta automática a cada 30 segundos recupera eventos perdidos. Voltar à aba,
recuperar a conexão ou reconectar o canal também provoca uma consulta. A idade da
última leitura completa é recalculada a cada 15 segundos.

O Wazuh Indexer é consultado pelo conector em ciclos de 60 segundos, com páginas
de 500 documentos. Se um snapshot demorar mais de um minuto, o seguinte começa
quando ele termina; nunca existem dois snapshots simultâneos nesse processo.
O tempo real do painel começa quando os dados chegam ao Supabase. A coleta do
Indexer continua sendo periódica e depende da disponibilidade da rede e do Wazuh.

O horário exibido corresponde à conclusão de um snapshot completo, nunca à mera
abertura do painel. Falhas antes da primeira página também são registradas em
`sync_runs`. Leituras parciais não confirmam resolução de vulnerabilidades.

Para instalações existentes, ajustar `SYNC_INTERVAL_SECONDS=60` e
`INDEXER_PAGE_SIZE=500` no `.env` privado do conector e reiniciar seu serviço.
Aplicar a migração `operational_realtime` para publicar as três tabelas operacionais.
