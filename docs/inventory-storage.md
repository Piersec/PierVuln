# Armazenamento e retenção do inventário

## Conteúdo e presença

Descrições e referências idênticas são armazenadas em `finding_content`, com SHA-256 do JSON canônico das duas colunas. Variantes permanecem separadas. Os campos calculados `finding_description`, `finding_references` e `finding_last_seen` conservam o formato consumido pelo site durante a conversão em lotes.

A publicação valida as páginas e os documentos antes de montar uma tabela temporária de IDs. Somente achados novos ou com conteúdo alterado são gravados. A confirmação de ausência usa os IDs desse conjunto completo, dentro da mesma transação de publicação. Uma execução incompleta não substitui o inventário publicado.

Para achados ativos, a última leitura é obtida da execução publicada da conexão. Ao confirmar a ausência, essa data é preservada no achado resolvido. `last_seen_sync_run_id` passa a representar a última alteração gravada, não a presença mais recente; consumidores devem usar `finding_last_seen`.

## Conversão e manutenção

- `piervuln-normalize-content`: até 10 registros a cada dois minutos, com limite de 25 segundos por transação e bloqueios limitados a um segundo. O lote foi reduzido após os limites iniciais excederem o tempo seguro no banco ativo. A rotina se remove do agendamento quando não há mais registros pendentes e cede enquanto houver publicação pendente.
- `piervuln-refresh-overview-snapshots`: recalcula uma empresa por vez em segundo plano quando a publicação muda. O painel lê o último resumo persistido enquanto uma nova versão é preparada.
- `piervuln-inventory-maintenance`: diariamente às 05:15 UTC. Fecha coletas abandonadas há duas horas sem publicação pendente, limpa temporários encerrados, remove filas e registros de execução sem referências após 30 dias e elimina conteúdo sem achados associados.
- Registros de execução ainda referenciados pelos achados ou pelo snapshot publicado são preservados.
- O último snapshot do front permanece disponível durante as tarefas. A conversão não altera empresa, severidade, primeira detecção, estado ou fluxo do caso.

## Arquivos de casos corrigidos

A rotina aceita somente achados corrigidos há pelo menos 90 dias e casos associados encerrados há pelo menos 90 dias. Antes da remoção, o arquivo compactado é enviado ao Storage privado, baixado novamente e conferido por SHA-256.

Um fingerprint adicional inclui os achados, casos, comentários e eventos em uma leitura consistente. A finalização bloqueia os registros associados e confere esse fingerprint. Se o conteúdo mudou, nada é removido do banco. Um manifesto cuja fonte mudou precisa de revisão/reprocessamento; a rotina preserva o arquivo e os dados para investigação.

Os arquivos podem ser baixados pela equipe interna na seção de arquivos existente. O prazo de expiração de um ano já definido no projeto continua aplicado aos arquivos finalizados. Não existe exclusão de achados ativos para cumprir uma meta de espaço.

O agendador aceita `ARCHIVE_JOB_TOKEN` para a operação global, ou as credenciais existentes da coleta (`WAZUH_CONNECTION_ID` e `WAZUH_INGEST_TOKEN`) para operar somente sobre sua conexão. A função valida o hash da credencial e restringe descoberta, retomada e expiração à conexão autenticada. Não se usa a chave administrativa no agendador.

Na instalação atual há um container de arquivamento com execução horária, reinício automático, sistema de arquivos somente para leitura e credenciais mantidas no Docker. O arquivo de ambiente temporário usado na instalação é removido imediatamente.

## Capacidade

Deduplicação e arquivamento limitam repetição e acúmulo de histórico; novos hosts e achados ativos continuam consumindo espaço. A conversão produz gravações uma única vez e pode aumentar temporariamente o tamanho físico. Não foi executado `VACUUM FULL`: ele bloquearia as tabelas. O espaço liberado pode ser reutilizado internamente antes de aparecer como redução no disco provisionado.

Ao acompanhar o consumo, separar tamanho físico do banco, índices, temporários e WAL gerado. WAL acumulado nas estatísticas de consultas não representa espaço atualmente ocupado.
