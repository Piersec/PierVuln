# Primeira coleta de uma empresa

Ao salvar uma empresa ativa com os acessos completos da integração, o coletor recebe a configuração na próxima consulta, normalmente em até 60 segundos. Indexer e Manager precisam de seus respectivos acessos e certificados CA.

A primeira leitura tem prioridade sobre leituras periódicas pendentes. O coletor de vulnerabilidades permite até duas conexões simultâneas, com apenas uma leitura por conexão. Uma configuração alterada durante uma leitura fica pendente para uma nova leitura assim que aquela conexão terminar. Isso também vale para a inclusão de empresas em uma conexão compartilhada: o snapshot pertence à conexão, portanto duas leituras dela não são executadas ao mesmo tempo.

Depois de concluir a primeira leitura, cada conexão passa a respeitar seu `SYNC_INTERVAL_SECONDS`, contado a partir da conclusão. O coletor de ativos mantém seu próprio intervalo. Alterações somente nos acessos do Manager não antecipam uma leitura do Indexer.

Falhas seguem o intervalo de novas tentativas, com limite de 15 minutos. Corrigir a configuração libera uma nova tentativa na próxima consulta de configuração. Empresas inativas e acessos incompletos não iniciam coleta.
