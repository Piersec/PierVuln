# PierVuln

Painel web multiempresa para acompanhar vulnerabilidades publicadas pelo Wazuh. O navegador usa a chave publicável do Supabase e RLS; chaves privilegiadas ficam nas Edge Functions. O conector busca o índice atual do Wazuh e envia páginas por HTTPS.

## Estado do projeto

- Supabase `PierGV`, região `ca-central-1`, PostgreSQL 17.
- Migrações do projeto localizadas em `supabase/migrations/`; os números correspondem ao histórico do projeto remoto.
- Edge Functions implantadas: `wazuh-ingest` (autenticação própria do conector), `admin-actions` (JWT de usuário obrigatório) e `archive-runner` (segredo próprio de tarefa).
- As tabelas públicas têm RLS. O endpoint interno do Indexer não é legível pela chave do navegador. Os Advisors de segurança não apontam alertas após a migração `advisor_cleanup`.
- A conexão Wazuh compartilhada está cadastrada no Supabase. O conector é um processo separado e precisa ficar ativo em uma máquina que alcance o Indexer.

## Rodar o painel

Requer Node.js 24 e pnpm 11.

```powershell
pnpm install
Copy-Item .env.example .env.local
pnpm dev
```

O arquivo `.env.local` contém somente `NEXT_PUBLIC_SUPABASE_URL` e `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`. A chave publicável pode estar no bundle do navegador; não coloque `service_role`, senha de banco ou credenciais do Wazuh nesse arquivo.

Para implantação, defina as mesmas duas variáveis públicas no provedor Next.js. A URL permitida para callbacks do Supabase Auth deve incluir o endereço publicado do app.

## Preparar acesso interno e convites

1. No painel do Supabase, desative **Allow new users to sign up** em **Authentication → Settings**. Mantenha os redirects de Auth limitados aos endereços do app.
2. Crie o primeiro usuário interno em **Authentication → Users**.
3. No SQL Editor, associe esse usuário ao papel interno, substituindo pelo UUID do usuário:

   ```sql
   insert into private.internal_admins (user_id)
   values ('UUID-DO-USUARIO');
   ```

4. Defina o segredo `APP_BASE_URL` das Edge Functions para a URL HTTPS do app. A função de administração só envia convites depois que esse endereço estiver configurado.
5. Entre no app com o usuário interno. Use **Administração** para criar empresas, convidar usuários e cadastrar conexões.

O papel interno é distinto dos vínculos de cliente e só pode ser conferido pelo backend. Cada cliente recebe acesso por convite e precisa de uma associação ativa a uma empresa.

## Conectar um Wazuh

Na Administração, crie uma conexão com a URL HTTPS do Indexer. Uma conexão **dedicada** fica associada a uma empresa; uma conexão **compartilhada** começa sem empresa e só mostra os agentes/grupos vinculados manualmente.

Ao criar a conexão, o app mostra uma vez o UUID e o segredo de ingestão. Guarde o segredo em um cofre e no arquivo privado `connector/.env`; o banco conserva apenas o hash SHA-256. Não o envie por e-mail nem o inclua em commits.

Copie `connector/.env.example` para `connector/.env` e configure:

- `SUPABASE_URL` e a chave publicável;
- `WAZUH_CONNECTION_ID` e `WAZUH_INGEST_TOKEN` da conexão recém-criada;
- `WAZUH_INDEXER_URL`, usuário somente leitura e senha;
- o padrão de índice `wazuh-states-vulnerabilities-*`;
- o certificado da CA do Indexer em `connector/certs/`.

O coletor exige HTTPS e valida certificados por padrão. Para certificado privado, monte a CA em `connector/certs/indexer-ca.pem`; não desative a validação TLS. O coletor deve rodar em uma rede que alcance o Indexer. Essa rede só precisa de saída HTTPS para o Supabase.

Valide a versão, conectividade e permissão de leitura antes de iniciar o serviço:

```powershell
cd connector
Copy-Item .env.example .env
docker compose run --rm --entrypoint pnpm wazuh-connector connector:check
docker compose up -d --build
```

O coletor usa scroll para ler o snapshot inteiro, envia lotes idempotentes e roda por padrão a cada 300 segundos. Uma falha de página ou contagem diferente registra a leitura como parcial; apenas um snapshot completo pode confirmar ausência e resolver um caso. O prazo de cinco minutos começa quando o dado já está no Indexer; a atualização do feed do Wazuh tem seu próprio intervalo.

### Iniciar automaticamente no Windows

Se o Windows não tiver Docker, instale uma tarefa para iniciar o conector no logon e reiniciá-lo se o processo terminar. Ela usa `connector/.env` e `connector/certs/indexer-ca.pem` locais; mantenha o computador ligado, conectado à rede/VPN do Indexer e com o usuário conectado.

```powershell
Copy-Item connector/.env.example connector/.env # só se connector/.env ainda não existir
# Preencha connector/.env e coloque a CA em connector/certs/indexer-ca.pem.
powershell -NoProfile -ExecutionPolicy Bypass -File connector/install-local-task.ps1
```

Os registros ficam em `connector/logs/connector.log`. Para parar e remover a tarefa:

```powershell
Stop-ScheduledTask -TaskName "PierVuln Wazuh Connector"
Unregister-ScheduledTask -TaskName "PierVuln Wazuh Connector" -Confirm:$false
```

Para Wazuh compartilhado, associe IDs de agente ou grupos em **Vincular agente / grupo**. O vínculo direto do agente tem precedência. Se grupos de um mesmo agente apontarem para empresas diferentes e não houver vínculo direto, o achado fica sem cliente até a equipe corrigir o mapeamento.

## Arquivamento e retenção

O processo `archive-scheduler` é um contêiner separado do conector Wazuh e não recebe as credenciais do Indexer. Copie `connector/.env.archive.example` para `connector/.env.archive` e defina `ARCHIVE_JOB_TOKEN` com um segredo aleatório. Configure o mesmo valor como segredo da Edge Function `archive-runner`.

Arquivos concluídos são compactados, enviados ao bucket privado, lidos de volta e comparados pelo SHA-256 antes da remoção do banco. A rotina arquiva achados resolvidos há pelo menos 90 dias, mantém o arquivo por um ano e só então o expira. Achados ativos não entram no processo. O manifesto guarda contagem, período, IDs, checksum e estado da remoção.

O serviço diário é iniciado junto com o conector:

```powershell
docker compose up -d --build archive-scheduler
```

Configure `ARCHIVE_JOB_TOKEN` e `APP_BASE_URL` em **Supabase → Edge Functions → Secrets** antes de habilitar convites e retenção. Não copie uma chave `service_role` para nenhum dos contêineres.

## CSV de referência

O CSV enviado tem 10.000 registros e 8 colunas (`agent.name`, sistema operacional, pacote, CVE, descrição, severidade, score e referência). Ele não contém o `_id` estável do Indexer, `agent.id`, versão completa do pacote, status atual ou horário de leitura, e há registros com formato irregular. Por isso, o CSV não é carregado como fonte operacional; o coletor consulta o Indexer para identidade e reconciliação confiáveis.

## Testes e verificação

```powershell
pnpm test:connector
pnpm typecheck
pnpm build
```

Os cenários transacionais de RLS e sincronização estão em `supabase/tests/`. Rode-os em um Supabase local limpo com Docker ativo:

```powershell
supabase start
supabase test db
```

As mesmas verificações de isolamento de dois clientes, leitura interna, notas privadas, reexecução de página, paginação incompleta, resolução em snapshot vazio e reabertura também foram executadas no projeto `PierGV` dentro de transações com rollback.

## Referências

- [Consulta de vulnerabilidades pela API do Indexer Wazuh](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html)
- [API do Indexer Wazuh: pesquisa e scroll](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html)
- [Segurança dos dados no Supabase](https://supabase.com/docs/guides/database/secure-data)
- [Workflow local de migrações Supabase](https://supabase.com/docs/guides/local-development/cli-workflows)
- [Configuração da detecção de vulnerabilidades Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/configuring-scans.html)
