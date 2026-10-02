# Worker Wazuh no mhomolog

O front continua no Vercel. O container no `mhomolog` executa somente o worker, usa a rede do host para alcançar os Indexers pela VPN e não publica portas. Ele busca as fontes ativas no Supabase a cada minuto e executa snapshots sequenciais no intervalo configurado. Ao cadastrar ou configurar uma fonte pelo site, ela entra no próximo ciclo de consulta; não é necessário criar arquivo por cliente nem atualizar o clone para cada fonte.

As credenciais do Indexer, o token de ingestão e, se necessário, o certificado CA são criptografados pelo Edge Function antes de serem guardados no banco. O worker autentica cada consulta com um token global. A chave de criptografia fica somente nos segredos do Supabase; o token do worker também fica no `.env` global do Docker.

## Ativação única no Supabase

Antes de usar o cadastro de fontes, aplique a migration e publique as duas Edge Functions:

```bash
supabase db push
supabase functions deploy admin-actions
supabase functions deploy wazuh-worker-config --no-verify-jwt
```

No painel do Supabase, em **Edge Functions → Secrets**, configure:

- `WAZUH_CONFIG_ENCRYPTION_KEY`: saída de `openssl rand -base64 32` (32 bytes codificados em Base64).
- `WAZUH_WORKER_CONFIG_TOKEN`: saída de `openssl rand -hex 32`.

O token da segunda variável também será colocado no `.env` do worker. Não altere a chave de criptografia depois de salvar credenciais, ou elas não poderão ser descriptografadas. Guarde cópias privadas dos dois valores.

## Preparar o host

Clone o repositório no `mhomolog`; o clone serve apenas para construir e atualizar a imagem Docker. O container não executa o site.

```bash
cd ~
git clone --depth 1 --branch master https://github.com/Piersec/PierVuln.git PierVuln
cd ~/PierVuln

sudo cp connector/mhomolog/worker.env.example connector/mhomolog/.env
sudo chmod 600 connector/mhomolog/.env
sudo nano connector/mhomolog/.env
```

Preencha `SUPABASE_URL` e `SUPABASE_PUBLISHABLE_KEY` com os valores públicos do projeto usados no Vercel. `WAZUH_WORKER_CONFIG_TOKEN` deve ser idêntico ao segredo configurado no Supabase. O padrão consulta novas configurações a cada 60 segundos e inicia cada fonte a cada 3600 segundos após concluir o snapshot anterior. Ajuste `SYNC_INTERVAL_SECONDS` se desejar outro intervalo; `INDEXER_PAGE_SIZE` fica limitado a 500 e a pausa entre páginas é 250 ms.

Confirme que o host alcança cada Indexer na porta 9200 pela VPN e alcança o Supabase por HTTPS. Cada Indexer deve usar uma URL HTTPS cujo certificado seja confiável. Se usar CA privada, cole o certificado PEM no cadastro da fonte pelo site.

## Iniciar e acompanhar

```bash
sudo bash connector/mhomolog/install-cron.sh
```

O script inicia o container e configura uma verificação de `origin/master` a cada cinco minutos. Quando o código do worker muda, reconstrói a imagem e recria o container; mudanças apenas no site ou na documentação não exigem rebuild. O Portainer mostra o container e seus logs.

```bash
sudo docker compose --project-directory connector/mhomolog --env-file connector/mhomolog/.env --file connector/mhomolog/docker-compose.yml logs --follow wazuh-connector
sudo tail -f /var/log/piervuln-mhomolog-sync.log
```

## Adicionar clientes e migrar fontes existentes

Depois da ativação única no Supabase, use **Administração → Adicionar fonte** no site. Informe URL HTTPS, usuário e senha do Indexer, empresa/topologia e certificado CA se necessário. A senha e o certificado não aparecem de volta na interface. Em até um minuto, o worker consulta a nova fonte e inicia o primeiro snapshot.

Para fontes já cadastradas, use **Configurar fonte existente** uma vez com o usuário e a senha do Indexer. Essa ação cria e armazena um novo token de ingestão; o token antigo deixa de funcionar. Depois disso, não há credenciais Wazuh necessárias no `.env` do host nem no Vercel para essa conexão.

## Pausar e retomar

Para interromper com segurança uma leitura em andamento, crie a pausa antes do próximo ciclo. O script envia `SIGTERM` ao worker e espera até três minutos. A pausa impede que o cron o inicie de novo.

```bash
sudo bash connector/mhomolog/pause-sync.sh
sudo bash connector/mhomolog/resume-sync.sh
```

O host atualiza o clone por fast-forward; para repositório privado, configure acesso Git somente de leitura para o usuário dono do clone. Uma reconstrução pode elevar CPU e uso de disco temporariamente. Se isso afetar o `mhomolog`, pause o worker e retome depois.
