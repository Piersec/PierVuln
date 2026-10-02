# Worker Wazuh no mhomolog

O front-end continua no Vercel. Este perfil inicia somente o worker Wazuh em um container Docker contínuo; ele não inicia Next.js nem abre portas. O container usa a rede do host para alcançar os Indexers pela rede/VPN já disponível no `mhomolog`, tem limite de memória de 512 MB e reinicia automaticamente após reboot do host.

O worker lê uma pasta por conexão, executa um snapshot por vez e espera o intervalo configurado depois de concluir o ciclo. Se um Indexer falhar, os demais ainda são tentados. A sincronização envia cada página ao Supabase e só encerra achados ausentes depois de um snapshot completo.

## Vercel e variáveis do worker

Deixe no Vercel as variáveis usadas pelo front:

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`

O worker recebe os mesmos valores no Linux com os nomes `SUPABASE_URL` e `SUPABASE_PUBLISHABLE_KEY`. O conector chama a Edge Function `wazuh-ingest`, que valida o token próprio de cada conexão; não precisa da chave `service_role` no container.

Mova para o host as variáveis Wazuh que hoje estão no Vercel. `WAZUH_CONNECTION_ID`, `WAZUH_INGEST_TOKEN`, `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD`, `INDEXER_INDEX_PATTERN`, `INDEXER_PAGE_SIZE` e `INDEXER_PAGE_DELAY_MS` ficam em um `.env` por Indexer. `WAZUH_INDEXER_CA_FILE` é substituída por um bundle PEM com as CAs de todos os Indexers, montado no container para validação TLS.

Depois de confirmar a sincronização no Docker, as variáveis Wazuh podem ser removidas do Vercel se não forem usadas por outra função. Nunca copie senhas ou tokens para o código, Git ou chat.

## Preparar o host

Use um clone do repositório apenas como fonte para construir a imagem. O processo que roda no container é o conector, não o site.

```bash
cd ~
git clone --depth 1 --branch master https://github.com/Piersec/PierVuln.git PierVuln
cd ~/PierVuln

sudo mkdir -p /opt/piervuln/config/connections
sudo cp connector/mhomolog/worker.env.example connector/mhomolog/.env
sudo chmod 600 connector/mhomolog/.env
sudo nano connector/mhomolog/.env
```

No `.env` global, preencha `SUPABASE_URL` com o valor de `NEXT_PUBLIC_SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` com o valor de `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` e ajuste `SYNC_INTERVAL_SECONDS`. O padrão é 3600 segundos após cada ciclo completo. Para muitos clientes ou snapshots grandes, meça a primeira carga antes de reduzir o intervalo.

Para cada Indexer, crie uma pasta e um `.env` privado. `WAZUH_CONNECTION_ID` e `WAZUH_INGEST_TOKEN` precisam corresponder a uma conexão ativa cadastrada no PierVuln.

```bash
sudo mkdir -p /opt/piervuln/config/connections/cliente-a
sudo cp connector/mhomolog/connection.env.example /opt/piervuln/config/connections/cliente-a/.env
sudo chmod 700 /opt/piervuln/config/connections/cliente-a
sudo chmod 600 /opt/piervuln/config/connections/cliente-a/.env
sudo nano /opt/piervuln/config/connections/cliente-a/.env
```

Repita para `cliente-b`, `cliente-c` e assim por diante. O nome da pasta aparece nos logs do Portainer. As conexões compartilham a VPN; o host precisa ter rota até cada endereço de Indexer.

Junte em `/opt/piervuln/config/indexers-ca-bundle.pem` os certificados CA PEM necessários para validar todos os Indexers. Não desative a verificação TLS. Os endereços HTTPS devem corresponder aos nomes/IPs cobertos pelos certificados.

Confirme que o usuário Linux tem Docker Compose e que o host alcança cada Indexer na porta 9200 e o Supabase por HTTPS. Este conector consulta o Indexer; ele não usa a API do Manager na porta 55000.

## Iniciar e acompanhar

A instalação constrói a imagem, inicia o container e cria um cron que consulta `origin/master` a cada cinco minutos. Quando encontra commit novo que altera o worker, reconstrói e recria o container; commits só de documentação/front não fazem build. O Portainer mostra o container para acompanhar estado e logs.

```bash
sudo bash connector/mhomolog/install-cron.sh
```

Veja os logs do container `wazuh-connector` no Portainer ou no host:

```bash
sudo docker compose --project-directory connector/mhomolog --env-file connector/mhomolog/.env --file connector/mhomolog/docker-compose.yml logs --follow wazuh-connector
sudo tail -f /var/log/piervuln-mhomolog-sync.log
```

O primeiro ciclo começa assim que o container inicia. A primeira carga completa pode demorar. Observe o desempenho do host e o espaço no Supabase antes de sincronizar centenas de milhares de achados.

## Pausar e retomar

Para interromper com segurança durante uma carga, o script envia `SIGTERM` ao worker e espera até três minutos. A pausa impede que o cron o inicie de novo.

```bash
sudo bash connector/mhomolog/pause-sync.sh
```

Para retomar, o worker volta imediatamente e executa um ciclo:

```bash
sudo bash connector/mhomolog/resume-sync.sh
```

## Como o código acompanha commits

O cron do host faz `git fetch` da branch `master`. Se avançar, atualiza o clone por fast-forward, reconstrói a imagem quando houver mudança no conector/dependências e recria só o worker. A autenticação do Git precisa estar configurada para o usuário dono do clone; para repositório privado, use uma chave de deploy somente leitura. O Vercel continua atualizando o front pelo fluxo que já usa.

Uma nova imagem pode elevar CPU e disco durante o build. O build ocorre somente quando a revisão do worker muda; use `pause-sync.sh` antes de uma atualização que esteja afetando o host.
