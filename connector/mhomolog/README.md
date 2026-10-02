# Execução no mhomolog

Este perfil roda o conector como job Docker de execução única, usa a rede do host para alcançar os Indexers internos e limita o container a 512 MB. Ele não inicia nem altera uma VPN. Use-o quando a VM já tiver rota de rede autorizada até os Indexers.

## Preparar conexões

Crie uma pasta e um `.env` privado para cada conexão Wazuh cadastrada no PierVuln. O host processa os arquivos em sequência:

```bash
sudo mkdir -p connector/mhomolog/connections/cliente-a
sudo cp connector/.env.example connector/mhomolog/connections/cliente-a/.env
sudo chmod 700 connector/mhomolog/connections/cliente-a
sudo chmod 600 connector/mhomolog/connections/cliente-a/.env
sudo nano connector/mhomolog/connections/cliente-a/.env
```

Preencha o UUID e o token de ingestão dessa conexão, além da URL HTTPS privada do Indexer, credencial de leitura e caminho da CA correspondente. Não reutilize credenciais entre Indexers e não coloque os arquivos `.env` ou certificados privados no Git. O Indexer deve permitir leitura dos índices de vulnerabilidades, criação e remoção de PIT e pesquisa. Não desative a validação TLS.

Coloque as CAs públicas dos certificados dos Indexers em `connector/certs/`; no `.env`, use o caminho dentro do container, por exemplo `/etc/wazuh/certs/indexer-cliente-a.pem`. A URL precisa corresponder ao nome ou IP presente no certificado.

Antes de sincronizar, confirme a rota de rede e HTTPS do host até cada Indexer na porta 9200 e a saída HTTPS até o Supabase. O conector usa o Indexer API diretamente; a porta 55000 é a API do Wazuh Manager e não é usada por este job.

## Validar e fazer a primeira carga

Execute a primeira carga fora do pico. Valide a conexão sem gravar dados:

```bash
env_file="$PWD/connector/mhomolog/connections/cliente-a/.env"
CONNECTOR_ENV_FILE="$env_file" docker compose \
  --project-directory "$PWD/connector/mhomolog" \
  --env-file "$env_file" \
  --file "$PWD/connector/mhomolog/docker-compose.yml" \
  run --build --rm --no-deps --entrypoint pnpm wazuh-connector connector:check
```

Depois da validação, rode a primeira carga manual:

```bash
sudo bash connector/mhomolog/run-sync.sh
```

O job lê páginas de até 500 documentos com PIT e `search_after`, aguarda 250 ms entre páginas e grava no Supabase antes de descartar cada página. Cada Indexer tem seu próprio UUID e token de ingestão. O limite de 512 MB se aplica a cada execução.

Observe o consumo no Windows host e na VM durante a primeira carga. Para pausar com segurança, marque a pausa, interrompa os containers ativos e deixe o sync atual registrar uma execução parcial:

```bash
sudo bash connector/mhomolog/pause-sync.sh
```

Para retomar, remova a pausa; a próxima execução ocorrerá no próximo horário agendado:

```bash
sudo bash connector/mhomolog/resume-sync.sh
```

## Agendar

Só instale o cron depois de validar e concluir a primeira carga. O padrão é uma vez por hora; `flock` impede sobreposição. As conexões são sequenciais e as próximas ainda serão tentadas caso uma falhe. O log, com permissão 600 e rotação semanal, fica em `/var/log/piervuln-mhomolog-sync.log`.

```bash
sudo bash connector/mhomolog/install-cron.sh
```

É possível usar intervalos que dividam uma hora, por exemplo 30 minutos:

```bash
sudo env SYNC_EVERY_MINUTES=30 bash connector/mhomolog/install-cron.sh
```

Uma carga com 300 mil documentos faz cerca de 600 chamadas de página por Indexer. Meça o tempo da primeira sincronização completa antes de encurtar o agendamento e meça o espaço no Supabase com 10 mil achados antes de importar centenas de milhares.
