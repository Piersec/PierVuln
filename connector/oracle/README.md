# Implantação Oracle Cloud ARM

Este perfil transforma o conector em um job Docker de execução única. A VPN fica no host Ubuntu, e cada conexão Wazuh usa um arquivo `.env` separado. As conexões são processadas em sequência pelo mesmo host e pela mesma VPN.

## Requisitos antes da VM

- Autorização escrita do administrador da VPN e do Wazuh.
- Um perfil VPN de cliente dedicado, limitado aos IPs dos Indexers necessários.
- Uma conta somente leitura no Wazuh Indexer para cada endpoint.
- Uma conexão Wazuh cadastrada no painel PierVuln para cada Indexer, com o respectivo UUID e token de ingestão.

## Criar e proteger a VM

1. Na Oracle Cloud, crie uma VM Ampere A1.Flex com Ubuntu 24.04 aarch64, 1 OCPU e 6 GB de RAM. Mantenha o boot volume no padrão de aproximadamente 50 GB.
2. Restrinja a entrada na VCN e no host à porta 22, com origem no IP público do administrador. Não abra as portas 9200 ou 55000 para a internet.
3. Converta a conta para Pay As You Go e configure o alerta de orçamento de US$ 1. O alerta avisa sobre gastos; ele não encerra recursos automaticamente.
4. Mantenha a VM dentro de 1.500 OCPU-h e 9.000 GB-h por mês. Uma VM contínua com 1 OCPU e 6 GB consome aproximadamente 744 OCPU-h e 4.464 GB-h em um mês de 31 dias, sem outras instâncias ARM no mesmo limite.

## Instalar a VPN no host

Instale o cliente OpenVPN e coloque o perfil fornecido pelo administrador em `/etc/openvpn/client/wazuh.conf`. No perfil, configure:

```text
pull-filter ignore "redirect-gateway"
auth-user-pass /etc/openvpn/client/wazuh.auth
```

Crie `/etc/openvpn/client/wazuh.auth` com o usuário na primeira linha e a senha na segunda. Restrinja o arquivo e ative a unidade:

```bash
sudo apt update && sudo apt install -y openvpn curl
sudo chown root:root /etc/openvpn/client/wazuh.auth /etc/openvpn/client/wazuh.conf
sudo chmod 600 /etc/openvpn/client/wazuh.auth /etc/openvpn/client/wazuh.conf
sudo systemctl enable --now openvpn-client@wazuh
sudo systemctl status openvpn-client@wazuh --no-pager
```

Confirme a rota VPN para cada endereço de Indexer. A porta 55000 é a API do Wazuh Manager; o conector lê vulnerabilidades no Indexer pela porta 9200. Portanto, teste a rota e o TLS para ambos quando ambos forem necessários. O conector usa autenticação Basic HTTPS diretamente no Indexer, não o JWT da API do Manager. Para testar apenas a rota/TLS da API do Manager, um HTTP 401 sem credenciais já confirma que o host respondeu:

```bash
curl --silent --show-error --output /dev/null --write-out 'HTTP %{http_code}\n' \
  --cacert /caminho/da/ca-do-wazuh.pem https://<IP-PRIVADO-DO-MANAGER>:55000/
```

O conector requer busca e scroll somente leitura no padrão de índices de
vulnerabilidade: `indices:data/read/search*`, `indices:data/read/scroll` e
`indices:data/read/scroll/clear`. O Indexer exige a permissão de limpeza tanto
no escopo de cluster quanto de índice. A busca inicial solicita a contagem exata;
as páginas seguintes avançam o contexto scroll e não são repetidas automaticamente
se a resposta se perder.

## Instalar Docker e preparar conexões

Instale Docker Engine e o plugin Compose pelos repositórios oficiais da Docker. Clone este repositório em `/opt/piervuln` e entre na VM por SSH. O arquivo `.dockerignore` impede que `.env`, certificados, logs e configurações de conexão entrem no contexto de build.

Coloque as CAs dos Indexers em `connector/certs/`. Para cada Indexer, crie um diretório distinto e um `.env` privado:

```bash
sudo mkdir -p connector/oracle/connections/cliente-a
sudo cp connector/.env.example connector/oracle/connections/cliente-a/.env
sudo chmod 700 connector/oracle/connections/cliente-a
sudo chmod 600 connector/oracle/connections/cliente-a/.env
```

Preencha cada `.env` com os dados da conexão PierVuln, usuário e senha somente leitura do Indexer, URL HTTPS do IP privado na porta 9200, padrão `wazuh-states-vulnerabilities-*`, página de 500 itens e `INDEXER_PAGE_DELAY_MS=250`. O nome de host da URL precisa corresponder ao SAN do certificado; usando um IP, o certificado deve conter esse IP. Defina `WAZUH_INDEXER_CA_FILE` para o caminho da CA dentro do container, por exemplo `/etc/wazuh/certs/indexer-cliente-a.pem`; guarde o arquivo correspondente em `connector/certs/`.

Repita para cada Indexer e use credenciais distintas. Não coloque segredos no `.env` compartilhado do painel nem no Git.

## Validar e ativar o job

Antes de instalar o cron, valide cada configuração manualmente. A imagem é construída para ARM64 e cada job é limitado a 512 MB:

```bash
env_file="$PWD/connector/oracle/connections/cliente-a/.env"
CONNECTOR_ENV_FILE="$env_file" docker compose \
  --project-directory "$PWD/connector/oracle" \
  --env-file "$env_file" \
  --file "$PWD/connector/oracle/docker-compose.yml" \
  run --build --rm --no-deps --entrypoint pnpm wazuh-connector connector:check
```

Depois de validar todas as conexões, instale o cron como root:

```bash
sudo bash connector/oracle/install-cron.sh
```

O cron roda de hora em hora por padrão, adequado para snapshots completos maiores. `flock -n` impede sobreposição; cada execução processa os arquivos em sequência e tenta as próximas conexões mesmo se uma falhar. Ajuste o intervalo ao tempo medido e à latência desejada, por exemplo: `sudo env SYNC_EVERY_MINUTES=30 bash connector/oracle/install-cron.sh`. O serviço OpenVPN precisa estar ativo. O log fica em `/var/log/piervuln-wazuh-sync.log`.

Para iniciar uma primeira carga manual fora do horário de pico, execute `sudo bash connector/oracle/run-sync.sh`.

O conector percorre snapshots completos com scroll e ordenação `_doc`, em páginas
de até 500 documentos, com intervalo de 250 ms. Ele conserva o `_id` do Indexer;
se um ID aparecer mais de uma vez, a execução falha sem publicar. O contexto
scroll usa keep-alive de 2 minutos, é fechado ao final e expira no Indexer se a
conexão cair. Cada execução tem limite de 30 minutos.

O Wazuh documenta `wazuh-states-vulnerabilities-*` como índice de estado atual.
Por isso, a leitura completa é necessária para que o PierVuln detecte documentos
que deixaram de aparecer e marque esses achados como resolvidos; um incremental
baseado apenas nos documentos ainda presentes não detectaria ausências. O
OpenSearch recomenda `_doc` para percorrer todos os documentos sem cálculo de
relevância ([scroll](https://docs.opensearch.org/latest/api-reference/search-apis/scroll/)).

Cada página é guardada no staging privado do Supabase. O protocolo 2 só publica
os achados depois de validar todos os documentos; uma falha anterior mantém a
última versão publicada. Antes de atualizar o coletor, instale a migração e a
Edge Function que anunciam o protocolo 2. Após a atualização, a primeira leitura
completa reconcilia o inventário legado.
O início da execução reaproveita o mesmo ID de requisição em tentativas de rede,
evitando criar execuções órfãs quando uma resposta do Supabase se perde.

O volume de 300 mil documentos leva cerca de 600 chamadas de página por conexão, além do tempo de processamento e envio ao Supabase. Execute a primeira carga fora do pico e meça o tempo de uma sincronização completa antes de escolher o intervalo do cron. Meça o tamanho ocupado por 10 mil achados no Supabase antes de importar 300 mil, pois o limite de armazenamento do plano gratuito pode ser atingido antes do limite da VM. A documentação Wazuh descreve esses índices como estado atual ([índices Wazuh](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)).
