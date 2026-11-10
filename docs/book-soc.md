# Book SOC

Área `/book-soc` do PierVuln, só para a equipe interna. Consulta o Wazuh direto, pelo servidor, com a conta somente leitura de cada cliente. Não usa banco nem n8n: os resultados ficam só em memória, por 60 segundos, e nenhum evento bruto sai do servidor.

O login do PierVuln serve apenas para saber quem é interno (`current_user_context`). O isolamento entre clientes vem da conta de cada um no Indexer, não do aplicativo.

## Páginas

- `/book-soc`: visão executiva do estado atual das vulnerabilidades (severidade, idade, mês da detecção, principais CVEs).
- `/book-soc/alertas`: painel de alertas com as regras do Book (níveis 12 a 16 por padrão, decoder, regras incluídas e excluídas, Domain Admins).

## Variáveis de ambiente (somente servidor)

`BOOK_SOC_CLIENTS` lista as chaves dos clientes, separadas por vírgula. Para cada chave `X`:

| Variável | Obrigatória | Conteúdo |
|---|---|---|
| `BOOK_SOC_X_NAME` | não | Nome exibido |
| `BOOK_SOC_X_URL` | sim | Endereço HTTPS do Indexer do cliente |
| `BOOK_SOC_X_USER` | sim | Usuário somente leitura |
| `BOOK_SOC_X_PASSWORD_B64` | sim | Senha em base64 |
| `BOOK_SOC_X_INDEX` | sim | Índice de vulnerabilidades |
| `BOOK_SOC_X_ALERTS_INDEX` | não | Índice de alertas; sem ele, a aba Alertas fica indisponível para o cliente |
| `BOOK_SOC_X_EXCLUDED_GROUPS` | não | Grupos de regra fora da análise de alertas; padrão `vulnerability-detector` |

A senha vai em base64 para não depender de como cada ferramenta trata caracteres como `$` e `#`. Para gerar:

```bash
node -e "console.log(Buffer.from(process.argv[1]).toString('base64'))" 'senha'
```

Chaves usam letras maiúsculas, números e `_`; `JEAN_PIAGET` vira o identificador `jean-piaget`. Entradas incompletas, sem HTTPS ou com nome de índice inválido são ignoradas.

## Rede e certificados

O servidor que roda o Next precisa alcançar o Indexer de cada cliente. Os Indexers usam certificados de CA privada, então o Node precisa confiar nelas. Reúna os certificados públicos num único arquivo `.pem` e inicie o processo com:

```powershell
$env:NODE_EXTRA_CA_CERTS = "$PWD\connector\certs\book-soc-ca-bundle.pem"
npm run dev -- -p 3100
```

`NODE_EXTRA_CA_CERTS` só é lido quando o processo inicia. Se aparecer `UNABLE_TO_VERIFY_LEAF_SIGNATURE` no log (`[book-soc] consulta ao Indexer falhou`), o processo está sem a CA.

Em hospedagem na nuvem (por exemplo, Vercel), os Indexers internos (`192.168.x.x`) não são alcançáveis e a CA privada não é confiada sem configuração extra. Sem isso, as páginas carregam, mas a consulta falha.

## Limites conhecidos

- A idade usa `vulnerability.detected_at`, a data registrada no índice. Se o Wazuh reindexa, ela pode refletir a varredura mais recente e não a primeira detecção.
- O painel de alertas lista as 20 regras com mais ocorrências e resume o restante em "Outras regras". O período vai até 93 dias.
- As colunas "Tratadas" e "Situação SOC" do Book original não existem aqui: dependem de estado de revisão que o Book guardava localmente.
