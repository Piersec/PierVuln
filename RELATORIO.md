# RELATORIO — Visão geral do SOC

## Escopo
- Modo: redesign parcial de uma página.
- Tela entregue: `/soc`.
- A página segue a composição aprovada: risco, mapa, países, incidentes, tendência e firewalls.

## Referências usadas
- Captura fornecida pelo usuário: `00-home-widgets.jpg`.
- Tokens e hierarquia existentes em `DESIGN.md`.
- Painéis, navegação e mapa já existentes no projeto.

## Componentes (origem)
- `Panel`, lista de severidade e estados de carregamento: `src/components/soc-module-pages.tsx`.
- Mapa Leaflet reutilizado de `src/components/soc-demo-threat-map.tsx`; modo compacto usado na visão geral.
- Gráfico temporal com Recharts, já usado pelo projeto.
- Botões de período com HeroUI; sem dependência nova.

## Bibliotecas
- Recharts: gráfico de volume diário de incidentes.
- Leaflet: mapa interativo de demonstração existente.
- HeroUI: controles de período existentes no ecossistema visual do produto.

## Checklist de leis de UX
| Tela | Lei | Passou/Falhou | Correção |
|---|---|---|---|
| Visão geral do SOC | Hick e hierarquia | Passou | Três períodos e ação de atualizar ficam agrupados no cabeçalho. |
| Visão geral do SOC | Fitts | Passou | Botões de período e links principais têm altura mínima de 44 px. |
| Visão geral do SOC | Proximidade e agrupamento | Passou | Conteúdo foi distribuído em seis cartões na ordem aprovada. |
| Visão geral do SOC | Doherty e estados | Passou | Skeleton, atualização preservando os dados, erro e vazio estão definidos. |
| Visão geral do SOC | Contraste | Passou | Texto auxiliar `#d4d7da` sobre cartão `#191a1c`: 12,05:1. Link do mapa `#71d8f0` sobre cartão: 10,60:1. |
| Visão geral do SOC | Responsividade | Passou | Grade empilha os cartões em uma coluna até 650 px. |

## Itens proibidos
- Nenhum item visual encontrado nas duas rodadas.
- Movimento do skeleton respeita `prefers-reduced-motion`.
- Severidade no resumo de incidentes usa rótulo legível; a cor aparece somente no indicador.

## Verificação visual
- Rodadas feitas: 2, com prévia local e dados fictícios, usando CUA.
- Viewports revisados: 1440 × 900 e 390 × 844.
- Primeira rodada apontou rótulos de severidade com contraste inadequado, barra nativa fora da paleta e atribuição clara no mapa. Esses pontos foram corrigidos e revistos na segunda rodada.
- Capturas: a revisão foi exibida no navegador, mas não foi possível exportar os arquivos para `.design/screens/`. Nenhum arquivo de captura é incluído.
- A rota temporária de prévia foi removida; não será publicada.

## Dados e limites conhecidos
- Mapa e países usam coordenadas simuladas da demonstração. Para dados reais, o painel informa que geolocalização ainda não está disponível.
- O RPC atual limita as fontes a cinco no total. O cartão de firewalls mostra as fontes classificadas como firewall dentro desse conjunto, não um ranking global exato.
- A tendência usa data de criação dos incidentes. O banco ainda não identifica autoria por IA ou pessoa.
- A consulta dos incidentes lê até 1.000 linhas; acima disso, mostra uma mensagem para reduzir o período em vez de desenhar uma série incompleta.

## Validação técnica
- `npm run typecheck`: aprovado.
- `git diff --check`: aprovado.
- `npm run build`: aprovado; a rota `/soc` foi gerada como página dinâmica.
- Testes automatizados: não executados.

## Pendências
- Salvar as capturas visuais em `.design/screens/` continua pendente; a captura pelo navegador foi bloqueada pela política de segurança da ferramenta.
- Ranking exato de firewalls depende de ampliar a resposta do RPC.
- Geolocalização real depende de dados de localização na origem dos alertas.
