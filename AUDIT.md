# Auditoria e redesign do PierVuln

## Escopo e método

Foram revisadas as rotas `/`, `/book` e `/login` em desktop (1440 × 1000) e mobile (390 × 844), primeiro na versão publicada para observar o produto com dados reais e depois na prévia local para conferir o redesign sem gravar alterações no Supabase. A auditoria foi visual e funcional, com snapshots de acessibilidade do navegador e medições de largura da página. Não foram executadas suítes de teste.

As capturas do Chrome foram inspecionadas durante o trabalho, mas não puderam ser exportadas para arquivos locais: a API de navegador disponível retorna imagens para inspeção e não oferece caminho de gravação. Portanto, este relatório registra o método e os achados; não afirma que existam arquivos de screenshot anexados.

## Achados antes do redesign

| Área | Evidência | Ajuste aplicado |
| --- | --- | --- |
| Painel `/` · desktop | A tabela mostrava 50 casos por página; os cartões de resumo davam o mesmo peso visual a métricas com escopos diferentes. | O resumo agora destaca o total da consulta e identifica que severidade, andamento e fontes contam o resultado inteiro; a tabela continua paginada. |
| Painel `/` · mobile | A navegação lateral não oferecia acesso evidente aos destinos do produto; as linhas da tabela exigiam rolagem horizontal e os alvos eram pequenos. | A navegação e o acesso interno ficam visíveis no topo; casos viram cartões empilhados com rótulos, e os botões, seletores e paginação aumentam de altura. |
| Book `/book` · desktop | A distribuição por severidade, série temporal e exposição estavam renderizadas, mas valores dentro dos gráficos eram difíceis de comparar; o Book tinha uma linguagem e navegação diferentes do painel. | Os valores são rotulados nas séries e a direção visual e a navegação foram unificadas. O texto do Book continua explicando que a série agrupa casos ativos pela primeira detecção, sem se passar por histórico de snapshots. |
| Book `/book` · mobile | Os gráficos empilhavam, mas rótulos e controles ficavam pequenos; o destino de administração não aparecia na navegação móvel. | Gráficos ganham valores e rótulos mais legíveis, a navegação se adapta ao papel e o conteúdo reserva espaço para a barra inferior. |
| Login `/login` | O formulário tinha campos baixos e texto de apoio com pouco contraste em relação à importância do acesso. | O formulário ganhou campos de 48px, estados de foco claros e contexto sobre o produto, mantendo login e fluxo de convite. |

Os dados, filtros, paginação, seleção de empresa, comentários, notas internas, administração e permissões existentes foram mantidos. Não foram inseridas métricas de exemplo no painel nem uma promessa de frequência de sincronização que a página não pudesse confirmar.

## Direção visual

O sistema está documentado em [`DESIGN.md`](./DESIGN.md): um registro técnico de exposição, com superfícies azul-marinho, ciano para foco e ação, tipografia IBM Plex e painéis definidos por bordas. A direção usa como referência os rótulos e gráficos das imagens fornecidas pelo usuário, preservando a paleta escura e a leitura analítica. O arquivo [`.impeccable/design.json`](./.impeccable/design.json) registra tokens, rampas de cor e componentes para as ferramentas Impeccable/Stitch.

### Coleções DESIGN.md consultadas

- `awesome-design-60/design-md/linear/DESIGN.md` e `ifuryst-design-md/design-md/linear.app/DESIGN.md`: hierarquia tipográfica clara e uso contido de bordas.
- `awesome-design-60/design-md/sentry/DESIGN.md` e `ifuryst-design-md/design-md/sentry/DESIGN.md`: contraste de console operacional e agrupamento denso de informação.
- `awesome-design-60/design-md/supabase/DESIGN.md`: semântica explícita de estados e feedback.

As coleções serviram como referência de hierarquia e comportamento; não foram copiadas as identidades visuais ou paletas desses produtos.

## Skills consultadas

- `product-design:audit`: inventário de rotas e fluxos, evidência visual por viewport e priorização dos problemas encontrados.
- `design-taste-frontend` e `impeccable` (`new-work`, `craft-floor`, `concept-seed`, `document`): direção “registro de exposição técnica”, hierarquia orientada aos dados e documentação dos tokens implementados.
- `redesign-existing-projects`: redesign integral sem trocar Next.js, React, Recharts ou o fluxo já existente.
- `antislop-ui` e `antislop`: revisão de hierarquia, estados reais, consistência e remoção de adornos que não explicam o produto.
- `antislop-human`: rótulos, teclado, foco, diálogo e cálculo de contraste WCAG.
- `antislop-layoutmobile`: reflow, alvos de toque, barra inferior e conteúdo sem overflow em viewport estreita.

O script `contrast-check.py` da skill estava presente, mas o alias de Python do Windows abria a Microsoft Store em vez de um interpretador. Os pares de cores usados foram então calculados com a fórmula WCAG 2.x em JavaScript: texto principal sobre fundo 16,40:1; texto auxiliar sobre superfícies 9,36:1; foco ciano sobre fundo 12,21:1; texto de ação sobre ciano 10,02:1; e borda comum sobre painel 3,80:1. Esses resultados cobrem os pares semânticos principais, não substituem uma avaliação completa de cada navegador e monitor.

## MCPs e componentes

- **Figma MCP:** `whoami` confirmou uma sessão autenticada. A busca por componentes/sistemas disponíveis requer um `fileKey`; não havia arquivo Figma ou link fornecido no projeto. Não foi criado um arquivo novo, pois a tarefa era alterar este repositório.
- **shadcn, Magic UI, HeroUI e 21st:** não havia servidores ou ferramentas MCP correspondentes carregados nesta sessão. Também não havia dependências desses kits no projeto. Para manter a stack existente, o redesenho usa CSS próprio e Recharts já instalado.
- A lista de ferramentas disponíveis foi inspecionada antes de concluir que esses quatro MCPs não estavam disponíveis. Nenhum deles foi tratado como se tivesse sido consultado.

## Auditoria visual depois do redesign

_A preencher após a revisão autenticada das rotas publicadas em desktop e mobile._
