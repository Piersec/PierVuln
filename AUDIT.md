# Auditoria e redesign do PierVuln

## Escopo e método

As rotas `/`, `/book` e `/login` foram revisadas antes do redesign na produção e, depois, na prévia local em desktop e mobile (390 × 844), sem gravar alterações no Supabase. Após publicar, `/` e `/book` foram conferidas novamente em desktop com a sessão autenticada, e `/login` foi conferida em mobile. A auditoria combinou inspeção visual, árvore de acessibilidade do navegador e medições de largura. A aba móvel separada não herdou a sessão autenticada para `/` e `/book`; nessas rotas protegidas, a revisão responsiva final foi feita na prévia local. Não foram executadas suítes de teste.

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

- `product-design:index` e `product-design:audit`: seleção do método de produto e inventário de rotas e fluxos, evidência visual por viewport e priorização dos problemas encontrados.
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

### Desktop publicado

- `/`: a hierarquia do painel, navegação, paginação, indicadores e tabela foram conferidos na produção. O resumo agora deixa claro o escopo do conjunto completo; a quantidade de linhas exibidas fica associada à página atual. O estado de atualização comunica quando uma fonte está desatualizada.
- `/book`: os cartões, gráficos de severidade, evolução, tempo de exposição, tabela Top 3 e inventário técnico foram conferidos com a sessão autenticada. Rótulos e totais aparecem junto às visualizações. A nota explica que os pontos mensais agrupam achados ativos pela primeira detecção e não representam snapshots mensais históricos.
- `/login`: a composição de acesso foi verificada na prévia local em desktop; o caminho de autenticação e convite continuou presente.

### Mobile

- Na prévia local a 390 × 844, `/` e `/book` refluem para uma coluna sem overflow horizontal da página. A navegação continua disponível, os casos ficam em cartões e os gráficos ficam empilhados. A área inferior reserva espaço para a navegação móvel.
- Em produção, `/login` foi verificada a 390 × 844: os campos e o botão ocupam a largura disponível, os rótulos permanecem legíveis e a página não cria rolagem horizontal.
- A aba autenticada de produção foi mantida no tamanho normal do Chrome e uma nova aba móvel não recebeu a sessão existente; não foi inserida senha para tentar contornar essa limitação. Por isso, as rotas protegidas `/` e `/book` foram revisadas em mobile na prévia local, sem dados do cliente.

### Correções e verificação

- A revisão visual encontrou uma resolução incorreta das variáveis de fonte, que fazia a interface cair em fontes de sistema; os estilos foram corrigidos antes da publicação e a IBM Plex aparece no resultado publicado.
- Uma única execução de `impeccable detect --json` apontou dois acentos laterais estreitos (“side-tab”); esses acentos foram removidos. A ferramenta também apresentou recomendações de valores de tokens. O detector não foi executado novamente após os ajustes, então este relatório não afirma que todos os avisos tenham sido eliminados.
- `pnpm typecheck` e `pnpm build` passaram para o código publicado. Nenhuma suíte de testes foi executada. Os screenshots foram inspecionados no navegador, sem exportação para arquivos locais.
- A revisão final de acabamento e documentação Impeccable foi feita nesta sessão, inline; não havia executor de subagentes disponível para delegar os papéis `finish-reviewer` e `documenter`.
