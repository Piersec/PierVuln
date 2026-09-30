---
name: PierVuln
description: Registro técnico de exposição a vulnerabilidades com contexto, histórico e fluxo de tratamento.
colors:
  canvas: "#090a0b"
  surface: "#191a1c"
  surface-raised: "#252628"
  surface-inset: "#121315"
  line: "#35373a"
  line-strong: "#4b4e52"
  text-primary: "#f6f7f7"
  text-muted: "#a4a8ae"
  primary: "#61df57"
  primary-strong: "#82ed79"
  primary-ink: "#0a1209"
  nav-current: "#262a26"
  positive: "#61df57"
  caution: "#ffce78"
  critical: "#fb7580"
  high: "#ffc078"
  medium: "#8dbdff"
  low: "#a7acb6"
typography:
  display:
    fontFamily: "IBM Plex Sans, Arial, sans-serif"
    fontSize: "clamp(1.75rem, 3vw, 2.375rem)"
    fontWeight: 700
    lineHeight: 1.13
    letterSpacing: "-0.025em"
  title:
    fontFamily: "IBM Plex Sans, Arial, sans-serif"
    fontSize: "19px"
    fontWeight: 600
    lineHeight: 1.3
  body:
    fontFamily: "IBM Plex Sans, Arial, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "IBM Plex Mono, Consolas, monospace"
    fontSize: "11px"
    fontWeight: 500
    lineHeight: 1.4
  micro-label:
    fontFamily: "IBM Plex Mono, Consolas, monospace"
    fontSize: "10px"
    fontWeight: 600
    lineHeight: 1.4
  caption:
    fontFamily: "IBM Plex Sans, Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.5
  control:
    fontFamily: "IBM Plex Sans, Arial, sans-serif"
    fontSize: "13px"
    fontWeight: 500
    lineHeight: 1.4
  compact-body:
    fontFamily: "IBM Plex Sans, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  tight: "4px"
  control: "12px"
  compact: "6px"
  card: "15px"
  brand: "8px"
  pill: "999px"
  circle: "50%"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "18px"
  xl: "24px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-ink}"
    rounded: "{rounded.pill}"
    padding: "0 17px"
    height: "42px"
  button-secondary:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.pill}"
    padding: "0 13px"
    height: "42px"
  field:
    backgroundColor: "{colors.surface-inset}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "42px"
  nav-current:
    backgroundColor: "{colors.nav-current}"
    textColor: "{colors.primary-strong}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "48px"
  severity-critical:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.critical}"
    rounded: "{rounded.control}"
    padding: "3px 9px"
    height: "30px"
  surface-card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.card}"
    padding: "20px"
---

# Design System: PierVuln

## Overview

**Creative North Star: “Registro de exposição técnica.”**

PierVuln trata cada achado como um item verificável: a interface mostra o estado da fonte, a identidade do caso e o andamento do tratamento sem confundir leitura atual com histórico mensal. O painel de vulnerabilidades funciona como uma fila operacional; o Book transforma a mesma leitura em comparações que ajudam a priorizar correções.

O sistema usa fundo quase preto, cartões em cinza carvão e verde reservado a ações, foco e tendência positiva. A hierarquia vem de tipografia, contraste entre superfícies e espaçamento; estados críticos, altos, médios e baixos mantêm cores próprias e rótulos textuais. **Key Characteristics:**

- Totais globais permanecem separados da paginação da tabela.
- O estado recente ou desatualizado da fonte fica visível antes dos casos.
- Gráficos incluem valores e texto que explica o recorte dos dados.
- Controles mantêm rótulos acessíveis, foco claro e alvos grandes em telas pequenas.

## Colors

A paleta parte do preto e do carvão da referência visual, com verde luminoso para orientar a ação.

### Primary
- **Verde de ação** (`colors.primary`): ações principais, gráficos de tendência e navegação ativa.
- **Verde luminoso** (`colors.primary-strong`): foco visível, links técnicos e rótulos selecionados.

### Neutral
- **Campo profundo** (`colors.canvas`): fundo global do produto.
- **Superfície de leitura** (`colors.surface`): painéis, formulários e gráficos.
- **Superfície elevada** (`colors.surface-raised`): controles e áreas secundárias.
- **Superfície de entrada** (`colors.surface-inset`): campos editáveis e filtros.
- **Texto principal** (`colors.text-primary`): títulos, valores e conteúdo prioritário.
- **Texto auxiliar** (`colors.text-muted`): explicações, metadados e estados secundários.
- **Divisória** (`colors.line`): separação interna de linhas e campos; cartões não usam contorno.

### Named Rules
**The Signal Rule.** Verde indica ação ou dado em foco; a severidade usa sua própria cor e sempre conserva o rótulo textual.

## Typography

- **Display Font:** IBM Plex Sans (com Arial como fallback)
- **Body Font:** IBM Plex Sans (com Arial como fallback)
- **Label/Mono Font:** IBM Plex Mono (com Consolas como fallback)

**Character:** A sans-serif mantém leitura confortável nos casos, nos totais e nos textos do relatório; a monoespaçada distingue CVEs e metadados técnicos.

### Hierarchy
- **Display** (700, variável conforme viewport, entre 28px e 38px, line-height 1.13): títulos de página.
- **Headline** (700, 17–19px, line-height 1.3): seções, painéis e títulos de gráficos.
- **Title** (600, 15–16px, line-height 1.3): blocos de formulário e informação.
- **Body** (400, 15px, line-height 1.5): explicações e texto corrido, com linhas curtas em painéis.
- **Label** (500, 11–13px, line-height 1.4): dados monoespaçados e rótulos concisos; não reduzir texto essencial abaixo de 12px.

### Named Rules
**The Readable Number Rule.** Use números tabulares nos indicadores e IBM Plex Mono para identificadores técnicos; mantenha unidades e rótulos ao lado do valor.

## Layout

Em desktop, uma faixa lateral de 72px mantém a navegação por ícones acessíveis e libera largura para o painel. O cabeçalho reúne contexto e ações. O dashboard começa com quatro indicadores compactos de largura igual; a lista de casos ocupa um painel próprio abaixo. O Book repete os quatro indicadores e coloca dois gráficos grandes lado a lado na segunda linha. A tabela continua compacta e com paginação explícita.

Em larguras intermediárias e pequenas, os quatro indicadores passam para duas colunas. A tabela de casos vira cartões empilhados e os gráficos passam para uma coluna. Os resumos apresentam o total da seleção independentemente das 50 linhas da página atual.

## Elevation & Depth

Os cartões se separam do fundo somente pela diferença de superfície; não têm bordas nem sombras em repouso. O Spotlight Card acompanha o ponteiro discretamente no primeiro indicador. O painel lateral de detalhes se distingue por uma camada de fundo escurecida. Controles em foco mantêm contorno visível.

### Named Rules
**The Borderless Card Rule.** Use contraste de superfície e espaçamento para organizar os cartões; reserve linhas para tabela, campos e separações internas.

## Shapes

Cartões usam raio de 15px e dispensam bordas. Botões de ação, filtros e chips usam formato de cápsula; campos e painéis de tabela têm raio moderado. Campos, botões e seletores mantêm altura mínima confortável para toque.

## Auditoria da referência

O [dashboard do SecurityOne Lab](https://lab.pod2.securityone.ai/dashboard), inspecionado em 30/09/2026, motivou a faixa lateral mínima e o cabeçalho compacto. As capturas de tela fornecidas pelo usuário em seguida passam a definir a composição principal: fundo quase preto, quatro indicadores pequenos, painéis de gráficos grandes e tabela agrupada em uma única superfície. A tabela de casos, o filtro de severidade e o carregamento usam os componentes Table, Dropdown e Skeleton do [HeroUI v3](https://heroui.com/), com estilos locais que preservam a paleta e os cartões sem borda. Nenhuma métrica ou interação é inferida das imagens.

## Components

### Bento tiles
- **Origem:** `BentoGrid` e `BentoCard` adaptados do [Magic UI Bento Grid](https://magicui.design/docs/components/bento-grid) para o CSS existente; `SpotlightCard` adaptado do [React Bits](https://github.com/DavidHDev/react-bits/blob/main/src/content/Components/SpotlightCard/SpotlightCard.jsx).
- **Behavior:** quatro indicadores equivalentes abrem dashboard e Book. O spotlight verde acompanha o mouse nos cards do painel, do Book e nos indicadores administrativos, como feedback suave da área apontada pelo usuário. O efeito só aparece na interação, não bloqueia controles e fica desativado em telas de toque e com redução de movimento. Os blocos mantêm rótulo, valor e explicação, sem números fictícios e sem borda.

### Buttons
- **Character:** diretos e com rótulos verbais, sem depender de ícones isolados.
- **Shape:** cápsula para ações compactas.
- **Primary:** fundo verde, texto quase preto e altura mínima de 42px.
- **Secondary:** superfície elevada sem borda.
- **Hover / Focus:** o hover reforça o contraste; o foco usa anel externo verde e permanece perceptível no tema escuro.

### Fields and filters
- **Character:** campos integrados à superfície, com contraste próprio e valor legível.
- **Shape:** cantos moderados, altura mínima de 42px e espaçamento interno horizontal.
- **Behavior:** cada filtro tem nome acessível; foco não depende apenas de mudança de cor.

### Navigation
- **Character:** texto direto e item atual claramente delimitado.
- **Shape:** alvos de 44–48px sem borda; a opção ativa mantém cor e fundo distintos.
- **Behavior:** o painel principal preserva os três destinos internos em viewport móvel; o Book mantém sua navegação acessível junto à conta.

### Severity chips
- **Character:** rótulo textual com ponto de cor e fundo, para que a cor não seja o único sinal.
- **Behavior:** manter a mesma associação semântica de severidade em tabela, detalhes e gráficos.

### Data panels and charts
- **Character:** superfícies planas separadas pelo fundo; linhas discretas aparecem apenas dentro das tabelas e gráficos.
- **Behavior:** todo gráfico inclui descrição acessível, valores visíveis e nota quando o conjunto atual não representa uma série histórica de snapshots.

## Do's and Don'ts

- Do manter o total consultado separado da quantidade de registros exibidos na página.
- Do mostrar quando a última leitura completa ficou desatualizada.
- Do validar que a tabela, filtros e navegação cabem em telas de 390px sem rolagem horizontal da página.
- Do manter contraste AA para texto comum e foco claramente visível em teclado.
- Don't usar cor isolada para comunicar severidade, fluxo ou frescor da fonte.
- Don't apresentar a distribuição atual por primeira detecção como contagem histórica de snapshots.
- Don't reduzir rótulos essenciais para microtexto nem trocar texto de ação por glifos ambíguos.
