---
name: PierVuln
description: Registro técnico de exposição Wazuh com contexto, histórico e fluxo de tratamento.
colors:
  canvas: "#081923"
  surface: "#0d2330"
  surface-raised: "#102b3b"
  surface-inset: "#07151e"
  line: "#607f90"
  line-strong: "#6f91a2"
  text-primary: "#f0f6f8"
  text-muted: "#b6c8d1"
  primary: "#57dce5"
  primary-strong: "#86f1f2"
  primary-ink: "#06222d"
  nav-current: "#123747"
  positive: "#78dfb5"
  caution: "#ffce78"
  critical: "#ff8190"
  high: "#ffc078"
  medium: "#62dce7"
  low: "#a0caff"
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
  control: "5px"
  compact: "6px"
  card: "15px"
  brand: "8px"
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
    rounded: "{rounded.control}"
    padding: "0 17px"
    height: "46px"
  button-secondary:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.control}"
    padding: "0 13px"
    height: "44px"
  field:
    backgroundColor: "{colors.surface-inset}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "44px"
  nav-current:
    backgroundColor: "{colors.nav-current}"
    textColor: "{colors.primary-strong}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "46px"
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

O sistema usa superfícies azul-marinho, texto claro e um acento ciano reservado a navegação, foco e dados em destaque. A hierarquia vem de tipografia, bordas e espaçamento; estados críticos, altos, médios e baixos mantêm cores próprias e rótulos textuais. **Key Characteristics:**

- Totais globais permanecem separados da paginação da tabela.
- O estado recente ou desatualizado da fonte fica visível antes dos casos.
- Gráficos incluem valores e texto que explica o recorte dos dados.
- Controles mantêm rótulos acessíveis, foco claro e alvos grandes em telas pequenas.

## Colors

A paleta parte de um campo escuro e usa o ciano para orientar atenção sem pintar toda a interface como alerta.

### Primary
- **Ciano de leitura** (`colors.primary`): ações principais, destaques do relatório e navegação ativa.
- **Ciano luminoso** (`colors.primary-strong`): foco visível, links técnicos e rótulos selecionados.

### Neutral
- **Campo profundo** (`colors.canvas`): fundo global do produto.
- **Superfície de leitura** (`colors.surface`): painéis, formulários e gráficos.
- **Superfície elevada** (`colors.surface-raised`): controles e áreas secundárias.
- **Superfície de entrada** (`colors.surface-inset`): campos editáveis e filtros.
- **Texto principal** (`colors.text-primary`): títulos, valores e conteúdo prioritário.
- **Texto auxiliar** (`colors.text-muted`): explicações, metadados e estados secundários.
- **Divisória** (`colors.line`): separação de linhas e regiões sem sombras.

### Named Rules
**The Signal Rule.** Ciano indica ação ou dado em foco; a severidade usa sua própria cor e sempre conserva o rótulo textual.

## Typography

- **Display Font:** IBM Plex Sans (com Arial como fallback)
- **Body Font:** IBM Plex Sans (com Arial como fallback)
- **Label/Mono Font:** IBM Plex Mono (com Consolas como fallback)

**Character:** A sans-serif mantém leitura confortável nos casos e nos textos do relatório; a monoespaçada distingue CVEs, totais e metadados técnicos.

### Hierarchy
- **Display** (700, variável conforme viewport, entre 28px e 38px, line-height 1.13): títulos de página.
- **Headline** (700, 17–19px, line-height 1.3): seções, painéis e títulos de gráficos.
- **Title** (600, 15–16px, line-height 1.3): blocos de formulário e informação.
- **Body** (400, 15px, line-height 1.5): explicações e texto corrido, com linhas curtas em painéis.
- **Label** (500, 11–13px, line-height 1.4): dados monoespaçados e rótulos concisos; não reduzir texto essencial abaixo de 12px.

### Named Rules
**The Readable Number Rule.** Use IBM Plex Mono para identificadores e contagens; mantenha unidades e rótulos em texto normal ao lado do valor.

## Layout

Em desktop, a navegação lateral fixa a orientação do produto e o conteúdo ocupa uma coluna fluida. O primeiro bloco usa um bento de 12 colunas: o total ocupa duas linhas, os indicadores críticos e de fluxo ficam próximos e o estado da fonte recebe uma faixa própria. O Book repete a lógica com blocos de larguras diferentes para resumo, critérios, gráficos e concentração por CVE. A lista de casos continua em tabela compacta com paginação explícita.

Em larguras intermediárias, os bentos passam para seis colunas. Em telas pequenas, a leitura vira uma coluna, com os dois indicadores curtos lado a lado quando houver espaço; a tabela de casos vira cartões empilhados e os gráficos passam para uma coluna. Os resumos apresentam o total da seleção independentemente das 50 linhas da página atual.

## Elevation & Depth

O sistema usa planos de fundo e bordas para separar as superfícies. O bloco principal de exposição recebe um degradê curto e anéis de leitura que remetem a uma varredura; o Spotlight Card acompanha o ponteiro somente nesse bloco. Sombras são evitadas em repouso; o painel lateral de detalhes se distingue por uma camada de fundo escurecida. Foco e seleção usam contorno visível.

### Named Rules
**The Border First Rule.** Use tom de superfície e divisórias para organizar conteúdo; reserve sobreposição escura para o diálogo de detalhes.

## Shapes

Controles têm cantos discretos e consistentes; cartões bento e painéis usam raio de 15px para marcar regiões de conteúdo. Chips de severidade usam borda e fundo preenchido, enquanto navegação e tabela evitam cápsulas decorativas. Campos, botões e seletores mantêm altura mínima confortável para toque.

## Components

### Bento tiles
- **Origem:** `BentoGrid` e `BentoCard` adaptados do [Magic UI Bento Grid](https://magicui.design/docs/components/bento-grid) para o CSS existente; `SpotlightCard` adaptado do [React Bits](https://github.com/DavidHDev/react-bits/blob/main/src/content/Components/SpotlightCard/SpotlightCard.jsx).
- **Behavior:** largura e altura expressam prioridade real dos dados. O spotlight aparece somente no total de casos e respeita redução de movimento. Os blocos mantêm rótulo, valor e explicação, sem números fictícios.

### Buttons
- **Character:** diretos e com rótulos verbais, sem depender de ícones isolados.
- **Shape:** canto curto (5px).
- **Primary:** fundo ciano, texto azul-escuro e altura de 46px.
- **Secondary:** superfície elevada, borda visível e altura mínima de 44px.
- **Hover / Focus:** o hover reforça o contraste; o foco usa anel externo ciano e permanece perceptível no tema escuro.

### Fields and filters
- **Character:** campos integrados à superfície, mantendo borda clara e valor legível.
- **Shape:** cantos curtos (5px), altura mínima de 44px e espaçamento interno horizontal.
- **Behavior:** cada filtro tem nome acessível; foco não depende apenas de mudança de cor.

### Navigation
- **Character:** texto direto e item atual claramente delimitado.
- **Shape:** linhas de 44–46px com borda sutil; a opção ativa mantém cor e fundo distintos.
- **Behavior:** o painel principal preserva os três destinos internos em viewport móvel; o Book mantém sua navegação acessível junto à conta.

### Severity chips
- **Character:** rótulo textual com ponto de cor e borda, para que a cor não seja o único sinal.
- **Behavior:** manter a mesma associação semântica de severidade em tabela, detalhes e gráficos.

### Data panels and charts
- **Character:** superfícies planas divididas por bordas e títulos explícitos.
- **Behavior:** todo gráfico inclui descrição acessível, valores visíveis e nota quando o conjunto atual não representa uma série histórica de snapshots.

## Do's and Don'ts

- Do manter o total consultado separado da quantidade de registros exibidos na página.
- Do mostrar quando a última leitura completa ficou desatualizada.
- Do validar que a tabela, filtros e navegação cabem em telas de 390px sem rolagem horizontal da página.
- Do manter contraste AA para texto comum e foco claramente visível em teclado.
- Don't usar cor isolada para comunicar severidade, fluxo ou frescor da fonte.
- Don't apresentar a distribuição atual por primeira detecção como contagem histórica de snapshots.
- Don't reduzir rótulos essenciais para microtexto nem trocar texto de ação por glifos ambíguos.
