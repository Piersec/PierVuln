# Validação dos emails

Verificação em 01/10/2026. Escopo: os 13 HTMLs de envio e a prévia local, sem alterar o Supabase hospedado.

## Evidência técnica

- 13 templates com placeholders preservados; nenhum script, SVG, domínio demonstrativo ou código fictício nos HTMLs de envio.
- Cinco templates por link: botão de 52px e link alternativo apontam exatamente para `{{ .ConfirmationURL }}`.
- Reautenticação usa `{{ .Token }}`; os sete avisos de segurança não contêm links de confirmação.
- Prévia em navegador Chromium: viewport externo 1280px, 390px e 320px. Todos os 13 documentos internos ficaram dentro da largura disponível (960px, 359px e 289px, respectivamente; uma barra vertical reduziu um documento desktop a 945px).
- Contraste calculado: texto secundário/superfície 7,29:1; secundário/fundo 8,29:1; texto principal/superfície 16,23:1; texto/botão 11,06:1; código/fundo 10,80:1; link/superfície 11,89:1; secundário/inset 7,78:1.
- Navegador não registrou erros ou avisos no console durante a verificação.
- Os dados da prévia são explicitamente demonstrativos, com emails em `example.com` e código fictício.
- Nenhum email real enviado, token real consumido ou teste de caixa de entrada Gmail/Outlook realizado. Compatibilidade de recebimento requer teste SMTP; os fallbacks foram inspecionados no código.

## Interações conferidas

Cada linha abaixo corresponde à navegação pela âncora da prévia, abertura do HTML fonte com título/conteúdo correto, recolhimento por clique e expansão por Enter:

| Template | Âncora | Fonte abre | Recolhe / expande por teclado |
| --- | --- | --- | --- |
| Confirm sign up | PASS: #confirm-sign-up | PASS: confirm-sign-up.html | PASS |
| Invite user | PASS: #invite-user | PASS: invite-user.html | PASS |
| Magic link or OTP | PASS: #magic-link-or-otp | PASS: magic-link-or-otp.html | PASS |
| Change email address | PASS: #change-email-address | PASS: change-email-address.html | PASS |
| Reset password | PASS: #reset-password | PASS: reset-password.html | PASS |
| Reauthentication | PASS: #reauthentication | PASS: reauthentication.html | PASS |
| Password changed | PASS: #password-changed | PASS: password-changed.html | PASS |
| Email address changed | PASS: #email-address-changed | PASS: email-address-changed.html | PASS |
| Phone number changed | PASS: #phone-number-changed | PASS: phone-number-changed.html | PASS |
| Sign-in method linked | PASS: #sign-in-method-linked | PASS: sign-in-method-linked.html | PASS |
| Sign-in method removed | PASS: #sign-in-method-removed | PASS: sign-in-method-removed.html | PASS |
| MFA method added | PASS: #mfa-method-added | PASS: mfa-method-added.html | PASS |
| MFA method removed | PASS: #mfa-method-removed | PASS: mfa-method-removed.html | PASS |

As ações dos emails de envio foram verificadas por inspeção de `href`, porque as variáveis dependem da renderização pelo Supabase. Os links demonstrativos da prévia apontam para `example.com`; não representam um teste de autenticação.

## Gate antislop

### Hard Gate

- R-02 PASS: textos novos sem travessão.
- R-03 PASS: os 13 exemplos sem overflow horizontal em desktop, 390px e 320px; botões principais com 52px.
- R-17 PASS: nenhum indicador, estatística ou prazo de validade inventado.
- R-18 PASS: nenhum depoimento ou pessoa fictícia.
- R-23 PASS: marca textual existente; nenhum novo logo, avatar ou imagem criado.
- R-24 PASS: todas as 13 âncoras da prévia apontam para seções existentes, testadas.
- R-25 PASS: todas as combinações de texto superam 4,5:1, conforme cálculos acima.
- R-26 PASS: links de envio preservam ConfirmationURL; links locais e controles da prévia exercitados; exemplos explicitamente identificados.
- R-27 PASS: documento estático sem busca de dados; orientações cobrem solicitação não reconhecida e token expirado, sem simular estado de envio.
- R-28 PASS: nenhuma FAQ adicionada.
- R-32 PASS: elementos nativos, outline visível declarado e os 13 accordions expandidos por Enter.
- R-33 PASS: HTML escrito como arquivos fonte, sem script de remendo de CSS.
- R-34 PASS: sem alternador de tema; estilos essenciais inline e fallback de fonte inspecionados.
- R-35 PASS: prévia executada no navegador, fontes e controles testados; ações Supabase inspecionadas sem envio real.
- R-36 PASS: sem alegações de certificação, desempenho ou segurança inventadas.
- R-37 PASS: direção derivada de DESIGN.md e declarada antes da criação.
- R-38 PASS: dados reais vêm das variáveis do Supabase; exemplos identificados como prévia.

### Purpose-Gate

- R-01 PASS: cores da identidade existente, sem gradientes ou glows.
- R-04 PASS: sem ícones decorativos.
- R-06 PASS: IBM Plex/Arial da identidade; fonte mono apenas no código para legibilidade.
- R-07 PASS: fundo liso da paleta, sem padrões.
- R-08 PASS: sem setas decorativas nos botões.
- R-09 PASS: sem badges ou categorias duplicando o título.
- R-10 PASS: sem glassmorphism.
- R-12 PASS: sem sombras.
- R-13 PASS: sem glows.
- R-14 PASS: superfície única agrupa cada mensagem transacional; não há grade de features.
- R-19 PASS: emails estáticos e sem animação, compatíveis com MOTION 1.
- R-22 PASS: sem ilustrações.

### Liveliness

- Dials PASS: ENERGY 1 / RHYTHM 1 / MOTION 1 explícitos.
- Consistência PASS: estrutura previsível para mensagens transacionais da mesma conta.
- Foco PASS: botão nos fluxos por link, código na reautenticação, título nos avisos.
- Espaçamento PASS: 36px na superfície, 24px para separar ação e instruções; celular com 22px.
- Acento PASS: verde reservado à ação, ao código e ao link alternativo.
- Identidade PASS: marca PierVuln, fundo e superfícies do site, botão em cápsula.
- Design Read PASS: declarado antes de gerar os arquivos e registrado no README.

### Craftsmanship e Quality Locks

- C-1 PASS: razões para paleta, layout, fonte, espaçamento e marca documentadas no README.
- C-2 PASS: fontes, âncoras e accordions exercitados; destinos dinâmicos dos emails inspecionados.
- C-3 PASS: conteúdo restrito ao evento, conta, ação quando aplicável e orientação de segurança.
- C-4 PASS: exemplos em três larguras; expansão por teclado; fontes de fallback e dados variáveis com quebra.
- C-5 PASS: sem claims ou dados de usuários inventados nos templates de envio.
- R-05 PASS: uma coluna transacional por email, coerente com RHYTHM 1.
- R-11 PASS: superfície de 15px, dados de 12px e botão em cápsula do design existente.
- R-15 PASS: CTAs específicos, como Confirmar email, Aceitar convite e Redefinir senha.
- R-16 PASS: textos diretos sobre o evento e a ação, sem buzzwords.
- R-20 PASS: direção do produto existente, com marca textual e cores do PierVuln.
- R-21 PASS: tema escuro segue a identidade documentada, sem impor novo tema ao site.
- R-29 PASS: neutros e um acento verde, sem cores adicionais.
- R-30 PASS: nenhum outro produto usado como molde.
- R-31 PASS: decisões principais justificadas por escrito no README.

Resultado: PASS para o escopo de HTML e prévia local. Renderização final em clientes de email e envio SMTP ainda não verificados.
