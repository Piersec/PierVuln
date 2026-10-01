# Emails do PierVuln

13 templates HTML em português para o projeto Supabase `jgrmgqukkrwrntsihmmk`.

## Aplicar no Supabase

1. Abra [Email Templates](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates).
2. Selecione o template indicado na tabela abaixo.
3. Cole o assunto no campo **Subject** e todo o conteúdo do HTML no campo **Body** / código-fonte.
4. Salve e confira a prévia do Supabase.
5. Para os sete templates de **Security**, habilite a respectiva notificação no projeto se quiser que esses emails sejam enviados.

A criação destes arquivos não altera a configuração do projeto remoto nem habilita notificações. Não cole `preview.html` no Supabase.

| Template no painel | HTML | Assunto |
| --- | --- | --- |
| [Confirm sign up](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/confirm-sign-up) | [confirm-sign-up.html](confirm-sign-up.html) | Confirme seu email | PierVuln |
| [Invite user](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/invite-user) | [invite-user.html](invite-user.html) | Você foi convidado para o PierVuln |
| [Magic link or OTP](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/magic-link-or-otp) | [magic-link-or-otp.html](magic-link-or-otp.html) | Seu link de acesso | PierVuln |
| [Change email address](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/change-email-address) | [change-email-address.html](change-email-address.html) | Confirme a alteração de email | PierVuln |
| [Reset password](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/reset-password) | [reset-password.html](reset-password.html) | Redefina sua senha | PierVuln |
| [Reauthentication](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/reauthentication) | [reauthentication.html](reauthentication.html) | Seu código de verificação | PierVuln |
| [Password changed](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/password-changed) | [password-changed.html](password-changed.html) | Sua senha foi alterada | PierVuln |
| [Email address changed](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/email-address-changed) | [email-address-changed.html](email-address-changed.html) | Seu email foi alterado | PierVuln |
| [Phone number changed](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/phone-number-changed) | [phone-number-changed.html](phone-number-changed.html) | Seu telefone foi alterado | PierVuln |
| [Sign-in method linked](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/sign-in-method-linked) | [sign-in-method-linked.html](sign-in-method-linked.html) | Novo método de acesso vinculado | PierVuln |
| [Sign-in method removed](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/sign-in-method-removed) | [sign-in-method-removed.html](sign-in-method-removed.html) | Método de acesso removido | PierVuln |
| [MFA method added](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/mfa-method-added) | [mfa-method-added.html](mfa-method-added.html) | Verificação adicional ativada | PierVuln |
| [MFA method removed](https://supabase.com/dashboard/project/jgrmgqukkrwrntsihmmk/auth/templates/mfa-method-removed) | [mfa-method-removed.html](mfa-method-removed.html) | Verificação adicional removida | PierVuln |

## Prévia

Abra [preview.html](preview.html) no navegador. Os 13 exemplos usam endereços `example.com`, telefones demonstrativos e um código fictício, exclusivamente na prévia. Os links dentro dos iframes apontam para `example.com` e não autenticam usuários. O HTML de envio conserva os placeholders.

## Variáveis e fluxo

- Autenticação por link: `{{ .ConfirmationURL }}` no botão e no link alternativo. Mantém o token, tipo e redirecionamento gerados pelo Supabase.
- Reautenticação: `{{ .Token }}` para inserir na operação que solicitou o código, sem botão de confirmação.
- Conta: `{{ .Email }}`.
- Alteração de email: `{{ .Email }}` e `{{ .NewEmail }}`. O texto atende às confirmações do email antigo e novo quando a opção Secure email change estiver ativa.
- Notificação de email alterado: `{{ .OldEmail }}` e `{{ .Email }}`; não usa `NewEmail`, exclusivo do template de confirmação.
- Telefone alterado: `{{ .OldPhone }}` e `{{ .Phone }}`.
- Método de acesso: `{{ .Provider }}`.
- MFA: `{{ .FactorType }}`.

O template **Magic link or OTP** usa o modo magic link. O login atual do PierVuln não oferece um formulário para inserir OTP de acesso; o email não promete esse fluxo. A reautenticação é um template preparado para quando a aplicação solicitar esse código.

O retorno da recuperação continua vindo de `resetPasswordForEmail({ redirectTo: ".../reset-password?mode=update" })`; o email de convite respeita o retorno para onboarding. Não construa URLs anexando caminhos a `SiteURL`: no projeto, ela já contém `/onboarding`. Confira Site URL e Redirect URLs no painel antes de testar os fluxos.

As notificações de segurança informam uma alteração já realizada. Não usam tokens ou links de confirmação. Orientam o usuário a acessar o endereço conhecido do serviço e contatar o administrador da equipe, sem inventar um contato de suporte.

## Compatibilidade e direção visual

- Paleta de [DESIGN.md](../../DESIGN.md): fundo `#090a0b`, superfície `#191a1c`, texto `#f6f7f7`, secundário `#a4a8ae` e ação `#61df57`.
- Direção: emails transacionais para usuários do PierVuln, ENERGY 1 / RHYTHM 1 / MOTION 1.
- Uma coluna de até 560px: leitura curta e adaptação para celular, com tabelas de apresentação e estilos essenciais inline.
- Tipografia IBM Plex Sans com Arial de fallback: continuidade com o site sem depender de carregamento de fontes remotas. Consolas no código facilita a leitura dos dígitos.
- Marca textual PierVuln: identificação permanece visível quando imagens estão bloqueadas. Sem SVG, imagens, scripts, fontes externas, flex ou grid no email.
- Espaçamento separa mensagem, ação e orientação de segurança; verde destaca o botão ou código. Cantos de 15px na superfície e botão em cápsula acompanham o site.
- Clientes Outlook recebem contêiner condicional de 560px e fallback Arial. O email continua legível quando media queries ou bordas arredondadas são ignoradas.
- Prazo de validade não é fixado no texto porque depende da configuração do projeto.
- Não há promessa de funcionamento de cor forçada em todos os clientes: alguns reescrevem as cores no modo escuro.

## Validação

Os placeholders e destinos foram conferidos contra a [documentação oficial de templates](https://supabase.com/docs/guides/auth/auth-email-templates). O teste de envio real depende do SMTP e de uma conta de teste do projeto. Nenhum email foi enviado nem token real consumido nesta tarefa.

[Relatório visual e técnico](validation.md).
