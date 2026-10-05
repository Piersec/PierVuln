# Recuperação de senha e onboarding

O login oferece `/reset-password`. A solicitação usa `auth.resetPasswordForEmail`. Os e-mails de recuperação e convite entregam `{{ .Token }}` como código digitado na aplicação; o app valida com `auth.verifyOtp` (tipo `recovery` ou `invite`) antes de liberar a redefinição ou o onboarding. Isso evita que filtros automáticos do email consumam o link único antes do usuário. A nova senha é salva com `auth.updateUser`, após verificação do usuário pelo Supabase. A página exige confirmação e a mesma composição de senha do onboarding: 12 caracteres, maiúscula, minúscula, número e símbolo. Após salvar, a sessão local é encerrada e o usuário pode voltar ao login.

No projeto remoto PierGV (`jgrmgqukkrwrntsihmmk`), o Site URL foi definido como `https://piervuln.vercel.app/onboarding`. A lista de redirecionamentos existente, `https://piervuln.vercel.app/**`, cobre onboarding e recuperação. Os links enviados diretamente pelo painel Supabase, sem redirecionamento explícito, usam esse Site URL. Links com um redirecionamento explícito autorizado continuam respeitando esse destino.

A função `admin-actions` envia os convites de clientes e equipe para `/onboarding`. Convites antigos com `/login?invite=1` também são encaminhados ao onboarding. O onboarding continua aceitando convites antigos por link; os novos podem ser validados pelo código digitado. Eventos `PASSWORD_RECOVERY` recebidos no onboarding, login ou painel abrem a redefinição de senha.

Depois de publicar o app, atualize no projeto Supabase os templates **Invite user** e **Reset password** com `supabase/email-templates/invite-user.html` e `supabase/email-templates/reset-password.html`. O painel do Supabase não é atualizado automaticamente pelos arquivos locais. Os códigos seguem o prazo configurado em Auth → Sign In / Providers → Email OTP expiration (padrão de uma hora).

O `supabase/config.toml` mantém os equivalentes locais. Ele não aplica configurações ao projeto hospedado. Para testar os e-mails do projeto remoto em localhost, é necessário autorizar também o endereço local no painel Supabase; para testes com Supabase local, os endereços já estão no arquivo.

Referência: [recuperação de senha no Supabase](https://supabase.com/docs/reference/javascript/auth-resetpasswordforemail).

## Verificação de entrega

Direção: tela de acesso para usuários do PierVuln, conforme `DESIGN.md`; ENERGY 1 / RHYTHM 2 / MOTION 1. Mantém IBM Plex Sans, fundo escuro e verde na ação principal, com formulário e instruções separados pelas superfícies existentes. Nenhum novo ativo visual ou efeito foi criado.

- Hard Gate PASS: nenhum dado fictício, navegação sem destino ou ativo visual novo; todas as ações têm formulário, handler ou link.
- R-03 PASS: navegador em 390 x 844; largura do documento e viewport iguais a 390 px, sem overflow horizontal.
- R-25 PASS: texto secundário `#a4a8ae` sobre `#090a0b` supera 4,5:1; estilos de campos, botão e foco são os já definidos pelo projeto.
- R-27 PASS: estados de verificação, solicitação, envio, alteração, link inválido e conclusão, com mensagens de erro e botões bloqueados durante requisições.
- Purpose-Gate PASS: fontes, cores e superfícies reutilizadas para consistência com o login; nenhuma decoração adicional.
- Liveliness PASS: marca existente e linguagem visual de `DESIGN.md`, com verde na ação principal; nenhuma animação nova.
- C-1/C-3 PASS: composição concentrada no formulário e na instrução de recuperação de acesso.
- C-2/R-26 PASS: validado o bloqueio do formulário vazio e a ação “Solicitar novo link”, que retorna ao formulário de e-mail.
- C-4 PASS: link expirado exibe mensagem e recuperação; campos possuem labels, autocomplete, estados de foco e avisos acessíveis.
- C-5 PASS: nenhuma afirmação de envio a uma conta inexistente; confirmação de solicitação não revela se o e-mail existe.
- R-35 PASS: TypeScript e build de produção passaram; `/reset-password` aparece na lista de rotas geradas.
- Onboarding PASS: `/login?invite=1` abriu `/onboarding` em teste no navegador; Supabase confirmou o salvamento do novo Site URL.

Limite da verificação: não foi enviado e-mail para uma pessoa nem alterada a senha de uma conta real. O recebimento do e-mail, consumo de um token real e salvamento final da senha ainda precisam ser exercitados pelo titular da conta. O SMTP do projeto e os limites de envio do Supabase continuam se aplicando.
