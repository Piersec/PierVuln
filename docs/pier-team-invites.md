# Convites da Equipe Pier

Um convite administrativo enviado em Authentication > Users do Supabase para
`@piersec.com.br` atribui automaticamente o acesso de administrador interno.
O vínculo é criado quando o Auth grava `invited_at`, na mesma transação do convite.
Não depende da conclusão do onboarding nem de atualizar o token do usuário.

Convites corporativos existentes são regularizados pela migração
`pier_direct_auth_invites`. O cadastro comum, os convites para outros domínios
e campos como `role` em `user_metadata` não concedem esse acesso.
O domínio precisa ser exatamente `piersec.com.br`.

O formulário Equipe Pier do PierVuln continua concedendo o acesso pelo backend
administrativo; ele também permite convidar membros com outros domínios.
O vínculo em `private.internal_admins` permanece a fonte das permissões.

Para conferir os cenários no banco, executar
`supabase/tests/pier_auth_invites.sql`. O teste cria contas temporárias sem enviar
e-mail e usa rollback para não deixar usuários nem permissões de teste gravados.
