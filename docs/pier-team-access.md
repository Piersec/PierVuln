# Acesso da Equipe Pier

Todo usuário convidado pelo campo “Equipe Pier” recebe acesso de administrador interno. Esse vínculo é registrado em `private.internal_admins` pela função `public.add_internal_admin_invite`, chamada pela Edge Function `admin-actions` após a criação da conta no Supabase Auth.

Criar a conta no Auth, aceitar o convite ou ter um e-mail da Pier não concede esse acesso por si só. As regras de leitura e administração consultam o vínculo privado; não usam metadados editáveis pelo usuário nem o domínio do e-mail.

A migração `20260930173707_fix_pier_team_admin_grant.sql` corrige a validação do chamador para ler `auth.jwt()->>'role'`. A versão anterior consultava apenas `request.jwt.claim.role`, que pode estar vazio quando o PostgREST fornece as claims no formato JSON em `request.jwt.claims`. Nessas chamadas, o convite podia criar uma conta Auth sem concluir a concessão de acesso interno.

A função continua restrita ao `service_role` e pode ser chamada novamente para a mesma conta sem duplicar o vínculo. Nenhuma regra de isolamento de clientes foi alterada.

## Verificação

O teste transacional `supabase/tests/pier_team_admin_grant.sql` passou no projeto remoto e reverteu os registros de teste ao terminar. Ele verifica concessão com claims JSON, repetição sem duplicidade, reconhecimento como administrador e rejeição de chamadas autenticadas pelo navegador e pelo corpo da função.

Também foi verificado um usuário corrigido com o contexto `authenticated`: `current_user_context` retornou `is_internal_admin = true`, e as contagens visíveis de empresas, achados e casos coincidiram com as contagens totais do banco.

Após corrigir um vínculo ausente, atualize a página para recarregar o contexto de permissões. Não é necessário modificar a senha ou o token do usuário.
