create or replace function public.can_delete_user_account(p_user_id uuid)
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select not (
    exists (select 1 from private.internal_admins where user_id = p_user_id)
    and (select count(*) from private.internal_admins) <= 1
  );
$$;

revoke all on function public.can_delete_user_account(uuid) from public, anon, authenticated;
grant execute on function public.can_delete_user_account(uuid) to service_role;
