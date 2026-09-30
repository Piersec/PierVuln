create or replace function public.add_internal_admin_invite(
  p_user_id uuid,
  p_created_by uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.jwt()->>'role') is distinct from 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;

  insert into private.internal_admins (user_id, created_by)
  values (p_user_id, p_created_by)
  on conflict (user_id) do nothing;
end;
$$;

revoke all on function public.add_internal_admin_invite(uuid, uuid) from public, anon, authenticated;
grant execute on function public.add_internal_admin_invite(uuid, uuid) to service_role;
