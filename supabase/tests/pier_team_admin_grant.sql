begin;

insert into auth.users (id, email)
values ('00000000-0000-4000-8000-000000000901', 'pier-team-grant@example.test');

set local role service_role;
select set_config('request.jwt.claim.role', '', true);
select set_config('request.jwt.claims', '{"role":"service_role"}', true);

select public.add_internal_admin_invite('00000000-0000-4000-8000-000000000901', null);
select public.add_internal_admin_invite('00000000-0000-4000-8000-000000000901', null);

reset role;
do $$
begin
  if (select count(*) from private.internal_admins where user_id = '00000000-0000-4000-8000-000000000901') <> 1 then
    raise exception 'Pier invitation must grant administrator access exactly once';
  end if;
end;
$$;

select set_config('request.jwt.claims', '{"sub":"00000000-0000-4000-8000-000000000901","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '00000000-0000-4000-8000-000000000901', true);
set local role authenticated;

do $$
begin
  if (public.current_user_context()->>'is_internal_admin')::boolean is distinct from true then
    raise exception 'Invited Pier user must be recognized as an administrator';
  end if;
  begin
    perform public.add_internal_admin_invite('00000000-0000-4000-8000-000000000901', null);
    raise exception 'Browser users must not be able to grant internal access';
  exception when insufficient_privilege then
    null;
  end;
end;
$$;

reset role;
do $$
begin
  begin
    perform public.add_internal_admin_invite('00000000-0000-4000-8000-000000000901', null);
    raise exception 'Grant function must reject an authenticated JWT even under elevated SQL privileges';
  exception when insufficient_privilege then
    null;
  end;
end;
$$;

rollback;
