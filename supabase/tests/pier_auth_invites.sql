begin;

-- Reproduce Auth's insert/update sequence without sending invitation emails.
insert into auth.users (id, email, invited_at, raw_user_meta_data) values
  (gen_random_uuid(), 'piervuln-test-direct-invite@piersec.com.br', now(), '{}'),
  (gen_random_uuid(), 'piervuln-test-delayed-invite@piersec.com.br', null, '{}'),
  (gen_random_uuid(), 'piervuln-test-signup@piersec.com.br', null, '{"role":"admin","is_internal_admin":true}'),
  (gen_random_uuid(), 'piervuln-test-external-invite@example.invalid', now(), '{"role":"admin"}'),
  (gen_random_uuid(), 'piervuln-test-suffix@piersec.com.br.example.invalid', now(), '{}');
update auth.users set invited_at=now()
where email='piervuln-test-delayed-invite@piersec.com.br';
update auth.users set invited_at=now()
where email='piervuln-test-direct-invite@piersec.com.br';

do $$
declare v_user_id uuid; v_context jsonb;
begin
  assert (select count(*) from private.internal_admins a join auth.users u on u.id=a.user_id
    where u.email in ('piervuln-test-direct-invite@piersec.com.br','piervuln-test-delayed-invite@piersec.com.br')) = 2,
    'Direct and delayed corporate invitations must grant admin once';
  assert not exists(select 1 from private.internal_admins a join auth.users u on u.id=a.user_id
    where u.email in ('piervuln-test-signup@piersec.com.br','piervuln-test-external-invite@example.invalid','piervuln-test-suffix@piersec.com.br.example.invalid')),
    'Signup, user metadata and unrelated domains must not grant admin';
  assert not has_function_privilege('authenticated','private.grant_pier_auth_invite()','execute'),
    'Users must not call the provisioning function';
  select id into v_user_id from auth.users where email='piervuln-test-delayed-invite@piersec.com.br';
  perform set_config('request.jwt.claims',jsonb_build_object('sub',v_user_id,'role','authenticated')::text,true);
  select public.current_user_context() into v_context;
  assert (v_context->>'is_internal_admin')::boolean, 'User context must recognize the granted admin';
  perform set_config('piervuln.test_expected_cases',(select count(*)::text from public.vulnerability_cases),true);
end;
$$;

set local role authenticated;
do $$
begin
  assert (public.current_user_context()->>'is_internal_admin')::boolean,
    'Authenticated admin must be recognized';
  assert (select count(*) from public.vulnerability_cases)=current_setting('piervuln.test_expected_cases')::bigint,
    'Admin must read the complete inventory through RLS';
end;
$$;
reset role;

select set_config('request.jwt.claims',jsonb_build_object('sub',id,'role','authenticated')::text,true)
from auth.users where email='piervuln-test-signup@piersec.com.br';
set local role authenticated;
do $$
begin
  assert not (public.current_user_context()->>'is_internal_admin')::boolean,
    'An ordinary corporate signup must remain non-admin';
  assert (select count(*) from public.vulnerability_cases)=0,
    'A signup without membership must not read the inventory';
end;
$$;
reset role;

rollback;
