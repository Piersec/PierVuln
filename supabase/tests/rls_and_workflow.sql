-- Transactional tenant-isolation smoke test. Safe to run with `supabase test db`:
-- all fixture records, including auth users, are rolled back at the end.
begin;

insert into auth.users (id, email)
values
  ('00000000-0000-4000-8000-000000000101', 'piergv-rls-a@example.test'),
  ('00000000-0000-4000-8000-000000000102', 'piergv-rls-b@example.test'),
  ('00000000-0000-4000-8000-000000000103', 'piergv-rls-internal@example.test');

insert into private.internal_admins (user_id)
values ('00000000-0000-4000-8000-000000000103');

insert into public.companies (id, name, slug)
values
  ('00000000-0000-4000-8000-000000000201', 'RLS Test A', 'rls-test-a'),
  ('00000000-0000-4000-8000-000000000202', 'RLS Test B', 'rls-test-b');

insert into public.company_memberships (company_id, user_id, role)
values
  ('00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000101', 'analyst'),
  ('00000000-0000-4000-8000-000000000202', '00000000-0000-4000-8000-000000000102', 'analyst');

insert into public.wazuh_connections (id, tenant_id, name, mode, endpoint_url)
values
  ('00000000-0000-4000-8000-000000000301', '00000000-0000-4000-8000-000000000201', 'Test A', 'dedicated', 'https://a.example.test:9200'),
  ('00000000-0000-4000-8000-000000000302', '00000000-0000-4000-8000-000000000202', 'Test B', 'dedicated', 'https://b.example.test:9200');

insert into public.wazuh_findings (
  id, connection_id, source_document_id, tenant_id, vulnerability_id, severity
)
values
  ('00000000-0000-4000-8000-000000000401', '00000000-0000-4000-8000-000000000301', 'test-source-a', '00000000-0000-4000-8000-000000000201', 'CVE-TEST-A', 'High'),
  ('00000000-0000-4000-8000-000000000402', '00000000-0000-4000-8000-000000000302', 'test-source-b', '00000000-0000-4000-8000-000000000202', 'CVE-TEST-B', 'Critical');

insert into public.vulnerability_cases (id, finding_id, tenant_id)
values
  ('00000000-0000-4000-8000-000000000501', '00000000-0000-4000-8000-000000000401', '00000000-0000-4000-8000-000000000201'),
  ('00000000-0000-4000-8000-000000000502', '00000000-0000-4000-8000-000000000402', '00000000-0000-4000-8000-000000000202');

insert into public.vulnerability_comments (
  id, case_id, finding_id, tenant_id, author_id, visibility, body
)
values
  ('00000000-0000-4000-8000-000000000601', '00000000-0000-4000-8000-000000000501', '00000000-0000-4000-8000-000000000401', '00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000101', 'shared', 'Shared test comment'),
  ('00000000-0000-4000-8000-000000000602', '00000000-0000-4000-8000-000000000501', '00000000-0000-4000-8000-000000000401', '00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000103', 'internal', 'Internal test note'),
  ('00000000-0000-4000-8000-000000000603', '00000000-0000-4000-8000-000000000502', '00000000-0000-4000-8000-000000000402', '00000000-0000-4000-8000-000000000202', '00000000-0000-4000-8000-000000000102', 'shared', 'Other tenant comment');

set local role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '00000000-0000-4000-8000-000000000101', true);
select set_config('request.jwt.claims', '{"sub":"00000000-0000-4000-8000-000000000101","role":"authenticated"}', true);

do $$
begin
  if (select count(*) from public.companies) <> 1 then
    raise exception 'Tenant A must see only its own company';
  end if;
  if (select count(*) from public.wazuh_findings) <> 1
     or (select vulnerability_id from public.wazuh_findings limit 1) <> 'CVE-TEST-A' then
    raise exception 'Tenant A must see only its own Wazuh finding';
  end if;
  if (select count(*) from public.vulnerability_comments) <> 1 then
    raise exception 'Tenant A must see the shared comment, not the internal note';
  end if;

  begin
    update public.vulnerability_cases
    set workflow_status = 'resolved'
    where id = '00000000-0000-4000-8000-000000000501';
    raise exception 'Customer must not resolve a case outside a complete Wazuh sync';
  exception when insufficient_privilege then
    null;
  end;

  begin
    insert into public.vulnerability_comments (
      case_id, finding_id, tenant_id, author_id, visibility, body
    ) values (
      '00000000-0000-4000-8000-000000000501',
      '00000000-0000-4000-8000-000000000401',
      '00000000-0000-4000-8000-000000000201',
      '00000000-0000-4000-8000-000000000101',
      'internal', 'Customer must not create a private note'
    );
    raise exception 'Customer must not create internal notes';
  exception when insufficient_privilege then
    null;
  end;
end;
$$;

select set_config('request.jwt.claim.sub', '00000000-0000-4000-8000-000000000102', true);
select set_config('request.jwt.claims', '{"sub":"00000000-0000-4000-8000-000000000102","role":"authenticated"}', true);
do $$
begin
  if (select count(*) from public.companies) <> 1
     or (select slug from public.companies limit 1) <> 'rls-test-b' then
    raise exception 'Tenant B must see only its own company';
  end if;
  if (select count(*) from public.vulnerability_cases) <> 1 then
    raise exception 'Tenant B must not see tenant A cases';
  end if;
end;
$$;

select set_config('request.jwt.claim.sub', '00000000-0000-4000-8000-000000000103', true);
select set_config('request.jwt.claims', '{"sub":"00000000-0000-4000-8000-000000000103","role":"authenticated"}', true);
do $$
begin
  if (select count(*) from public.companies) <> 2 then
    raise exception 'Internal admin must see both companies';
  end if;
  if (select count(*) from public.vulnerability_comments) <> 3 then
    raise exception 'Internal admin must see shared comments and private notes';
  end if;
  if (public.current_user_context() ->> 'is_internal_admin')::boolean is distinct from true then
    raise exception 'Current-user context must report the internal role';
  end if;
end;
$$;

reset role;
rollback;
