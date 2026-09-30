-- All fixtures, broadcasts, and state transitions are rolled back.
begin;
do $$
declare
  test_user uuid := gen_random_uuid();
  company_a uuid; company_b uuid; connection_id uuid;
  original_cases bigint := (select count(*) from public.vulnerability_cases);
  original_findings bigint := (select count(*) from public.wazuh_findings);
begin
  perform set_config('request.jwt.claims','{"role":"service_role"}',true);
  insert into auth.users(id,email,aud,role) values(test_user,'admin-test-'||test_user::text||'@example.invalid','authenticated','authenticated');
  insert into public.companies(name,slug) values('Admin test A','admin-test-a-'||test_user::text) returning id into company_a;
  insert into public.companies(name,slug) values('Admin test B','admin-test-b-'||test_user::text) returning id into company_b;
  insert into public.company_memberships(company_id,user_id,role) values(company_a,test_user,'viewer');
  insert into public.wazuh_connections(name,mode,tenant_id,endpoint_url) values('Admin test source','dedicated',company_a,'https://never-broadcast.example.invalid') returning id into connection_id;
  perform set_config('pier.test_company',company_a::text,true);
  perform set_config('pier.test_other_company',company_b::text,true);
  perform set_config('pier.test_user',test_user::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',test_user)::text,true);
  if not private.has_company_membership(company_a) or private.has_company_membership(company_b) or private.is_internal_admin() then raise exception 'Tenant isolation failed'; end if;
  update public.companies set is_active=false where id=company_a;
  if private.has_company_membership(company_a) then raise exception 'Inactive company still accessible'; end if;
  update public.companies set is_active=true where id=company_a;
  if not private.has_company_membership(company_a) then raise exception 'Company reactivation failed'; end if;
  update public.company_memberships set is_active=false where company_id=company_a and user_id=test_user;
  if private.has_company_membership(company_a) then raise exception 'Inactive membership still accessible'; end if;
  update public.company_memberships set is_active=true where company_id=company_a and user_id=test_user;
  update public.wazuh_connections set is_active=false where id=connection_id;
  if private.can_access_connection(connection_id) then raise exception 'Inactive connection still accessible'; end if;
  perform set_config('request.jwt.claims','{"role":"service_role"}',true);
  begin
    perform public.register_wazuh_sync(connection_id,'test');
    raise exception 'Inactive connection accepted ingestion';
  exception when no_data_found then null;
  end;
  update public.wazuh_connections set is_active=true where id=connection_id;
  perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',test_user)::text,true);
  if not private.can_access_connection(connection_id) then raise exception 'Connection reactivation failed'; end if;
  if (select count(*) from public.vulnerability_cases) <> original_cases or (select count(*) from public.wazuh_findings) <> original_findings then raise exception 'Historical data changed'; end if;
  if exists(select 1 from realtime.messages where topic='pier-admin' and payload::text like '%never-broadcast%') then raise exception 'Endpoint leaked into broadcast'; end if;
end;
$$;

set local role authenticated;
do $$
begin
  if not exists(select 1 from public.companies where id=current_setting('pier.test_company')::uuid) then raise exception 'Client cannot read own company'; end if;
  if exists(select 1 from public.companies where id=current_setting('pier.test_other_company')::uuid) then raise exception 'Client can read another company'; end if;
  begin
    perform public.admin_panel_data();
    raise exception 'Client accessed administrative Auth data';
  exception when insufficient_privilege then null;
  end;
  if exists(select 1 from realtime.messages where topic='pier-admin') then raise exception 'Client received admin-only broadcasts'; end if;
end;
$$;
reset role;
rollback;
