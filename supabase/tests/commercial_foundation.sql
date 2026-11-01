-- Execute with a database administrator. All fixture rows are rolled back.
begin;
do $$
declare
  v_user uuid;
  v_plan uuid;
  v_extra uuid;
  v_lead uuid;
  v_terms public.commercial_lead_terms;
begin
  select user_id into v_user from private.internal_admins limit 1;
  if v_user is null then raise exception 'An internal administrator is required'; end if;
  perform set_config('request.jwt.claim.sub', v_user::text, true);
  insert into public.commercial_plans(name, setup_cents, monthly_cents, is_active)
    values ('Validation fixture',150000,14900,true) returning id into v_plan;
  insert into public.commercial_extras(name, setup_cents, monthly_cents, is_active)
    values ('Validation fixture',1000,2000,true) returning id into v_extra;
  insert into public.commercial_leads(company_name,contact_name,email)
    values ('Validation fixture','Validation','validation@example.invalid') returning id into v_lead;
  select * into v_terms from public.set_commercial_lead_selection(v_lead,v_plan,array[v_extra,v_extra]);
  if v_terms.setup_cents <> 151000 or v_terms.monthly_cents <> 16900 or cardinality(v_terms.extra_ids) <> 1 then
    raise exception 'Incorrect server-side total or duplicated extra';
  end if;
  if has_table_privilege('anon','public.commercial_leads','select')
    or has_table_privilege('authenticated','public.commercial_lead_terms','update') then
    raise exception 'Unexpected commercial privilege';
  end if;
end;
$$;
set local role authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000000',true);
do $$
begin
  if (select count(*) from public.commercial_leads) <> 0 then raise exception 'RLS did not isolate leads'; end if;
  begin
    perform public.set_commercial_lead_selection(null,null,'{}');
    raise exception 'Missing authorization guard';
  exception when insufficient_privilege then null;
  end;
end;
$$;
rollback;
