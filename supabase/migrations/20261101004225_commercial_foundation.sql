create table public.commercial_plans (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(btrim(name)) between 1 and 100),
  description text not null default '' check (length(description) <= 3000),
  setup_cents bigint not null check (setup_cents between 0 and 100000000000),
  monthly_cents bigint not null check (monthly_cents between 0 and 100000000000),
  limits jsonb not null default '{}' check (jsonb_typeof(limits) = 'object'),
  is_active boolean not null default false,
  updated_at timestamptz not null default now()
);
create table public.commercial_extras (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(btrim(name)) between 1 and 100),
  setup_cents bigint not null check (setup_cents between 0 and 100000000000),
  monthly_cents bigint not null check (monthly_cents between 0 and 100000000000),
  is_active boolean not null default false
);
create table public.commercial_leads (
  id uuid primary key default gen_random_uuid(),
  company_name text not null check (length(btrim(company_name)) between 1 and 200),
  contact_name text not null check (length(btrim(contact_name)) between 1 and 200),
  email text not null check (length(email) between 3 and 254 and position('@' in email) > 1),
  project_scope text not null default '' check (length(project_scope) <= 10000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table public.commercial_lead_terms (
  lead_id uuid primary key references public.commercial_leads(id) on delete restrict,
  plan_id uuid not null references public.commercial_plans(id) on delete restrict,
  extra_ids uuid[] not null default '{}',
  setup_cents bigint not null,
  monthly_cents bigint not null,
  pricing_snapshot jsonb not null,
  revision integer not null default 1,
  selected_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);
create table public.commercial_audit_events (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id) on delete set null,
  entity_table text not null,
  entity_id uuid not null,
  action text not null,
  created_at timestamptz not null default now()
);
create index commercial_audit_entity_idx on public.commercial_audit_events(entity_id, created_at desc);

alter table public.commercial_plans enable row level security;
alter table public.commercial_extras enable row level security;
alter table public.commercial_leads enable row level security;
alter table public.commercial_lead_terms enable row level security;
alter table public.commercial_audit_events enable row level security;
revoke all on public.commercial_plans, public.commercial_extras, public.commercial_leads,
  public.commercial_lead_terms, public.commercial_audit_events from public, anon, authenticated;
grant select, insert, update on public.commercial_plans, public.commercial_extras, public.commercial_leads to authenticated;
grant select on public.commercial_lead_terms, public.commercial_audit_events to authenticated;
grant all on public.commercial_plans, public.commercial_extras, public.commercial_leads,
  public.commercial_lead_terms, public.commercial_audit_events to service_role;
create policy commercial_plans_admin on public.commercial_plans to authenticated
  using ((select private.is_internal_admin())) with check ((select private.is_internal_admin()));
create policy commercial_extras_admin on public.commercial_extras to authenticated
  using ((select private.is_internal_admin())) with check ((select private.is_internal_admin()));
create policy commercial_leads_admin on public.commercial_leads to authenticated
  using ((select private.is_internal_admin())) with check ((select private.is_internal_admin()));
create policy commercial_terms_admin on public.commercial_lead_terms for select to authenticated
  using ((select private.is_internal_admin()));
create policy commercial_audit_admin on public.commercial_audit_events for select to authenticated
  using ((select private.is_internal_admin()));

create function private.audit_commercial_change() returns trigger language plpgsql
security definer set search_path = '' as $$
begin
  if tg_table_name in ('commercial_leads', 'commercial_plans') then new.updated_at := now(); end if;
  insert into public.commercial_audit_events(actor_id, entity_table, entity_id, action)
    values (auth.uid(), tg_table_name, new.id, lower(tg_op));
  return new;
end;
$$;
revoke all on function private.audit_commercial_change() from public, anon, authenticated;
create trigger commercial_plan_audit before insert or update on public.commercial_plans
  for each row execute function private.audit_commercial_change();
create trigger commercial_extra_audit before insert or update on public.commercial_extras
  for each row execute function private.audit_commercial_change();
create trigger commercial_lead_audit before insert or update on public.commercial_leads
  for each row execute function private.audit_commercial_change();

create function public.set_commercial_lead_selection(p_lead_id uuid, p_plan_id uuid, p_extra_ids uuid[] default '{}')
returns public.commercial_lead_terms language plpgsql security definer set search_path = '' as $$
declare
  v_plan public.commercial_plans;
  v_result public.commercial_lead_terms;
  v_ids uuid[];
  v_extras jsonb;
  v_setup bigint := 0;
  v_monthly bigint := 0;
  v_count integer;
begin
  if not private.is_internal_admin() then raise exception 'Acesso administrativo necessário' using errcode = '42501'; end if;
  perform 1 from public.commercial_leads where id = p_lead_id for update;
  if not found then raise exception 'Lead inexistente'; end if;
  select * into v_plan from public.commercial_plans where id = p_plan_id and is_active for share;
  if not found then raise exception 'Plano inexistente ou inativo'; end if;
  select coalesce(array_agg(distinct x), '{}'::uuid[]) into v_ids from unnest(coalesce(p_extra_ids, '{}'::uuid[])) x;
  if cardinality(v_ids) > 50 then raise exception 'Limite de adicionais excedido'; end if;
  perform 1 from public.commercial_extras where id = any(v_ids) for share;
  select count(*), coalesce(sum(setup_cents),0), coalesce(sum(monthly_cents),0), coalesce(jsonb_agg(to_jsonb(e)), '[]'::jsonb)
    into v_count, v_setup, v_monthly, v_extras from public.commercial_extras e where id = any(v_ids) and is_active;
  if v_count <> cardinality(v_ids) then raise exception 'Adicional inexistente ou inativo'; end if;
  insert into public.commercial_lead_terms(lead_id, plan_id, extra_ids, setup_cents, monthly_cents, pricing_snapshot, selected_by)
    values (p_lead_id, p_plan_id, v_ids, v_plan.setup_cents + v_setup, v_plan.monthly_cents + v_monthly,
      jsonb_build_object('plan',to_jsonb(v_plan),'extras',v_extras,'currency','BRL'), auth.uid())
    on conflict (lead_id) do update set plan_id=excluded.plan_id, extra_ids=excluded.extra_ids,
      setup_cents=excluded.setup_cents, monthly_cents=excluded.monthly_cents, pricing_snapshot=excluded.pricing_snapshot,
      revision=commercial_lead_terms.revision+1, selected_by=excluded.selected_by, updated_at=now()
    returning * into v_result;
  insert into public.commercial_audit_events(actor_id, entity_table, entity_id, action)
    values(auth.uid(),'commercial_lead_terms',p_lead_id,'selection_updated');
  return v_result;
end;
$$;
revoke all on function public.set_commercial_lead_selection(uuid,uuid,uuid[]) from public, anon;
grant execute on function public.set_commercial_lead_selection(uuid,uuid,uuid[]) to authenticated;
