create table public.vulnerability_overview_snapshots (
  tenant_id uuid primary key references public.companies(id) on delete cascade,
  overview jsonb not null,
  source_marker jsonb not null,
  refreshed_at timestamptz not null default now(),
  stale boolean not null default false
);
alter table public.vulnerability_overview_snapshots enable row level security;
create policy vulnerability_overview_snapshots_read on public.vulnerability_overview_snapshots
for select to authenticated
using ((select private.is_internal_admin()) or private.has_company_membership(tenant_id));
revoke all on public.vulnerability_overview_snapshots from public, anon, authenticated, service_role;
grant select on public.vulnerability_overview_snapshots to authenticated;

alter function public.get_vulnerability_overview(uuid, text)
  rename to get_vulnerability_overview_live;

create function public.get_vulnerability_overview(
  p_company_id uuid default null,
  p_agent_name_prefix text default null
) returns setof jsonb
language plpgsql stable security definer set search_path = ''
as $$
declare
  v_overview jsonb;
begin
  if p_company_id is null then
    if not coalesce(private.is_internal_admin(), false) then
      raise exception 'Company scope is required' using errcode = '42501';
    end if;
  elsif not coalesce(private.is_internal_admin() or private.has_company_membership(p_company_id), false) then
    raise exception 'Company access required' using errcode = '42501';
  end if;

  if p_company_id is not null and p_agent_name_prefix is null then
    select s.overview into v_overview
    from public.vulnerability_overview_snapshots s
    where s.tenant_id = p_company_id;
    if found then
      return next v_overview;
      return;
    end if;
  end if;

  return query
    select live.overview
    from public.get_vulnerability_overview_live(p_company_id, p_agent_name_prefix) as live(overview);
end;
$$;
revoke all on function public.get_vulnerability_overview(uuid, text) from public, anon;
grant execute on function public.get_vulnerability_overview(uuid, text) to authenticated;

create function private.refresh_next_vulnerability_overview_snapshot()
returns uuid language plpgsql security definer set search_path = ''
as $$
declare
  v_tenant_id uuid;
  v_source_marker jsonb;
  v_overview jsonb;
begin
  if not pg_try_advisory_xact_lock(20261006, 1) then return null; end if;

  select coalesce(jsonb_agg(jsonb_build_array(c.id::text, c.published_sync_run_id::text) order by c.id), '[]'::jsonb)
  into v_source_marker
  from public.wazuh_connections c;

  select c.id into v_tenant_id
  from public.companies c
  left join public.vulnerability_overview_snapshots s on s.tenant_id = c.id
  where s.tenant_id is null or s.stale or s.source_marker is distinct from v_source_marker
  order by s.refreshed_at nulls first, c.id
  limit 1;
  if v_tenant_id is null then return null; end if;

  select live.overview into v_overview
  from public.get_vulnerability_overview_live(v_tenant_id, null) as live(overview)
  limit 1;
  if v_overview is null then return null; end if;

  insert into public.vulnerability_overview_snapshots (tenant_id, overview, source_marker, refreshed_at, stale)
  values (v_tenant_id, v_overview, v_source_marker, now(), false)
  on conflict (tenant_id) do update set
    overview = excluded.overview,
    source_marker = excluded.source_marker,
    refreshed_at = excluded.refreshed_at,
    stale = false;
  return v_tenant_id;
end;
$$;
revoke all on function private.refresh_next_vulnerability_overview_snapshot() from public, anon, authenticated, service_role;

create function private.mark_overview_snapshots_stale()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  update public.vulnerability_overview_snapshots set stale = true;
  return null;
end;
$$;
revoke all on function private.mark_overview_snapshots_stale() from public, anon, authenticated, service_role;
create trigger vulnerability_overview_snapshots_stale
after update of workflow_status on public.vulnerability_cases
for each statement execute function private.mark_overview_snapshots_stale();

do $$
begin
  if not exists (select 1 from cron.job where jobname = 'piervuln-normalize-content') then
    raise exception 'piervuln-normalize-content job is missing';
  end if;
  perform cron.alter_job(jobid, schedule := '*/2 * * * *')
  from cron.job where jobname = 'piervuln-normalize-content';
end;
$$;
select cron.schedule('piervuln-refresh-overview-snapshots', '1-59/2 * * * *',
  $job$set statement_timeout = '5min'; set lock_timeout = '1s'; select private.refresh_next_vulnerability_overview_snapshot();$job$);
notify pgrst, 'reload schema';
