set local lock_timeout = '3s';

create table private.company_storage_snapshot (
  singleton boolean primary key default true check (singleton),
  payload jsonb not null,
  measured_at timestamptz not null
);
alter table private.company_storage_snapshot enable row level security;
create policy company_storage_snapshot_deny_external on private.company_storage_snapshot
  for all to anon, authenticated using (false) with check (false);
revoke all on private.company_storage_snapshot from public, anon, authenticated;

create function private.refresh_company_storage_snapshot()
returns void language plpgsql security definer set search_path = ''
as $$
declare
  v_payload jsonb;
  v_started_at timestamptz := statement_timestamp();
begin
  if not pg_try_advisory_xact_lock(hashtextextended('company_storage_snapshot', 0)) then
    return;
  end if;

  with per_tenant as materialized (
    select 'findings' as kind, tenant_id, count(*) as records,
      sum(pg_column_size(f)::bigint) as row_bytes
    from public.wazuh_findings f group by tenant_id
    union all
    select 'cases', tenant_id, count(*), sum(pg_column_size(c)::bigint)
    from public.vulnerability_cases c group by tenant_id
    union all
    select 'events', tenant_id, count(*), sum(pg_column_size(e)::bigint)
    from public.finding_events e group by tenant_id
    union all
    select 'comments', tenant_id, count(*), sum(pg_column_size(c)::bigint)
    from public.vulnerability_comments c group by tenant_id
  ), sizes as (
    select 'findings' as kind, pg_total_relation_size('public.wazuh_findings') as physical
    union all select 'cases', pg_total_relation_size('public.vulnerability_cases')
    union all select 'events', pg_total_relation_size('public.finding_events')
    union all select 'comments', pg_total_relation_size('public.vulnerability_comments')
  ), weighted as (
    select p.*,
      round(s.physical * p.row_bytes::numeric /
        nullif(sum(p.row_bytes) over (partition by p.kind), 0))::bigint as allocated_bytes
    from per_tenant p join sizes s using (kind)
  ), companies as (
    select c.id as tenant_id,
      coalesce(sum(w.row_bytes), 0)::bigint as data_bytes,
      coalesce(sum(w.allocated_bytes), 0)::bigint as allocated_bytes,
      coalesce(sum(w.records) filter (where w.kind = 'findings'), 0)::bigint as finding_count
    from public.companies c left join weighted w on w.tenant_id = c.id
    group by c.id
  )
  select jsonb_build_object(
    'measured_at', v_started_at,
    'database_bytes', pg_database_size(current_database()),
    'refresh_seconds', 300,
    'companies', coalesce((select jsonb_agg(to_jsonb(c) order by tenant_id) from companies c), '[]'::jsonb)
  ) into v_payload;

  insert into private.company_storage_snapshot (singleton, payload, measured_at)
  values (true, v_payload, v_started_at)
  on conflict (singleton) do update
    set payload = excluded.payload, measured_at = excluded.measured_at;
end;
$$;
revoke all on function private.refresh_company_storage_snapshot() from public, anon, authenticated, service_role;

create function public.get_company_storage_usage()
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
begin
  if auth.uid() is null or not private.is_internal_admin() then
    raise exception 'Administrative access required' using errcode = '42501';
  end if;
  return (select payload from private.company_storage_snapshot where singleton);
end;
$$;
revoke all on function public.get_company_storage_usage() from public, anon, authenticated;
grant execute on function public.get_company_storage_usage() to authenticated;

select cron.schedule('piervuln-company-storage', '*/5 * * * *',
  $job$set statement_timeout = '45s'; set lock_timeout = '1s'; select private.refresh_company_storage_snapshot();$job$);
notify pgrst, 'reload schema';

