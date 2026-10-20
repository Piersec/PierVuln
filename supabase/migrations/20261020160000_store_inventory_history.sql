begin;

create table public.vulnerability_inventory_history (
  tenant_id uuid not null references public.companies(id) on delete cascade,
  granularity text not null check (granularity in ('weekly', 'monthly')),
  period_start date not null,
  period_end date not null,
  total_findings bigint not null check (total_findings >= 0),
  critical_count bigint not null check (critical_count >= 0),
  high_count bigint not null check (high_count >= 0),
  medium_count bigint not null check (medium_count >= 0),
  low_count bigint not null check (low_count >= 0),
  informational_count bigint check (informational_count is null or informational_count >= 0),
  unclassified_count bigint check (unclassified_count is null or unclassified_count >= 0),
  in_progress_count bigint check (in_progress_count is null or in_progress_count >= 0),
  source_kind text not null check (source_kind in ('report', 'overview_snapshot')),
  source_file text,
  source_sheet text,
  source_refreshed_at timestamptz,
  source_stale boolean,
  captured_at timestamptz not null default now(),
  primary key (tenant_id, granularity, period_start),
  check (period_end >= period_start),
  check (total_findings >= critical_count + high_count + medium_count + low_count
    + coalesce(informational_count, 0) + coalesce(unclassified_count, 0))
);

create index vulnerability_inventory_history_period_idx
  on public.vulnerability_inventory_history (granularity, period_start desc);

alter table public.vulnerability_inventory_history enable row level security;

create policy vulnerability_inventory_history_read
  on public.vulnerability_inventory_history
  for select to authenticated
  using (private.is_internal_admin() or private.has_company_membership(tenant_id));

revoke all on public.vulnerability_inventory_history from public, anon, authenticated;
grant select on public.vulnerability_inventory_history to authenticated;
grant all on public.vulnerability_inventory_history to service_role;

create or replace function private.capture_weekly_vulnerability_history()
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_period_start date := date_trunc('week', now() at time zone 'America/Sao_Paulo')::date;
  v_rows integer;
begin
  insert into public.vulnerability_inventory_history (
    tenant_id, granularity, period_start, period_end, total_findings,
    critical_count, high_count, medium_count, low_count,
    informational_count, unclassified_count, in_progress_count,
    source_kind, source_refreshed_at, source_stale, captured_at
  )
  select c.id, 'weekly', v_period_start, v_period_start + 6,
    coalesce((s.overview ->> 'activeCount')::bigint, 0),
    coalesce((s.overview -> 'severityCounts' ->> 'Critical')::bigint, 0),
    coalesce((s.overview -> 'severityCounts' ->> 'High')::bigint, 0),
    coalesce((s.overview -> 'severityCounts' ->> 'Medium')::bigint, 0),
    coalesce((s.overview -> 'severityCounts' ->> 'Low')::bigint, 0),
    coalesce((s.overview -> 'severityCounts' ->> 'Informational')::bigint, 0),
    coalesce((s.overview -> 'severityCounts' ->> 'Unknown')::bigint, 0),
    coalesce((s.overview ->> 'inProgressCount')::bigint, 0),
    'overview_snapshot', s.refreshed_at, s.stale, now()
  from public.companies c
  join public.vulnerability_overview_snapshots s on s.tenant_id = c.id
  where c.is_active
  on conflict (tenant_id, granularity, period_start) do update
  set period_end = excluded.period_end,
      total_findings = excluded.total_findings,
      critical_count = excluded.critical_count,
      high_count = excluded.high_count,
      medium_count = excluded.medium_count,
      low_count = excluded.low_count,
      informational_count = excluded.informational_count,
      unclassified_count = excluded.unclassified_count,
      in_progress_count = excluded.in_progress_count,
      source_kind = excluded.source_kind,
      source_refreshed_at = excluded.source_refreshed_at,
      source_stale = excluded.source_stale,
      captured_at = excluded.captured_at;

  get diagnostics v_rows = row_count;
  return v_rows;
end;
$$;

revoke all on function private.capture_weekly_vulnerability_history() from public, anon, authenticated;

insert into public.vulnerability_inventory_history (
  tenant_id, granularity, period_start, period_end, total_findings,
  critical_count, high_count, medium_count, low_count,
  informational_count, unclassified_count, source_kind, source_file, source_sheet
)
values
  ('040735bf-192b-4eb9-9ceb-fddaca25782c', 'monthly', '2026-02-01', '2026-02-28', 63452, 1052, 41618, 19218, 1564, null, null, 'report', 'vulnerabilidades - fevereiro a setembro.xlsx', 'FEVEREIRO'),
  ('040735bf-192b-4eb9-9ceb-fddaca25782c', 'monthly', '2026-04-01', '2026-04-30', 55776, 885, 38978, 15338, 575, null, null, 'report', 'vulnerabilidades - fevereiro a setembro.xlsx', 'ABRIL'),
  ('040735bf-192b-4eb9-9ceb-fddaca25782c', 'monthly', '2026-05-01', '2026-05-31', 132980, 3252, 90831, 36575, 2322, null, null, 'report', 'vulnerabilidades - fevereiro a setembro.xlsx', 'MAIO'),
  ('040735bf-192b-4eb9-9ceb-fddaca25782c', 'monthly', '2026-06-01', '2026-06-30', 182057, 9710, 109052, 60444, 2851, null, null, 'report', 'vulnerabilidades - fevereiro a setembro.xlsx', 'JUNHO'),
  ('040735bf-192b-4eb9-9ceb-fddaca25782c', 'monthly', '2026-07-01', '2026-07-31', 259889, 7769, 180504, 68509, 3107, null, null, 'report', 'vulnerabilidades - fevereiro a setembro.xlsx', 'JULHO'),
  ('040735bf-192b-4eb9-9ceb-fddaca25782c', 'monthly', '2026-08-01', '2026-08-31', 293908, 9630, 195417, 85119, 3742, null, null, 'report', 'vulnerabilidades - fevereiro a setembro.xlsx', 'AGOSTO'),
  ('040735bf-192b-4eb9-9ceb-fddaca25782c', 'monthly', '2026-09-01', '2026-09-30', 383103, 16525, 257781, 104107, 4690, null, null, 'report', 'vulnerabilidades - fevereiro a setembro.xlsx', 'SETEMBRO')
on conflict (tenant_id, granularity, period_start) do update
set period_end = excluded.period_end,
    total_findings = excluded.total_findings,
    critical_count = excluded.critical_count,
    high_count = excluded.high_count,
    medium_count = excluded.medium_count,
    low_count = excluded.low_count,
    informational_count = excluded.informational_count,
    unclassified_count = excluded.unclassified_count,
    in_progress_count = excluded.in_progress_count,
    source_kind = excluded.source_kind,
    source_file = excluded.source_file,
    source_sheet = excluded.source_sheet,
    source_refreshed_at = excluded.source_refreshed_at,
    source_stale = excluded.source_stale,
    captured_at = excluded.captured_at;

select private.capture_weekly_vulnerability_history();

do $$
declare
  v_job_id bigint;
begin
  for v_job_id in
    select jobid from cron.job where jobname = 'piervuln-weekly-inventory-history'
  loop
    perform cron.unschedule(v_job_id);
  end loop;

  perform cron.schedule(
    'piervuln-weekly-inventory-history',
    '0 6 * * 1',
    'set statement_timeout = ''30s''; set lock_timeout = ''1s''; select private.capture_weekly_vulnerability_history();'
  );
end;
$$;

notify pgrst, 'reload schema';
commit;
