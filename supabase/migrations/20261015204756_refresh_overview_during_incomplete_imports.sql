create or replace function private.vulnerability_overview_source_marker(p_tenant_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_array(
    connection.id::text,
    connection.published_sync_run_id::text,
    run.id::text,
    run.status::text,
    run.pages_received,
    run.documents_received
  ) order by connection.id), '[]'::jsonb)
  from public.wazuh_connections connection
  left join lateral (
    select sync_run.id, sync_run.status, sync_run.pages_received, sync_run.documents_received
    from public.sync_runs sync_run
    where sync_run.connection_id = connection.id
    order by sync_run.started_at desc, sync_run.id desc
    limit 1
  ) run on true
  where connection.tenant_id = p_tenant_id
     or (connection.mode = 'shared' and exists (
       select 1
       from public.wazuh_agent_mappings mapping
       where mapping.connection_id = connection.id
         and mapping.tenant_id = p_tenant_id
         and mapping.is_active
     ));
$$;

revoke all on function private.vulnerability_overview_source_marker(uuid)
  from public, anon, authenticated, service_role;

create or replace function private.refresh_next_vulnerability_overview_snapshot()
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_tenant_id uuid;
  v_source_marker jsonb;
  v_overview jsonb;
begin
  if not pg_try_advisory_xact_lock(20261006, 1) then return null; end if;

  select company.id into v_tenant_id
  from public.companies company
  left join public.vulnerability_overview_snapshots snapshot
    on snapshot.tenant_id = company.id
  where snapshot.tenant_id is null
     or snapshot.stale
     or snapshot.source_marker is distinct from
       private.vulnerability_overview_source_marker(company.id)
  order by snapshot.refreshed_at nulls first, company.id
  limit 1;
  if v_tenant_id is null then return null; end if;

  v_source_marker := private.vulnerability_overview_source_marker(v_tenant_id);
  select live.overview into v_overview
  from public.get_vulnerability_overview_live(v_tenant_id, null) as live(overview)
  limit 1;
  if v_overview is null then return null; end if;

  insert into public.vulnerability_overview_snapshots
    (tenant_id, overview, source_marker, refreshed_at, stale)
  values (v_tenant_id, v_overview, v_source_marker, now(), false)
  on conflict (tenant_id) do update set
    overview = excluded.overview,
    source_marker = excluded.source_marker,
    refreshed_at = excluded.refreshed_at,
    stale = false;
  return v_tenant_id;
end;
$$;

revoke all on function private.refresh_next_vulnerability_overview_snapshot()
  from public, anon, authenticated, service_role;

notify pgrst, 'reload schema';
