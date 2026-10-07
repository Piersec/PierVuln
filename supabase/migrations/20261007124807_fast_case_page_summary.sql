create or replace function public.get_vulnerability_case_summary(p_company_id uuid default null)
returns jsonb
language plpgsql stable security invoker set search_path = ''
as $$
declare
  v_summary jsonb;
  v_snapshot_count bigint;
begin
  if p_company_id is null then
    if not coalesce(private.is_internal_admin(), false) then
      raise exception 'Company scope is required' using errcode = '42501';
    end if;
  elsif not coalesce(private.is_internal_admin() or private.has_company_membership(p_company_id), false) then
    raise exception 'Company access required' using errcode = '42501';
  end if;

  with visible_snapshots as materialized (
    select s.overview, s.stale, s.refreshed_at
    from public.vulnerability_overview_snapshots s
    where p_company_id is null or s.tenant_id = p_company_id
  ), severity_totals as (
    select item.key, sum(item.value::bigint) as total
    from visible_snapshots snapshot
    cross join lateral jsonb_each_text(snapshot.overview->'severityCounts') item
    group by item.key
  )
  select count(*), jsonb_build_object(
    'caseCount', coalesce(sum((snapshot.overview->>'caseCount')::bigint), 0),
    'criticalHighCount', coalesce(sum((snapshot.overview->>'criticalHighCount')::bigint), 0),
    'inProgressCount', coalesce(sum((snapshot.overview->>'inProgressCount')::bigint), 0),
    'severityCounts', coalesce((
      select jsonb_object_agg(severity.key, severity.total)
      from severity_totals severity
    ), '{}'::jsonb),
    'refreshedAt', max(snapshot.refreshed_at),
    'stale', coalesce(bool_or(snapshot.stale), true)
  )
  into v_snapshot_count, v_summary
  from visible_snapshots snapshot;

  if v_snapshot_count = 0 then
    return null;
  end if;
  return v_summary;
end;
$$;

revoke all on function public.get_vulnerability_case_summary(uuid) from public, anon;
grant execute on function public.get_vulnerability_case_summary(uuid) to authenticated;
notify pgrst, 'reload schema';
