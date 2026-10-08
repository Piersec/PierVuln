create function public.get_vulnerability_overview_period(
  p_company_id uuid,
  p_agent_name_prefix text,
  p_start timestamptz,
  p_end timestamptz
) returns setof jsonb
language plpgsql stable security definer set search_path = ''
as $$
begin
  if p_start is null or p_end is null or p_start >= p_end or p_end - p_start > interval '367 days' then
    raise exception 'Invalid dashboard period' using errcode = '22023';
  end if;
  if p_company_id is null then
    if not coalesce(private.is_internal_admin(), false) then
      raise exception 'Company scope is required' using errcode = '42501';
    end if;
  elsif not coalesce(private.is_internal_admin() or private.has_company_membership(p_company_id), false) then
    raise exception 'Company access required' using errcode = '42501';
  end if;

  return query
  with scoped_findings as materialized (
    select f.id, f.tenant_id, f.vulnerability_id,
      case when f.cvss_base >= 9 then 'Critical' when f.cvss_base >= 7 then 'High'
        when f.cvss_base >= 4 then 'Medium' when f.cvss_base >= 1 then 'Low'
        when f.cvss_base = 0 then 'Informational' else 'Unknown' end as severity,
      f.cvss_base, f.agent_id, f.agent_name, f.first_detected_at, f.source_state, f.resolved_at
    from public.wazuh_findings f
    where f.tenant_id is not null
      and (p_company_id is null or f.tenant_id = p_company_id)
      and (p_agent_name_prefix is null or f.agent_name like p_agent_name_prefix || '%')
      and ((f.source_state = 'active' and f.first_detected_at >= p_start and f.first_detected_at < p_end)
        or (f.source_state = 'resolved' and f.resolved_at >= p_start and f.resolved_at < p_end))
  ), active as materialized (
    select *, greatest(0, floor(extract(epoch from (now() - first_detected_at)) / 86400)) as age_days
    from scoped_findings where source_state = 'active'
  ), case_workflow as (
    select c.workflow_status from public.vulnerability_cases c
    join active a on a.id = c.finding_id and a.tenant_id = c.tenant_id
    where c.workflow_status in ('in_progress', 'awaiting_validation')
  ), severity_counts as (
    select severity, count(*) as total from active group by severity
  ), age_counts as (
    select case when age_days <= 7 then 0 when age_days <= 30 then 1 when age_days <= 90 then 2 else 3 end as band,
      severity, count(*) as total from active group by 1, 2
  ), trend_counts as (
    select case when p_end - p_start > interval '31 days'
        then to_char(first_detected_at at time zone 'America/Sao_Paulo', 'YYYY-MM')
        else to_char(first_detected_at at time zone 'America/Sao_Paulo', 'YYYY-MM-DD') end as bucket,
      severity, count(*) as total from active group by 1, 2
  ), cve_groups as (
    select tenant_id, upper(vulnerability_id) as cve, coalesce(max(cvss_base), 0) as cvss,
      (array['Informational','Low','Medium','High','Critical'])[greatest(1, max(
        case severity when 'Critical' then 5 when 'High' then 4 when 'Medium' then 3 when 'Low' then 2 else 1 end
      ))] as severity,
      count(*) as cases,
      count(distinct coalesce(nullif(agent_id, ''), nullif(agent_name, ''))) as hosts
    from active group by tenant_id, upper(vulnerability_id)
  )
  select jsonb_build_object(
    'activeCount', (select count(*) from active),
    'caseCount', (select count(*) from active),
    'criticalHighCount', (select count(*) from active where severity in ('Critical', 'High')),
    'inProgressCount', (select count(*) from case_workflow),
    'corrected30', (select count(*) from scoped_findings where source_state = 'resolved'),
    'severityCounts', coalesce((select jsonb_object_agg(severity, total) from severity_counts), '{}'::jsonb),
    'ageCounts', coalesce((select jsonb_agg(jsonb_build_object('band', band, 'severity', severity, 'count', total)) from age_counts), '[]'::jsonb),
    'monthCounts', '[]'::jsonb,
    'trendCounts', coalesce((select jsonb_agg(jsonb_build_object('bucket', bucket, 'severity', severity, 'count', total)) from trend_counts), '[]'::jsonb),
    'groups', coalesce((select jsonb_agg(jsonb_build_object(
      'tenantId', tenant_id, 'cve', cve, 'severity', severity, 'cvss', cvss,
      'caseCount', cases, 'hostCount', hosts
    ) order by tenant_id, cve) from cve_groups), '[]'::jsonb)
  );
end;
$$;
revoke all on function public.get_vulnerability_overview_period(uuid, text, timestamptz, timestamptz) from public, anon;
grant execute on function public.get_vulnerability_overview_period(uuid, text, timestamptz, timestamptz) to authenticated;
notify pgrst, 'reload schema';
