create index if not exists findings_overview_cover_idx
on public.wazuh_findings (tenant_id, source_state)
include (id, vulnerability_id, severity, cvss_base, agent_id, agent_name, first_detected_at, resolved_at);
create index if not exists cases_in_progress_overview_idx
on public.vulnerability_cases (tenant_id, finding_id)
where workflow_status in ('in_progress', 'awaiting_validation');

create or replace function public.get_vulnerability_overview(
  p_company_id uuid default null, p_agent_name_prefix text default null
) returns setof jsonb
language sql stable security invoker
set work_mem = '16MB'
set plan_cache_mode = 'force_custom_plan'
as $overview$

  with scoped_findings as materialized (
    select f.id, f.tenant_id, f.vulnerability_id, f.severity, f.cvss_base,
      f.agent_id, f.agent_name, f.first_detected_at, f.source_state, f.resolved_at
    from public.wazuh_findings f
    where f.tenant_id is not null
      and (p_company_id is null or f.tenant_id = p_company_id)
      and (p_agent_name_prefix is null or f.agent_name like p_agent_name_prefix || '%')
  ), active as materialized (
    select *, greatest(0, floor(extract(epoch from (now() - first_detected_at)) / 86400)) as age_days
    from scoped_findings
    where source_state = 'active'
  ), case_workflow as materialized (
    select c.finding_id, c.workflow_status
    from public.vulnerability_cases c
    join active a on a.id = c.finding_id and a.tenant_id = c.tenant_id
    where c.workflow_status in ('in_progress', 'awaiting_validation')
      and (p_company_id is null or c.tenant_id = p_company_id)
  ), severity_counts as (
    select severity, count(*) as total from active group by severity
  ), age_counts as (
    select case when age_days <= 7 then 0 when age_days <= 30 then 1 when age_days <= 90 then 2 else 3 end as band,
      severity, count(*) as total
    from active group by 1, 2
  ), month_counts as (
    select to_char(first_detected_at at time zone 'UTC', 'YYYY-MM') as month,
      severity, count(*) as total
    from active
    where first_detected_at >= date_trunc('month', now()) - interval '6 months'
    group by 1, 2
  ), cve_groups as (
    select tenant_id, upper(vulnerability_id) as cve, coalesce(max(cvss_base), 0) as cvss,
      (array['Informational','Low','Medium','High','Critical'])[greatest(1, max(
        case severity when 'Critical' then 5 when 'High' then 4 when 'Medium' then 3 when 'Low' then 2 else 1 end
      ))] as severity,
      count(*) as cases,
      count(distinct coalesce(nullif(agent_id, ''), nullif(agent_name, ''))) as hosts
    from active
    group by tenant_id, upper(vulnerability_id)
  )
  select jsonb_build_object(
    'activeCount', (select count(*) from active),
    'caseCount', (select count(*) from active),
    'criticalHighCount', (select count(*) from active where severity in ('Critical', 'High')),
    'inProgressCount', (select count(*) from case_workflow where workflow_status in ('in_progress', 'awaiting_validation')),
    'corrected30', (select count(*) from scoped_findings where source_state = 'resolved' and resolved_at >= now() - interval '30 days'),
    'severityCounts', coalesce((select jsonb_object_agg(severity, total) from severity_counts), '{}'::jsonb),
    'ageCounts', coalesce((select jsonb_agg(jsonb_build_object('band', band, 'severity', severity, 'count', total)) from age_counts), '[]'::jsonb),
    'monthCounts', coalesce((select jsonb_agg(jsonb_build_object('month', month, 'severity', severity, 'count', total)) from month_counts), '[]'::jsonb),
    'groups', coalesce((select jsonb_agg(jsonb_build_object(
      'tenantId', tenant_id, 'cve', cve, 'severity', severity, 'cvss', cvss,
      'caseCount', cases, 'hostCount', hosts
    ) order by tenant_id, cve) from cve_groups), '[]'::jsonb)
  );

$overview$;

