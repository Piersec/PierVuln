create table public.asset_classifications (
  tenant_id uuid not null references public.companies(id),
  agent_key text not null check (length(agent_key) between 1 and 256),
  is_critical boolean not null default false,
  primary key (tenant_id, agent_key)
);
alter table public.asset_classifications enable row level security;
create policy asset_classifications_read on public.asset_classifications for select to authenticated
using ((select private.is_internal_admin()) or private.has_company_membership(tenant_id));
create policy asset_classifications_insert on public.asset_classifications for insert to authenticated
with check ((select private.is_internal_admin()) or private.has_company_role(tenant_id, array['owner','admin','analyst']));
create policy asset_classifications_update on public.asset_classifications for update to authenticated
using ((select private.is_internal_admin()) or private.has_company_role(tenant_id, array['owner','admin','analyst']))
with check ((select private.is_internal_admin()) or private.has_company_role(tenant_id, array['owner','admin','analyst']));
grant select, insert, update on public.asset_classifications to authenticated;

create index if not exists findings_tenant_cve_idx on public.wazuh_findings (tenant_id, vulnerability_id);

create function public.get_kanban_groups(p_company_id uuid default null, p_search text default '')
returns jsonb language sql stable security invoker
set work_mem = '16MB' set plan_cache_mode = 'force_custom_plan'
as $body$
  with scoped as materialized (
    select c.tenant_id, upper(f.vulnerability_id) as cve, f.cvss_base,
      coalesce(nullif(f.agent_id,''),nullif(f.agent_name,'')) as agent_key,
      f.agent_name, f.first_detected_at,
      f.source_state = 'active' and c.workflow_status <> 'resolved' as active,
      c.workflow_status::text as workflow
    from public.wazuh_findings f
    join public.vulnerability_cases c on c.finding_id=f.id and c.tenant_id=f.tenant_id
    where p_company_id is null or c.tenant_id=p_company_id
  ), grouped as (
    select s.tenant_id, s.cve, max(s.cvss_base) as cvss,
      count(*) as cases, count(distinct s.agent_key) as hosts,
      min(s.first_detected_at) as first_detected,
      bool_or(coalesce(a.is_critical,false)) as critical_asset,
      case when not bool_or(s.active) then 'resolved'
        when bool_or(s.active and s.workflow='awaiting_validation') then 'awaiting_validation'
        when bool_or(s.active and s.workflow='in_progress') then 'in_progress'
        else 'open' end as status
    from scoped s left join public.asset_classifications a on a.tenant_id=s.tenant_id and a.agent_key=s.agent_key
    group by s.tenant_id,s.cve
    having p_search='' or bool_or(s.cve ilike '%'||p_search||'%' or s.agent_name ilike '%'||p_search||'%')
  )
  select coalesce(jsonb_agg(jsonb_build_object('key',tenant_id||':'||cve,'tenantId',tenant_id,'cve',cve,
    'cvss',cvss,'severity',case when cvss>=9 then 'Critical' when cvss>=7 then 'High'
      when cvss>=4 then 'Medium' when cvss>=1 then 'Low' when cvss=0 then 'Informational' else 'Unknown' end,
    'hostCount',hosts,'caseCount',cases,'firstDetected',first_detected,'criticalAsset',critical_asset,'status',status)
    order by tenant_id,cve),'[]'::jsonb) from grouped;
$body$;
revoke all on function public.get_kanban_groups(uuid,text) from public,anon;
grant execute on function public.get_kanban_groups(uuid,text) to authenticated;

create function public.move_kanban_group(p_company_id uuid, p_cve text, p_status text)
returns integer language plpgsql security invoker set search_path = public
as $body$
declare changed integer;
begin
  if p_status not in ('open','in_progress','awaiting_validation') then raise exception 'Etapa inválida'; end if;
  if not (private.is_internal_admin() or private.has_company_role(p_company_id,array['owner','admin','analyst'])) then
    raise exception 'Sem permissão para alterar esta empresa' using errcode='42501';
  end if;
  update public.vulnerability_cases c set workflow_status=p_status::public.vulnerability_workflow_status
  from public.wazuh_findings f
  where c.finding_id=f.id and c.tenant_id=p_company_id and f.tenant_id=p_company_id
    and upper(f.vulnerability_id)=upper(p_cve) and f.source_state='active' and c.workflow_status<>'resolved';
  get diagnostics changed=row_count;
  return changed;
end;
$body$;
revoke all on function public.move_kanban_group(uuid,text,text) from public,anon;
grant execute on function public.move_kanban_group(uuid,text,text) to authenticated;
create or replace function public.get_vulnerability_overview(
  p_company_id uuid default null, p_agent_name_prefix text default null
) returns setof jsonb
language sql stable security invoker
set work_mem = '16MB'
set plan_cache_mode = 'force_custom_plan'
as $overview$

  with scoped_findings as materialized (
    select f.id, f.tenant_id, f.vulnerability_id, case when f.cvss_base >= 9 then 'Critical' when f.cvss_base >= 7 then 'High' when f.cvss_base >= 4 then 'Medium' when f.cvss_base >= 1 then 'Low' when f.cvss_base = 0 then 'Informational' else 'Unknown' end as severity, f.cvss_base,
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


