create index if not exists wazuh_findings_tenant_active_id_idx
  on public.wazuh_findings (tenant_id, id)
  where source_state = 'active';

create or replace function public.get_report_export_batch(
  p_company_id uuid,
  p_after_id uuid default null,
  p_limit integer default 5000
)
returns jsonb
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce(
    jsonb_agg(to_jsonb(batch_row) order by batch_row.finding_id),
    '[]'::jsonb
  )
  from (
    select
      f.id as finding_id,
      coalesce(c.workflow_status::text, 'open') as workflow_status,
      f.agent_id as finding_agent_id,
      f.agent_name as finding_agent_name,
      f.host_os as finding_host_os,
      f.package_name as finding_package_name,
      f.package_version as finding_package_version,
      f.vulnerability_id as finding_vulnerability_id,
      case when f.content_id is null then f.description else content.description end as finding_description,
      f.cvss_base as finding_cvss_base,
      case when f.content_id is null then f.reference_urls else content.reference_urls end as finding_reference_urls,
      f.first_detected_at as finding_first_detected_at,
      f.last_seen_at as finding_last_seen_at
    from public.wazuh_findings as f
    left join public.vulnerability_cases as c
      on c.finding_id = f.id and c.tenant_id = f.tenant_id
    left join public.finding_content as content
      on content.id = f.content_id
    where f.tenant_id = p_company_id
      and f.source_state = 'active'
      and f.id > coalesce(p_after_id, '00000000-0000-0000-0000-000000000000'::uuid)
    order by f.id
    limit least(greatest(coalesce(p_limit, 5000), 1), 5000)
  ) as batch_row;
$$;

revoke all on function public.get_report_export_batch(uuid, uuid, integer)
  from public, anon;
grant execute on function public.get_report_export_batch(uuid, uuid, integer)
  to authenticated;

notify pgrst, 'reload schema';
