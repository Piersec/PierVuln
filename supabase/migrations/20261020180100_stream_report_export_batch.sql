drop function public.get_report_export_batch(uuid, uuid, integer);

create function public.get_report_export_batch(
  p_company_id uuid,
  p_after_id uuid default null,
  p_limit integer default 5000
)
returns table (
  finding_id uuid,
  workflow_status text,
  finding_agent_id text,
  finding_agent_name text,
  finding_host_os text,
  finding_package_name text,
  finding_package_version text,
  finding_vulnerability_id text,
  finding_description text,
  finding_cvss_base numeric,
  finding_reference_urls text[],
  finding_first_detected_at timestamptz,
  finding_last_seen_at timestamptz
)
language sql
stable
security invoker
set search_path = ''
as $$
  select
    f.id,
    coalesce(c.workflow_status::text, 'open'),
    f.agent_id,
    f.agent_name,
    f.host_os,
    f.package_name,
    f.package_version,
    f.vulnerability_id,
    case when f.content_id is null then f.description else content.description end,
    f.cvss_base,
    case when f.content_id is null then f.reference_urls else content.reference_urls end,
    f.first_detected_at,
    f.last_seen_at
  from public.wazuh_findings as f
  left join public.vulnerability_cases as c
    on c.finding_id = f.id and c.tenant_id = f.tenant_id
  left join public.finding_content as content
    on content.id = f.content_id
  where f.tenant_id = p_company_id
    and f.source_state = 'active'
    and f.id > coalesce(p_after_id, '00000000-0000-0000-0000-000000000000'::uuid)
  order by f.id
  limit least(greatest(coalesce(p_limit, 5000), 1), 5000);
$$;

revoke all on function public.get_report_export_batch(uuid, uuid, integer)
  from public, anon;
grant execute on function public.get_report_export_batch(uuid, uuid, integer)
  to authenticated;

notify pgrst, 'reload schema';
