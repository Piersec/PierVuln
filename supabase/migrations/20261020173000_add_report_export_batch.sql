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
      r.id,
      r.finding_id,
      r.tenant_id,
      r.workflow_status::text as workflow_status,
      r.finding_agent_id,
      r.finding_agent_name,
      r.finding_agent_groups,
      r.finding_host_os,
      r.finding_package_name,
      r.finding_package_version,
      r.finding_vulnerability_id,
      r.finding_description,
      r.finding_severity,
      r.finding_cvss_base,
      r.finding_reference_urls,
      r.finding_source_state,
      r.finding_first_detected_at,
      r.finding_last_seen_at
    from public.vulnerability_case_records as r
    where r.tenant_id = p_company_id
      and r.finding_source_state = 'active'
      and (p_after_id is null or r.finding_id > p_after_id)
    order by r.finding_id
    limit least(greatest(coalesce(p_limit, 5000), 1), 5000)
  ) as batch_row;
$$;

revoke all on function public.get_report_export_batch(uuid, uuid, integer)
  from public, anon;
grant execute on function public.get_report_export_batch(uuid, uuid, integer)
  to authenticated;

notify pgrst, 'reload schema';
