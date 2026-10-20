create function public.get_report_export_batch_json(
  p_company_id uuid,
  p_after_id uuid default null,
  p_limit integer default 2500
)
returns jsonb
language sql stable security invoker set search_path = ''
as $$
  select coalesce(jsonb_agg(to_jsonb(batch) order by batch.finding_id), '[]'::jsonb)
  from public.get_report_export_batch(
    p_company_id,
    p_after_id,
    least(greatest(coalesce(p_limit, 2500), 1), 5000)
  ) as batch;
$$;

revoke all on function public.get_report_export_batch_json(uuid,uuid,integer) from public, anon;
grant execute on function public.get_report_export_batch_json(uuid,uuid,integer) to authenticated;
notify pgrst, 'reload schema';
